"""
AegisTrap Session Manager
===========================
Manages isolated attacker sessions, mapping each unique IP:Port combination
to its own chat history, virtual filesystem state, and response cache.
Provides the core AI context bridge to Ollama for dynamic response generation.
"""

import uuid
import time
import hashlib
import asyncio
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field

import aiohttp

from config import (
    OLLAMA_API_CHAT,
    OLLAMA_MODEL,
    LLM_SYSTEM_PROMPT,
    SESSION_TIMEOUT_SECONDS,
)


@dataclass
class VirtualFilesystem:
    """
    Represents a simulated filesystem state for a session.
    Tracks files created/modified by the attacker so the LLM
    can maintain consistency across commands.
    """
    # Current working directory
    cwd: str = "/root"
    # Mapping of path -> content (None means empty file from 'touch')
    files: Dict[str, Optional[str]] = field(default_factory=dict)
    # Directories created by the attacker
    directories: list = field(default_factory=list)

    def get_state_summary(self) -> str:
        """Generate a text summary of the virtual filesystem for LLM context."""
        lines = [f"Current directory: {self.cwd}"]
        if self.files:
            lines.append("Files created this session:")
            for path, content in self.files.items():
                if content:
                    lines.append(f"  {path} (content: {content[:100]})")
                else:
                    lines.append(f"  {path} (empty)")
        if self.directories:
            lines.append(f"Directories created: {', '.join(self.directories)}")
        return "\n".join(lines)


@dataclass
class AttackerSession:
    """
    Represents a single attacker's session with full state isolation.
    Each session maintains its own chat history, filesystem state,
    and response cache.
    """
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    attacker_ip: str = ""
    attacker_port: int = 0
    service: str = ""
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    chat_history: list = field(default_factory=list)
    virtual_fs: VirtualFilesystem = field(default_factory=VirtualFilesystem)
    response_cache: Dict[str, str] = field(default_factory=dict)
    failed_auth_attempts: int = 0
    authenticated: bool = False
    request_count: int = 0
    username: str = "root"

    def is_expired(self) -> bool:
        """Check if session has exceeded the maximum timeout."""
        return (time.time() - self.created_at) > SESSION_TIMEOUT_SECONDS

    def update_activity(self) -> None:
        """Update the last activity timestamp."""
        self.last_activity = time.time()
        self.request_count += 1

    def get_cache_key(self, command: str) -> str:
        """
        Generate a cache key based on the command and current filesystem state.
        This ensures cached responses are invalidated when state changes.
        """
        state_str = f"{command}|{self.virtual_fs.cwd}|{sorted(self.virtual_fs.files.keys())}"
        return hashlib.sha256(state_str.encode()).hexdigest()


class SessionManager:
    """
    Central session management engine.
    Maps attacker IP:Port pairs to isolated sessions and handles
    session lifecycle (creation, lookup, expiration, cleanup).
    """

    def __init__(self):
        # Primary session store: (ip, port) -> AttackerSession
        self._sessions: Dict[Tuple[str, int], AttackerSession] = {}
        # Session lookup by ID for cross-reference
        self._sessions_by_id: Dict[str, AttackerSession] = {}
        # Lock for thread-safe session operations
        self._lock = asyncio.Lock()

    async def create_session(
        self, attacker_ip: str, attacker_port: int, service: str
    ) -> AttackerSession:
        """
        Create a new isolated session for an attacker connection.

        Args:
            attacker_ip: Remote IP address of the attacker.
            attacker_port: Remote port of the attacker.
            service: The honeypot service being targeted (SSH, Telnet, HTTP, FTP).

        Returns:
            A new AttackerSession instance with initialized state.
        """
        async with self._lock:
            session = AttackerSession(
                attacker_ip=attacker_ip,
                attacker_port=attacker_port,
                service=service,
            )
            key = (attacker_ip, attacker_port)
            self._sessions[key] = session
            self._sessions_by_id[session.session_id] = session
            return session

    async def get_session(
        self, attacker_ip: str, attacker_port: int
    ) -> Optional[AttackerSession]:
        """
        Retrieve an existing session by IP:Port, or return None if not found/expired.
        """
        key = (attacker_ip, attacker_port)
        session = self._sessions.get(key)
        if session and session.is_expired():
            await self.destroy_session(attacker_ip, attacker_port)
            return None
        return session

    async def get_session_by_id(self, session_id: str) -> Optional[AttackerSession]:
        """Retrieve a session by its unique UUID."""
        session = self._sessions_by_id.get(session_id)
        if session and session.is_expired():
            await self.destroy_session(session.attacker_ip, session.attacker_port)
            return None
        return session

    async def destroy_session(self, attacker_ip: str, attacker_port: int) -> None:
        """Remove a session from the manager and free resources."""
        async with self._lock:
            key = (attacker_ip, attacker_port)
            session = self._sessions.pop(key, None)
            if session:
                self._sessions_by_id.pop(session.session_id, None)

    async def cleanup_expired(self) -> int:
        """
        Remove all expired sessions. Returns count of sessions cleaned up.
        Should be called periodically by a background task.
        """
        expired_keys = []
        for key, session in self._sessions.items():
            if session.is_expired():
                expired_keys.append(key)

        for key in expired_keys:
            session = self._sessions.pop(key, None)
            if session:
                self._sessions_by_id.pop(session.session_id, None)

        return len(expired_keys)

    @property
    def active_session_count(self) -> int:
        """Return the number of currently active sessions."""
        return len(self._sessions)


class AIContextBridge:
    """
    The AI Context Bridge handles all communication with the Ollama LLM.
    It constructs prompts with full session context, manages chat history,
    implements response caching, and maintains filesystem state consistency.
    """

    def __init__(self):
        self._http_session: Optional[aiohttp.ClientSession] = None

    async def _get_http_session(self) -> aiohttp.ClientSession:
        """Lazy-initialize the aiohttp session for Ollama API calls."""
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=60)
            )
        return self._http_session

    def _build_system_prompt(self, session: AttackerSession) -> str:
        """
        Construct the full system prompt including base personality,
        current filesystem state, and session-specific context.
        """
        fs_state = session.virtual_fs.get_state_summary()
        prompt_parts = [
            LLM_SYSTEM_PROMPT,
            "",
            "=== CURRENT SESSION STATE ===",
            f"Username: {session.username}",
            f"Hostname: corp-srv-prod-01",
            fs_state,
            "",
            "Remember: respond ONLY with raw terminal output. No explanations, "
            "no markdown formatting, no code fences.",
        ]
        return "\n".join(prompt_parts)

    def _build_messages(self, session: AttackerSession, command: str) -> list:
        """
        Build the full message array for the Ollama API request.
        Includes system prompt, chat history, and the new command.
        """
        messages = [
            {"role": "system", "content": self._build_system_prompt(session)}
        ]

        # Include chat history for context continuity
        for entry in session.chat_history:
            messages.append(entry)

        # Add the current command as a user message
        messages.append({
            "role": "user",
            "content": f"{session.username}@corp-srv-prod-01:{session.virtual_fs.cwd}# {command}"
        })

        return messages

    async def generate_response(
        self, session: AttackerSession, command: str
    ) -> str:
        """
        Generate an AI response for a given command within a session context.

        Implements the caching strategy:
        1. Check if the command+state combination is cached -> return immediately
        2. If not cached, send full context to Ollama
        3. Cache the response for future identical requests

        Args:
            session: The attacker's session with full state.
            command: The raw command input from the attacker.

        Returns:
            The simulated terminal output string.
        """
        # Check the response cache first
        cache_key = session.get_cache_key(command)
        if cache_key in session.response_cache:
            return session.response_cache[cache_key]

        # Build messages and call Ollama
        messages = self._build_messages(session, command)

        try:
            http_session = await self._get_http_session()
            payload = {
                "model": OLLAMA_MODEL,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": 0.3,  # Low temperature for consistent output
                    "num_predict": 512,   # Limit response length
                }
            }

            async with http_session.post(OLLAMA_API_CHAT, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    response_text = data.get("message", {}).get("content", "")
                    # Strip any accidental markdown fences the LLM might add
                    response_text = self._sanitize_response(response_text)
                else:
                    error_body = await resp.text()
                    response_text = f"bash: internal error (service unavailable)\n"

        except aiohttp.ClientError:
            # If Ollama is unreachable, return a generic error
            response_text = "bash: internal error: connection refused\n"
        except asyncio.TimeoutError:
            response_text = ""

        # Update chat history with the exchange
        session.chat_history.append({
            "role": "user",
            "content": f"{session.username}@corp-srv-prod-01:{session.virtual_fs.cwd}# {command}"
        })
        session.chat_history.append({
            "role": "assistant",
            "content": response_text
        })

        # Trim chat history to prevent context overflow (keep last 50 exchanges)
        if len(session.chat_history) > 100:
            session.chat_history = session.chat_history[-100:]

        # Cache the response
        session.response_cache[cache_key] = response_text

        # Update filesystem state based on command patterns
        self._update_filesystem_state(session, command, response_text)

        return response_text

    def _sanitize_response(self, text: str) -> str:
        """
        Remove any markdown formatting the LLM might accidentally include.
        Ensures responses look like raw terminal output.
        """
        # Remove code fences
        text = text.replace("```bash", "").replace("```shell", "")
        text = text.replace("```", "")
        # Strip leading/trailing whitespace but preserve internal structure
        text = text.strip()
        return text

    def _update_filesystem_state(
        self, session: AttackerSession, command: str, response: str
    ) -> None:
        """
        Parse commands to update the virtual filesystem state.
        This ensures the LLM has accurate context for future commands.
        """
        cmd_lower = command.strip().lower()
        parts = command.strip().split()

        if not parts:
            return

        cmd = parts[0]

        # Track directory changes
        if cmd == "cd" and len(parts) > 1:
            target = parts[1]
            if target == "/":
                session.virtual_fs.cwd = "/"
            elif target == "~":
                session.virtual_fs.cwd = "/root"
            elif target == "..":
                parent = "/".join(session.virtual_fs.cwd.rstrip("/").split("/")[:-1])
                session.virtual_fs.cwd = parent if parent else "/"
            elif target.startswith("/"):
                session.virtual_fs.cwd = target
            else:
                session.virtual_fs.cwd = f"{session.virtual_fs.cwd.rstrip('/')}/{target}"

        # Track file creation via touch
        elif cmd == "touch" and len(parts) > 1:
            for filename in parts[1:]:
                if filename.startswith("/"):
                    path = filename
                else:
                    path = f"{session.virtual_fs.cwd.rstrip('/')}/{filename}"
                session.virtual_fs.files[path] = None

        # Track file creation via echo redirection
        elif ">" in command and "echo" in command:
            # Parse: echo "content" > filename or echo content >> filename
            try:
                if ">>" in command:
                    _, filepath = command.split(">>", 1)
                else:
                    _, filepath = command.split(">", 1)
                filepath = filepath.strip()
                if not filepath.startswith("/"):
                    filepath = f"{session.virtual_fs.cwd.rstrip('/')}/{filepath}"
                # Extract content between quotes if present
                content = command.split("echo", 1)[1].split(">")[0].strip().strip('"').strip("'")
                session.virtual_fs.files[filepath] = content
            except (ValueError, IndexError):
                pass

        # Track mkdir
        elif cmd == "mkdir" and len(parts) > 1:
            for dirname in parts[1:]:
                if dirname.startswith("-"):
                    continue
                if dirname.startswith("/"):
                    session.virtual_fs.directories.append(dirname)
                else:
                    session.virtual_fs.directories.append(
                        f"{session.virtual_fs.cwd.rstrip('/')}/{dirname}"
                    )

        # Track file removal
        elif cmd == "rm" and len(parts) > 1:
            for target in parts[1:]:
                if target.startswith("-"):
                    continue
                if not target.startswith("/"):
                    target = f"{session.virtual_fs.cwd.rstrip('/')}/{target}"
                session.virtual_fs.files.pop(target, None)

    async def close(self) -> None:
        """Clean up HTTP session resources."""
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()


# =============================================================================
# Module-level singleton instances for use across the application
# =============================================================================
session_manager = SessionManager()
ai_bridge = AIContextBridge()
