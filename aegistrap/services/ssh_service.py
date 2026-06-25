"""
AegisTrap SSH Honeypot Service
================================
Provides a realistic SSH server on port 2222 using AsyncSSH.
Handles authentication with configurable credential acceptance,
presents a Linux banner, and relays commands to the AI engine.
"""

import asyncio
import logging
from typing import Optional

import asyncssh

from config import (
    SSH_PORT,
    SSH_BANNER,
    VALID_CREDENTIALS,
    MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT,
)
from aegistrap.core.session_manager import session_manager, ai_bridge, AttackerSession

logger = logging.getLogger("aegistrap.ssh")


class SSHServerHandler(asyncssh.SSHServer):
    """
    AsyncSSH server protocol handler.
    Manages authentication logic per the honeypot rules:
    - Accept credentials from the configured valid list immediately.
    - After MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT failures, accept any credential.
    """

    def __init__(self):
        self._failed_attempts: int = 0
        self._username: str = ""
        self._peername: Optional[tuple] = None
        self._session: Optional[AttackerSession] = None
        self._log_callback = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        """Called when a new SSH connection is established."""
        self._peername = conn.get_extra_info("peername")
        ip = self._peername[0] if self._peername else "unknown"
        port = self._peername[1] if self._peername else 0
        logger.info(f"[SSH] New connection from {ip}:{port}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the SSH connection is closed."""
        ip = self._peername[0] if self._peername else "unknown"
        port = self._peername[1] if self._peername else 0
        logger.info(f"[SSH] Connection closed from {ip}:{port}")

    def begin_auth(self, username: str) -> bool:
        """
        Called when authentication begins.
        Returns True to indicate authentication is required.
        """
        self._username = username
        return True

    def password_auth_supported(self) -> bool:
        """Enable password-based authentication."""
        return True

    def validate_password(self, username: str, password: str) -> bool:
        """
        Validate credentials against the honeypot rules:
        1. If credentials match the valid list, accept immediately.
        2. After MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT failures, accept anything.
        """
        self._username = username

        # Check configured valid credentials
        if (username, password) in VALID_CREDENTIALS:
            logger.info(
                f"[SSH] Auth accepted (valid creds): {username}:{password} "
                f"from {self._peername}"
            )
            return True

        # Increment failed attempts
        self._failed_attempts += 1

        # After threshold, accept any credentials to maximize immersion
        if self._failed_attempts > MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT:
            logger.info(
                f"[SSH] Auth accepted (after {self._failed_attempts} failures): "
                f"{username}:{password} from {self._peername}"
            )
            return True

        logger.info(
            f"[SSH] Auth rejected (attempt {self._failed_attempts}): "
            f"{username}:{password} from {self._peername}"
        )
        return False


class SSHSessionHandler(asyncssh.SSHServerProcess):
    """
    Handles an authenticated SSH session's interactive shell.
    Relays all commands to the AI Context Bridge and returns
    simulated terminal output.
    """

    def __init__(self, process, session: AttackerSession, log_callback):
        self._process = process
        self._session = session
        self._log_callback = log_callback

    async def handle(self) -> None:
        """Main interactive shell loop for the SSH session."""
        session = self._session
        process = self._process

        # Send login banner
        process.stdout.write(
            "Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
            "\r\n"
            " * Documentation:  https://help.ubuntu.com\r\n"
            " * Management:     https://landscape.canonical.com\r\n"
            " * Support:        https://ubuntu.com/pro\r\n"
            "\r\n"
            "  System information as of Thu Jan 18 14:32:07 UTC 2024\r\n"
            "\r\n"
            "  System load:  0.42              Processes:             187\r\n"
            "  Usage of /:   34.2% of 98.30GB  Users logged in:       1\r\n"
            "  Memory usage: 62%               IPv4 address for eth0: 10.0.4.17\r\n"
            "  Swap usage:   3%\r\n"
            "\r\n"
            "Last login: Thu Jan 18 09:15:33 2024 from 10.0.4.1\r\n"
        )

        # Main command loop
        while not session.is_expired():
            # Display prompt
            prompt = f"{session.username}@corp-srv-prod-01:{session.virtual_fs.cwd}# "
            process.stdout.write(prompt)

            try:
                # Read a line from the attacker
                line = await asyncio.wait_for(
                    process.stdin.readline(), timeout=300  # 5 min idle timeout
                )
            except asyncio.TimeoutError:
                process.stdout.write("\r\nConnection timed out.\r\n")
                break
            except asyncssh.BreakReceived:
                break

            if not line:
                break

            command = line.strip()

            if not command:
                continue

            # Handle exit/logout commands locally
            if command in ("exit", "logout", "quit"):
                process.stdout.write("logout\r\n")
                break

            # Generate AI response for the command
            try:
                response = await ai_bridge.generate_response(session, command)
            except Exception as e:
                logger.error(f"[SSH] AI bridge error: {e}")
                response = f"bash: {command}: command not found"

            # Send response to attacker
            if response:
                # Ensure proper line endings for SSH terminal
                formatted = response.replace("\n", "\r\n")
                if not formatted.endswith("\r\n"):
                    formatted += "\r\n"
                process.stdout.write(formatted)

            # Log the interaction
            if self._log_callback:
                await self._log_callback(
                    session=session,
                    input_received=command,
                    ai_response=response,
                )

            # Update session activity
            session.update_activity()

        # Close the process
        process.close()


async def _handle_ssh_process(process: asyncssh.SSHServerProcess, log_callback=None):
    """
    Coroutine that handles a new SSH process (shell session).
    Creates or retrieves the session and launches the interactive handler.
    """
    conn = process.get_extra_info("connection")
    peername = process.get_extra_info("peername")

    if peername:
        ip, port = peername[0], peername[1]
    else:
        ip, port = "unknown", 0

    # Get or create session
    session = await session_manager.get_session(ip, port)
    if not session:
        session = await session_manager.create_session(ip, port, "SSH")

    # Set the authenticated username
    session.authenticated = True
    # Try to get the username from the connection
    try:
        session.username = process.get_extra_info("username") or "root"
    except Exception:
        session.username = "root"

    logger.info(
        f"[SSH] Shell session started for {session.username}@{ip}:{port} "
        f"(session: {session.session_id})"
    )

    # Run the interactive handler
    handler = SSHSessionHandler(process, session, log_callback)
    await handler.handle()

    # Cleanup
    await session_manager.destroy_session(ip, port)
    logger.info(f"[SSH] Session ended for {ip}:{port}")


async def start_ssh_server(
    host: str = "0.0.0.0",
    port: int = SSH_PORT,
    host_key_path: str = "ssh_host_key",
    log_callback=None,
) -> asyncssh.SSHAcceptor:
    """
    Start the SSH honeypot server.

    Args:
        host: Bind address (default: all interfaces).
        port: Listen port (default: 2222).
        host_key_path: Path to the SSH host key file.
        log_callback: Async callback for logging interactions.

    Returns:
        The AsyncSSH server acceptor for lifecycle management.
    """
    # Generate host key if it doesn't exist
    try:
        host_keys = [asyncssh.read_private_key(host_key_path)]
    except (FileNotFoundError, asyncssh.KeyImportError):
        logger.info(f"[SSH] Generating new host key at {host_key_path}")
        key = asyncssh.generate_private_key("ssh-rsa", 2048)
        key.write_private_key(host_key_path)
        host_keys = [key]

    def server_factory():
        return SSHServerHandler()

    async def process_factory(process):
        await _handle_ssh_process(process, log_callback)

    server = await asyncssh.create_server(
        server_factory,
        host,
        port,
        server_host_keys=host_keys,
        process_factory=process_factory,
        server_version=SSH_BANNER,
        login_timeout=60,
    )

    logger.info(f"[SSH] Honeypot listening on {host}:{port}")
    return server
