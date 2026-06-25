"""
AegisTrap Security Hardening Module
======================================
Implements defensive boundaries to protect the honeypot host system:
1. Absolute Isolation - Never executes commands on host OS
2. Payload Capture - Detects and logs malicious URLs from wget/curl commands
3. Rate Limiting - 50 requests/minute/IP with automatic connection drop
4. Session Throttling - 15-minute max session duration enforcement
"""

import re
import time
import asyncio
import logging
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from config import (
    RATE_LIMIT_REQUESTS_PER_MINUTE,
    SESSION_TIMEOUT_SECONDS,
)

logger = logging.getLogger("aegistrap.security")

# =============================================================================
# Payload Detection Patterns
# =============================================================================

# Regex patterns to detect URLs in attacker commands (wget, curl, etc.)
URL_PATTERN = re.compile(
    r'https?://[^\s\'"<>|;`$(){}]+',
    re.IGNORECASE
)

# Commands that attempt to download content
DOWNLOAD_COMMANDS = re.compile(
    r'\b(wget|curl|fetch|lwp-download|lynx|aria2c|axel)\b',
    re.IGNORECASE
)

# Commands that attempt code execution of downloaded content
EXECUTION_PATTERNS = re.compile(
    r'(\|\s*sh|\|\s*bash|\|\s*python|\|\s*perl|;\s*sh\s|;\s*bash\s|'
    r'chmod\s+\+x|chmod\s+[0-7]*[1357][0-7]*)',
    re.IGNORECASE
)

# Known malicious payload indicators
SUSPICIOUS_PATHS = re.compile(
    r'(/tmp/|/dev/shm/|/var/tmp/|\.sh$|\.py$|\.pl$|\.elf$|payload|shell|reverse|bind|'
    r'miner|xmrig|kinsing|tsunami|mirai|gafgyt|botnet|ddos|cryptonight)',
    re.IGNORECASE
)

# Base64 encoded command patterns
BASE64_EXEC_PATTERN = re.compile(
    r'(echo\s+[A-Za-z0-9+/=]{20,}\s*\|\s*base64\s+-d|'
    r'base64\s+-d\s*<<<|'
    r'python[23]?\s+-c\s+["\']import\s+base64)',
    re.IGNORECASE
)

# Reverse shell patterns
REVERSE_SHELL_PATTERN = re.compile(
    r'(bash\s+-i\s+>&\s*/dev/tcp|nc\s+-e|ncat\s+-e|'
    r'python.*socket.*connect|perl.*socket.*INET|'
    r'ruby.*TCPSocket|php.*fsockopen|'
    r'/dev/tcp/\d+\.\d+\.\d+\.\d+)',
    re.IGNORECASE
)


@dataclass
class ThreatIntelEntry:
    """Represents a captured threat intelligence indicator."""
    timestamp: float = field(default_factory=time.time)
    attacker_ip: str = ""
    session_id: str = ""
    threat_type: str = ""  # url_download, reverse_shell, base64_exec, suspicious_path
    indicator: str = ""    # The actual URL, command, or pattern detected
    full_command: str = "" # The complete command that triggered detection
    severity: str = "medium"  # low, medium, high, critical


@dataclass
class RateLimitEntry:
    """Tracks request counts and timestamps for rate limiting."""
    requests: List[float] = field(default_factory=list)
    blocked_until: float = 0.0
    total_blocked_count: int = 0


class PayloadCapture:
    """
    Detects and captures malicious payloads from attacker commands.
    Extracts URLs, identifies reverse shells, and logs threat indicators
    without ever executing anything on the host system.
    """

    def __init__(self):
        # Captured threat intelligence entries
        self._threat_intel: List[ThreatIntelEntry] = []
        self._lock = asyncio.Lock()

    async def analyze_command(
        self, command: str, attacker_ip: str, session_id: str
    ) -> List[ThreatIntelEntry]:
        """
        Analyze an attacker command for malicious indicators.
        
        Args:
            command: The raw command from the attacker.
            attacker_ip: Source IP address.
            session_id: Current session UUID.
            
        Returns:
            List of threat intelligence entries detected.
        """
        entries = []

        # Check for download commands with URLs
        if DOWNLOAD_COMMANDS.search(command):
            urls = URL_PATTERN.findall(command)
            for url in urls:
                severity = "high"
                if SUSPICIOUS_PATHS.search(url):
                    severity = "critical"

                entry = ThreatIntelEntry(
                    attacker_ip=attacker_ip,
                    session_id=session_id,
                    threat_type="url_download",
                    indicator=url,
                    full_command=command,
                    severity=severity,
                )
                entries.append(entry)
                logger.warning(
                    f"[THREAT] Payload URL captured: {url} from {attacker_ip} "
                    f"(severity: {severity})"
                )

        # Check for reverse shell attempts
        if REVERSE_SHELL_PATTERN.search(command):
            entry = ThreatIntelEntry(
                attacker_ip=attacker_ip,
                session_id=session_id,
                threat_type="reverse_shell",
                indicator=command[:200],
                full_command=command,
                severity="critical",
            )
            entries.append(entry)
            logger.warning(
                f"[THREAT] Reverse shell attempt from {attacker_ip}: "
                f"{command[:100]}"
            )

        # Check for base64-encoded execution
        if BASE64_EXEC_PATTERN.search(command):
            entry = ThreatIntelEntry(
                attacker_ip=attacker_ip,
                session_id=session_id,
                threat_type="base64_exec",
                indicator=command[:200],
                full_command=command,
                severity="high",
            )
            entries.append(entry)
            logger.warning(
                f"[THREAT] Base64 execution attempt from {attacker_ip}: "
                f"{command[:100]}"
            )

        # Check for execution of downloaded content
        if EXECUTION_PATTERNS.search(command) and DOWNLOAD_COMMANDS.search(command):
            entry = ThreatIntelEntry(
                attacker_ip=attacker_ip,
                session_id=session_id,
                threat_type="download_and_execute",
                indicator=command[:200],
                full_command=command,
                severity="critical",
            )
            entries.append(entry)
            logger.warning(
                f"[THREAT] Download-and-execute from {attacker_ip}: "
                f"{command[:100]}"
            )

        # Store entries
        if entries:
            async with self._lock:
                self._threat_intel.extend(entries)

        return entries

    def generate_simulated_download_response(self, command: str) -> str:
        """
        Generate a realistic simulated response for download commands
        without actually downloading anything.
        
        Args:
            command: The download command (wget/curl).
            
        Returns:
            Simulated terminal output string.
        """
        urls = URL_PATTERN.findall(command)
        url = urls[0] if urls else "http://example.com/file"
        
        # Extract filename from URL
        filename = url.rstrip("/").split("/")[-1] or "index.html"
        if "?" in filename:
            filename = filename.split("?")[0]

        cmd_lower = command.lower().strip()

        if cmd_lower.startswith("wget"):
            # Simulate wget output
            return (
                f"--2024-01-18 14:35:22--  {url}\n"
                f"Resolving {url.split('/')[2]}... 93.184.216.34\n"
                f"Connecting to {url.split('/')[2]}|93.184.216.34|:443... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 1847 (1.8K) [application/octet-stream]\n"
                f"Saving to: '{filename}'\n"
                f"\n"
                f"{filename}          100%[===================>]   1.80K  --.-KB/s    in 0s\n"
                f"\n"
                f"2024-01-18 14:35:22 (45.2 MB/s) - '{filename}' saved [1847/1847]"
            )

        elif cmd_lower.startswith("curl"):
            if "-o" in command or "-O" in command or "--output" in command:
                # curl saving to file
                return (
                    f"  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                    f"                                 Dload  Upload   Total   Spent    Left  Speed\n"
                    f"100  1847  100  1847    0     0  92350      0 --:--:-- --:--:-- --:--:-- 92350"
                )
            else:
                # curl output to stdout (simulate small script content)
                return (
                    "#!/bin/bash\n"
                    "# Downloaded content\n"
                    "echo 'executing...'\n"
                )

        return f"bash: {command.split()[0]}: simulated output"

    @property
    def threat_count(self) -> int:
        """Return total number of captured threat indicators."""
        return len(self._threat_intel)

    @property
    def threat_intel(self) -> List[ThreatIntelEntry]:
        """Return all captured threat intelligence entries."""
        return self._threat_intel.copy()


class RateLimiter:
    """
    Enforces rate limiting per IP address.
    Allows RATE_LIMIT_REQUESTS_PER_MINUTE requests per minute per IP.
    Automatically blocks IPs that exceed the threshold.
    """

    def __init__(self, max_requests: int = RATE_LIMIT_REQUESTS_PER_MINUTE):
        self._max_requests = max_requests
        self._window_seconds = 60.0  # 1 minute sliding window
        self._entries: Dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._lock = asyncio.Lock()

    async def check_rate_limit(self, ip: str) -> Tuple[bool, int]:
        """
        Check if an IP has exceeded its rate limit.
        
        Args:
            ip: The IP address to check.
            
        Returns:
            Tuple of (is_allowed: bool, remaining_requests: int).
            If is_allowed is False, the request should be dropped.
        """
        async with self._lock:
            entry = self._entries[ip]
            now = time.time()

            # Check if IP is in a block period
            if entry.blocked_until > now:
                return False, 0

            # Remove expired timestamps from the sliding window
            cutoff = now - self._window_seconds
            entry.requests = [ts for ts in entry.requests if ts > cutoff]

            # Check if limit is exceeded
            if len(entry.requests) >= self._max_requests:
                # Block for 60 seconds
                entry.blocked_until = now + 60.0
                entry.total_blocked_count += 1
                logger.warning(
                    f"[RATE-LIMIT] IP {ip} exceeded {self._max_requests} req/min. "
                    f"Blocked for 60s (total blocks: {entry.total_blocked_count})"
                )
                return False, 0

            # Record this request
            entry.requests.append(now)
            remaining = self._max_requests - len(entry.requests)
            return True, remaining

    async def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        entry = self._entries.get(ip)
        if not entry:
            return False
        return entry.blocked_until > time.time()

    def get_stats(self) -> Dict[str, dict]:
        """Return rate limiting statistics for all tracked IPs."""
        stats = {}
        now = time.time()
        for ip, entry in self._entries.items():
            cutoff = now - self._window_seconds
            active_requests = [ts for ts in entry.requests if ts > cutoff]
            stats[ip] = {
                "current_requests": len(active_requests),
                "is_blocked": entry.blocked_until > now,
                "total_blocks": entry.total_blocked_count,
            }
        return stats


class SessionThrottler:
    """
    Enforces maximum session duration limits.
    Automatically terminates sessions that exceed SESSION_TIMEOUT_SECONDS.
    """

    def __init__(self, timeout_seconds: int = SESSION_TIMEOUT_SECONDS):
        self._timeout = timeout_seconds
        self._sessions: Dict[str, float] = {}  # session_id -> start_time

    def register_session(self, session_id: str) -> None:
        """Register a new session start time."""
        self._sessions[session_id] = time.time()

    def is_session_expired(self, session_id: str) -> bool:
        """Check if a session has exceeded its maximum duration."""
        start_time = self._sessions.get(session_id)
        if start_time is None:
            return False
        return (time.time() - start_time) > self._timeout

    def get_remaining_time(self, session_id: str) -> float:
        """Get remaining time in seconds for a session."""
        start_time = self._sessions.get(session_id)
        if start_time is None:
            return self._timeout
        elapsed = time.time() - start_time
        return max(0, self._timeout - elapsed)

    def remove_session(self, session_id: str) -> None:
        """Remove a session from tracking."""
        self._sessions.pop(session_id, None)


class SecurityGateway:
    """
    Unified security gateway that combines all hardening measures.
    Should be called before processing any attacker command.
    """

    def __init__(self):
        self.payload_capture = PayloadCapture()
        self.rate_limiter = RateLimiter()
        self.session_throttler = SessionThrottler()

    async def process_command(
        self,
        command: str,
        attacker_ip: str,
        session_id: str,
    ) -> Tuple[bool, Optional[str], List[ThreatIntelEntry]]:
        """
        Process a command through all security checks.
        
        Args:
            command: The attacker's command.
            attacker_ip: Source IP address.
            session_id: Session UUID.
            
        Returns:
            Tuple of:
            - is_allowed: Whether the command should proceed to the LLM.
            - override_response: If not None, return this instead of calling LLM.
            - threats: List of detected threat indicators.
        """
        # 1. Rate limiting check
        allowed, remaining = await self.rate_limiter.check_rate_limit(attacker_ip)
        if not allowed:
            logger.warning(
                f"[SECURITY] Rate limit exceeded for {attacker_ip}, dropping command"
            )
            return False, "bash: too many requests, please slow down\n", []

        # 2. Session duration check
        if self.session_throttler.is_session_expired(session_id):
            logger.info(
                f"[SECURITY] Session {session_id} expired (max duration reached)"
            )
            return False, None, []

        # 3. Payload analysis
        threats = await self.payload_capture.analyze_command(
            command, attacker_ip, session_id
        )

        # 4. If download command detected, provide simulated response
        if DOWNLOAD_COMMANDS.search(command) and URL_PATTERN.search(command):
            simulated = self.payload_capture.generate_simulated_download_response(
                command
            )
            return True, simulated, threats

        # 5. Command is allowed to proceed to LLM
        return True, None, threats

    def get_security_stats(self) -> dict:
        """Return consolidated security statistics."""
        return {
            "threats_captured": self.payload_capture.threat_count,
            "rate_limit_stats": self.rate_limiter.get_stats(),
        }


# =============================================================================
# Module-level singleton instance
# =============================================================================
security_gateway = SecurityGateway()
