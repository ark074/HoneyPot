"""
AegisTrap Configuration
========================
Central configuration for all honeypot services, Ollama integration,
rate limiting, and logging parameters.
"""

import os

# =============================================================================
# Ollama LLM Configuration
# =============================================================================
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3:8b")
OLLAMA_API_CHAT = f"{OLLAMA_HOST}/api/chat"

# =============================================================================
# Service Port Configuration
# =============================================================================
SSH_PORT = int(os.getenv("SSH_PORT", "2222"))
TELNET_PORT = int(os.getenv("TELNET_PORT", "23"))
HTTP_PORT = int(os.getenv("HTTP_PORT", "80"))
HTTP_ALT_PORT = int(os.getenv("HTTP_ALT_PORT", "8080"))
FTP_PORT = int(os.getenv("FTP_PORT", "21"))

# =============================================================================
# Authentication Configuration
# =============================================================================
# Credentials that are always accepted on first attempt
VALID_CREDENTIALS = [
    ("root", "toor"),
    ("admin", "admin"),
    ("root", "password"),
    ("admin", "password123"),
    ("user", "user"),
    ("root", "123456"),
]

# After this many failed attempts, accept any credential
MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT = 1

# =============================================================================
# Security & Rate Limiting
# =============================================================================
RATE_LIMIT_REQUESTS_PER_MINUTE = 50
SESSION_TIMEOUT_SECONDS = 15 * 60  # 15 minutes

# =============================================================================
# Logging Configuration
# =============================================================================
LOG_DIR = os.getenv("LOG_DIR", "logs")
LOG_FILE = os.path.join(LOG_DIR, "honeypot_activity.json")
LOG_MAX_SIZE_MB = 100  # Roll over at 100MB

# =============================================================================
# Banner Configuration
# =============================================================================
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
TELNET_BANNER = (
    "Ubuntu 22.04.3 LTS\n"
    "corp-srv-prod-01 login: "
)
FTP_BANNER = "220 (vsFTPd 3.0.5)"
HTTP_SERVER_HEADER = "Apache/2.4.52 (Ubuntu)"

# =============================================================================
# LLM System Prompt (Core AI Personality)
# =============================================================================
LLM_SYSTEM_PROMPT = (
    "You are an authentic Ubuntu 22.04 LTS server running inside a corporate "
    "environment. The current user is root. You must behave exactly like a Linux "
    "terminal. Do not include markdown code fences (```) in your terminal responses. "
    "Do not explain commands. Only return raw stdout/stderr output. If an attacker "
    "runs a command like 'ls', 'whoami', 'cat /etc/passwd', or 'uname -a', generate "
    "realistic, text-only terminal responses that reflect a real production server. "
    "Maintain an in-memory memory structure of files the attacker creates (e.g., via "
    "'touch' or 'echo') so that if they run 'ls' again later in the session, those "
    "files persist in the output."
)
