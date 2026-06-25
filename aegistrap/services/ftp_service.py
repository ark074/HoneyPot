"""
AegisTrap FTP Honeypot Service
================================
Provides a realistic FTP server on port 21 using asyncio streams.
Presents a standard vsFTPd banner, captures anonymous or brute-forced
login strings, and intercepts file upload/download commands.
"""

import asyncio
import logging
from typing import Optional, Callable, Awaitable

from config import (
    FTP_PORT,
    FTP_BANNER,
    VALID_CREDENTIALS,
    MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT,
    SESSION_TIMEOUT_SECONDS,
)
from aegistrap.core.session_manager import session_manager, ai_bridge, AttackerSession

logger = logging.getLogger("aegistrap.ftp")

# =============================================================================
# FTP Response Codes
# =============================================================================
FTP_READY = "220"
FTP_GOODBYE = "221"
FTP_TRANSFER_OK = "226"
FTP_PASSIVE_MODE = "227"
FTP_LOGIN_OK = "230"
FTP_NEED_PASSWORD = "331"
FTP_LOGIN_FAIL = "530"
FTP_FILE_OK = "150"
FTP_CMD_OK = "200"
FTP_SYSTEM_TYPE = "215"
FTP_DIRECTORY = "257"
FTP_NOT_IMPLEMENTED = "502"
FTP_FILE_UNAVAIL = "550"

# =============================================================================
# Fake directory listings for realistic FTP responses
# =============================================================================
FAKE_ROOT_LISTING = (
    "drwxr-xr-x   2 root root     4096 Jan 15 09:12 backups\r\n"
    "drwxr-xr-x   3 root root     4096 Jan 10 14:30 config\r\n"
    "drwxr-xr-x   2 www-data www-data 4096 Jan 18 11:45 html\r\n"
    "-rw-r--r--   1 root root     2847 Jan 12 08:00 deploy.sh\r\n"
    "-rw-------   1 root root      512 Jan 08 16:22 .credentials\r\n"
    "drwxr-xr-x   2 root root     4096 Jan 14 20:00 logs\r\n"
    "-rw-r--r--   1 root root     1024 Jan 16 13:15 README.md\r\n"
)

FAKE_BACKUPS_LISTING = (
    "-rw-r--r--   1 root root  52428800 Jan 15 03:00 db_backup_20240115.sql.gz\r\n"
    "-rw-r--r--   1 root root  48234567 Jan 14 03:00 db_backup_20240114.sql.gz\r\n"
    "-rw-r--r--   1 root root 104857600 Jan 15 04:00 full_backup_20240115.tar.gz\r\n"
    "-rw-r--r--   1 root root   1048576 Jan 13 03:00 config_backup.tar.gz\r\n"
)

FAKE_CONFIG_LISTING = (
    "-rw-r--r--   1 root root     3421 Jan 10 14:30 nginx.conf\r\n"
    "-rw-r--r--   1 root root     1892 Jan 10 14:30 mysql.cnf\r\n"
    "-rw-------   1 root root      847 Jan 10 14:30 ssl-cert.pem\r\n"
    "-rw-------   1 root root      241 Jan 10 14:30 api-keys.env\r\n"
)

FAKE_FILE_CONTENTS = {
    "deploy.sh": (
        "#!/bin/bash\n"
        "# Production deployment script\n"
        "# Last modified: 2024-01-12\n"
        "\n"
        "export DB_PASS='Pr0d_S3cur3!_2024'\n"
        "export API_KEY='sk-corpnet-4a8f2b1c9d3e7f6a'\n"
        "\n"
        "cd /var/www/html\n"
        "git pull origin main\n"
        "composer install --no-dev\n"
        "php artisan migrate --force\n"
        "systemctl reload nginx\n"
    ),
    ".credentials": (
        "# Service Account Credentials\n"
        "LDAP_BIND_DN=cn=admin,dc=corpnet,dc=internal\n"
        "LDAP_BIND_PW=LdAp_Adm1n_2024!\n"
        "SMTP_USER=alerts@corpnet.com\n"
        "SMTP_PASS=Em@1l_S3nd3r_99\n"
    ),
    "README.md": (
        "# CorpNet Production Server\n"
        "\n"
        "## Access\n"
        "- SSH: port 22 (key-based auth preferred)\n"
        "- FTP: port 21 (service accounts only)\n"
        "- Web: port 80/443\n"
        "\n"
        "## Contacts\n"
        "- SysAdmin: j.mitchell@corpnet.com\n"
        "- DBA: s.rodriguez@corpnet.com\n"
    ),
}


class FTPClientHandler:
    """
    Handles a single FTP client connection.
    Implements the FTP command protocol with realistic responses,
    credential capture, and file operation interception.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        log_callback: Optional[Callable[..., Awaitable]] = None,
    ):
        self._reader = reader
        self._writer = writer
        self._log_callback = log_callback
        self._session: Optional[AttackerSession] = None
        self._ip: str = "unknown"
        self._port: int = 0
        self._authenticated: bool = False
        self._username: str = ""
        self._current_dir: str = "/"
        self._transfer_type: str = "A"  # ASCII by default
        self._rename_from: str = ""
        self._failed_attempts: int = 0

    async def handle(self) -> None:
        """Main entry point for handling an FTP connection."""
        peername = self._writer.get_extra_info("peername")
        self._ip = peername[0] if peername else "unknown"
        self._port = peername[1] if peername else 0

        logger.info(f"[FTP] New connection from {self._ip}:{self._port}")

        try:
            # Send welcome banner
            await self._send(f"{FTP_READY} {FTP_BANNER.split(' ', 1)[1] if ' ' in FTP_BANNER else '(vsFTPd 3.0.5)'}")

            # Create session for this connection
            self._session = await session_manager.create_session(
                self._ip, self._port, "FTP"
            )

            # Command processing loop
            while not self._session.is_expired():
                try:
                    line = await asyncio.wait_for(
                        self._reader.readline(),
                        timeout=SESSION_TIMEOUT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    await self._send(f"{FTP_GOODBYE} Timeout. Goodbye.")
                    break

                if not line:
                    break

                # Decode and parse the FTP command
                try:
                    command_line = line.decode("utf-8", errors="replace").strip()
                except Exception:
                    continue

                if not command_line:
                    continue

                # Parse command and arguments
                parts = command_line.split(" ", 1)
                cmd = parts[0].upper()
                args = parts[1] if len(parts) > 1 else ""

                # Log the raw command
                logger.debug(f"[FTP] {self._ip}:{self._port} -> {command_line}")

                # Dispatch command
                await self._dispatch_command(cmd, args, command_line)

                # Update session activity
                self._session.update_activity()

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            logger.info(f"[FTP] Connection reset from {self._ip}:{self._port}")
        except Exception as e:
            logger.error(f"[FTP] Error from {self._ip}:{self._port}: {e}")
        finally:
            if self._session:
                await session_manager.destroy_session(self._ip, self._port)
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            logger.info(f"[FTP] Connection closed from {self._ip}:{self._port}")

    async def _send(self, message: str) -> None:
        """Send an FTP response line to the client."""
        self._writer.write(f"{message}\r\n".encode())
        await self._writer.drain()

    async def _log_interaction(self, input_received: str, ai_response: str) -> None:
        """Log an FTP interaction via the callback."""
        if self._log_callback and self._session:
            await self._log_callback(
                session=self._session,
                input_received=input_received,
                ai_response=ai_response,
            )

    async def _dispatch_command(self, cmd: str, args: str, raw: str) -> None:
        """Route FTP commands to their respective handlers."""
        # Commands allowed before authentication
        pre_auth_commands = {"USER", "PASS", "QUIT", "AUTH", "FEAT"}

        if cmd not in pre_auth_commands and not self._authenticated:
            await self._send(f"{FTP_LOGIN_FAIL} Please login with USER and PASS.")
            await self._log_interaction(raw, "530 Not logged in")
            return

        # Command dispatch table
        handlers = {
            "USER": self._cmd_user,
            "PASS": self._cmd_pass,
            "QUIT": self._cmd_quit,
            "SYST": self._cmd_syst,
            "FEAT": self._cmd_feat,
            "PWD": self._cmd_pwd,
            "XPWD": self._cmd_pwd,
            "CWD": self._cmd_cwd,
            "XCWD": self._cmd_cwd,
            "CDUP": self._cmd_cdup,
            "TYPE": self._cmd_type,
            "PASV": self._cmd_pasv,
            "LIST": self._cmd_list,
            "NLST": self._cmd_nlst,
            "RETR": self._cmd_retr,
            "STOR": self._cmd_stor,
            "DELE": self._cmd_dele,
            "MKD": self._cmd_mkd,
            "XMKD": self._cmd_mkd,
            "RMD": self._cmd_rmd,
            "XRMD": self._cmd_rmd,
            "RNFR": self._cmd_rnfr,
            "RNTO": self._cmd_rnto,
            "SIZE": self._cmd_size,
            "NOOP": self._cmd_noop,
            "PORT": self._cmd_port,
            "AUTH": self._cmd_auth,
        }

        handler = handlers.get(cmd, self._cmd_unknown)
        await handler(args, raw)

    # =========================================================================
    # FTP Command Implementations
    # =========================================================================

    async def _cmd_user(self, args: str, raw: str) -> None:
        """Handle USER command."""
        self._username = args.strip()
        response = f"{FTP_NEED_PASSWORD} Please specify the password."
        await self._send(response)
        await self._log_interaction(raw, response)
        logger.info(f"[FTP] USER: {self._username} from {self._ip}:{self._port}")

    async def _cmd_pass(self, args: str, raw: str) -> None:
        """Handle PASS command with credential validation."""
        password = args.strip()

        # Check for anonymous login
        if self._username.lower() == "anonymous":
            self._authenticated = True
            self._session.authenticated = True
            self._session.username = "anonymous"
            response = f"{FTP_LOGIN_OK} Login successful."
            await self._send(response)
            await self._log_interaction(
                f"LOGIN: {self._username}:{password}", response
            )
            logger.info(
                f"[FTP] Anonymous login accepted from {self._ip}:{self._port}"
            )
            return

        # Check valid credentials
        if (self._username, password) in VALID_CREDENTIALS:
            self._authenticated = True
            self._session.authenticated = True
            self._session.username = self._username
            response = f"{FTP_LOGIN_OK} Login successful."
            await self._send(response)
            await self._log_interaction(
                f"LOGIN: {self._username}:{password}", response
            )
            logger.info(
                f"[FTP] Auth accepted (valid creds): {self._username}:{password} "
                f"from {self._ip}:{self._port}"
            )
            return

        # Increment failed attempts
        self._failed_attempts += 1

        # Accept after threshold
        if self._failed_attempts > MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT:
            self._authenticated = True
            self._session.authenticated = True
            self._session.username = self._username
            response = f"{FTP_LOGIN_OK} Login successful."
            await self._send(response)
            await self._log_interaction(
                f"LOGIN: {self._username}:{password}", response
            )
            logger.info(
                f"[FTP] Auth accepted (after {self._failed_attempts} failures): "
                f"{self._username}:{password} from {self._ip}:{self._port}"
            )
            return

        # Reject
        response = f"{FTP_LOGIN_FAIL} Login incorrect."
        await self._send(response)
        await self._log_interaction(
            f"LOGIN FAILED: {self._username}:{password}", response
        )
        logger.info(
            f"[FTP] Auth rejected (attempt {self._failed_attempts}): "
            f"{self._username}:{password} from {self._ip}:{self._port}"
        )

    async def _cmd_quit(self, args: str, raw: str) -> None:
        """Handle QUIT command."""
        response = f"{FTP_GOODBYE} Goodbye."
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_syst(self, args: str, raw: str) -> None:
        """Handle SYST command - return system type."""
        response = f"{FTP_SYSTEM_TYPE} UNIX Type: L8"
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_feat(self, args: str, raw: str) -> None:
        """Handle FEAT command - list supported features."""
        features = (
            "211-Features:\r\n"
            " EPRT\r\n"
            " EPSV\r\n"
            " MDTM\r\n"
            " PASV\r\n"
            " REST STREAM\r\n"
            " SIZE\r\n"
            " TVFS\r\n"
            " UTF8\r\n"
            "211 End"
        )
        self._writer.write(f"{features}\r\n".encode())
        await self._writer.drain()
        await self._log_interaction(raw, "211 Features listed")

    async def _cmd_pwd(self, args: str, raw: str) -> None:
        """Handle PWD command - print working directory."""
        response = f'{FTP_DIRECTORY} "{self._current_dir}" is the current directory'
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_cwd(self, args: str, raw: str) -> None:
        """Handle CWD command - change working directory."""
        target = args.strip() or "/"
        if target == "..":
            parts = self._current_dir.rstrip("/").split("/")
            self._current_dir = "/".join(parts[:-1]) or "/"
        elif target.startswith("/"):
            self._current_dir = target
        else:
            self._current_dir = f"{self._current_dir.rstrip('/')}/{target}"

        response = f"250 Directory successfully changed."
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_cdup(self, args: str, raw: str) -> None:
        """Handle CDUP command - move to parent directory."""
        await self._cmd_cwd("..", raw)

    async def _cmd_type(self, args: str, raw: str) -> None:
        """Handle TYPE command - set transfer type."""
        self._transfer_type = args.strip().upper()
        if self._transfer_type == "I":
            response = f"{FTP_CMD_OK} Switching to Binary mode."
        else:
            response = f"{FTP_CMD_OK} Switching to ASCII mode."
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_pasv(self, args: str, raw: str) -> None:
        """Handle PASV command - enter passive mode (simulated)."""
        # Simulate a passive mode response with a fake port
        # Format: (h1,h2,h3,h4,p1,p2) where port = p1*256+p2
        response = f"{FTP_PASSIVE_MODE} Entering Passive Mode (10,0,4,17,195,87)."
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_port(self, args: str, raw: str) -> None:
        """Handle PORT command - active mode (simulated)."""
        response = f"{FTP_CMD_OK} PORT command successful."
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_list(self, args: str, raw: str) -> None:
        """Handle LIST command - return directory listing."""
        await self._send(f"{FTP_FILE_OK} Here comes the directory listing.")

        # Select appropriate listing based on current directory
        if self._current_dir in ("/", "/root"):
            listing = FAKE_ROOT_LISTING
        elif "backup" in self._current_dir:
            listing = FAKE_BACKUPS_LISTING
        elif "config" in self._current_dir:
            listing = FAKE_CONFIG_LISTING
        else:
            listing = FAKE_ROOT_LISTING

        # Send listing data inline (since we don't have actual data connection)
        self._writer.write(listing.encode())
        await self._writer.drain()

        response = f"{FTP_TRANSFER_OK} Directory send OK."
        await self._send(response)
        await self._log_interaction(raw, f"Listed: {self._current_dir}")

    async def _cmd_nlst(self, args: str, raw: str) -> None:
        """Handle NLST command - return filename-only listing."""
        await self._send(f"{FTP_FILE_OK} Here comes the directory listing.")

        if self._current_dir in ("/", "/root"):
            names = "backups\r\nconfig\r\nhtml\r\ndeploy.sh\r\n.credentials\r\nlogs\r\nREADME.md\r\n"
        elif "backup" in self._current_dir:
            names = "db_backup_20240115.sql.gz\r\ndb_backup_20240114.sql.gz\r\nfull_backup_20240115.tar.gz\r\nconfig_backup.tar.gz\r\n"
        else:
            names = "backups\r\nconfig\r\nhtml\r\ndeploy.sh\r\nlogs\r\n"

        self._writer.write(names.encode())
        await self._writer.drain()

        response = f"{FTP_TRANSFER_OK} Directory send OK."
        await self._send(response)
        await self._log_interaction(raw, f"NLST: {self._current_dir}")

    async def _cmd_retr(self, args: str, raw: str) -> None:
        """Handle RETR command - simulate file download."""
        filename = args.strip()
        logger.info(
            f"[FTP] RETR: {filename} from {self._ip}:{self._port}"
        )

        # Check if we have fake content for this file
        basename = filename.split("/")[-1]
        if basename in FAKE_FILE_CONTENTS:
            content = FAKE_FILE_CONTENTS[basename]
            await self._send(
                f"{FTP_FILE_OK} Opening data connection for {filename} "
                f"({len(content)} bytes)."
            )
            self._writer.write(content.encode())
            await self._writer.drain()
            response = f"{FTP_TRANSFER_OK} Transfer complete."
            await self._send(response)
            await self._log_interaction(
                f"RETR {filename}", f"File served: {basename} ({len(content)} bytes)"
            )
        else:
            # Simulate a binary file download for known backup files
            if any(ext in filename for ext in [".gz", ".tar", ".zip", ".sql"]):
                await self._send(
                    f"{FTP_FILE_OK} Opening BINARY mode data connection for {filename}."
                )
                # Send a small amount of fake binary data
                fake_data = b"\x1f\x8b\x08\x00" + b"\x00" * 64  # gzip header + padding
                self._writer.write(fake_data)
                await self._writer.drain()
                response = f"{FTP_TRANSFER_OK} Transfer complete."
                await self._send(response)
                await self._log_interaction(
                    f"RETR {filename}", "Binary file transfer simulated"
                )
            else:
                response = f"{FTP_FILE_UNAVAIL} Failed to open file."
                await self._send(response)
                await self._log_interaction(f"RETR {filename}", response)

    async def _cmd_stor(self, args: str, raw: str) -> None:
        """Handle STOR command - simulate file upload capture."""
        filename = args.strip()
        logger.info(
            f"[FTP] STOR (upload attempt): {filename} from {self._ip}:{self._port}"
        )

        await self._send(
            f"{FTP_FILE_OK} Ok to send data."
        )

        # Read uploaded data (up to 1MB to prevent abuse)
        uploaded_data = b""
        try:
            while len(uploaded_data) < 1048576:  # 1MB max
                chunk = await asyncio.wait_for(
                    self._reader.read(4096), timeout=10
                )
                if not chunk:
                    break
                uploaded_data += chunk
        except asyncio.TimeoutError:
            pass

        response = f"{FTP_TRANSFER_OK} Transfer complete."
        await self._send(response)

        # Log the upload with size info
        await self._log_interaction(
            f"STOR {filename} ({len(uploaded_data)} bytes uploaded)",
            f"Upload captured: {filename} size={len(uploaded_data)}",
        )

        # Track the file in the virtual filesystem
        if self._session:
            path = f"{self._current_dir.rstrip('/')}/{filename}"
            self._session.virtual_fs.files[path] = f"(uploaded: {len(uploaded_data)} bytes)"

    async def _cmd_dele(self, args: str, raw: str) -> None:
        """Handle DELE command - simulate file deletion."""
        filename = args.strip()
        response = f"250 Delete operation successful."
        await self._send(response)
        await self._log_interaction(raw, response)
        logger.info(f"[FTP] DELE: {filename} from {self._ip}:{self._port}")

    async def _cmd_mkd(self, args: str, raw: str) -> None:
        """Handle MKD command - simulate directory creation."""
        dirname = args.strip()
        response = f'{FTP_DIRECTORY} "{self._current_dir.rstrip("/")}/{dirname}" created'
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_rmd(self, args: str, raw: str) -> None:
        """Handle RMD command - simulate directory removal."""
        response = "250 Remove directory operation successful."
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_rnfr(self, args: str, raw: str) -> None:
        """Handle RNFR command - rename from."""
        self._rename_from = args.strip()
        response = "350 Ready for RNTO."
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_rnto(self, args: str, raw: str) -> None:
        """Handle RNTO command - rename to."""
        rename_to = args.strip()
        response = "250 Rename successful."
        await self._send(response)
        await self._log_interaction(
            f"RENAME {self._rename_from} -> {rename_to}", response
        )

    async def _cmd_size(self, args: str, raw: str) -> None:
        """Handle SIZE command - return fake file size."""
        filename = args.strip().split("/")[-1]
        # Return realistic sizes for known files
        sizes = {
            "deploy.sh": 287,
            ".credentials": 198,
            "README.md": 312,
            "db_backup_20240115.sql.gz": 52428800,
            "full_backup_20240115.tar.gz": 104857600,
        }
        size = sizes.get(filename, 4096)
        response = f"213 {size}"
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_noop(self, args: str, raw: str) -> None:
        """Handle NOOP command - keep alive."""
        response = f"{FTP_CMD_OK} NOOP ok."
        await self._send(response)

    async def _cmd_auth(self, args: str, raw: str) -> None:
        """Handle AUTH command - reject TLS (we want plaintext creds)."""
        response = "534 AUTH not supported."
        await self._send(response)
        await self._log_interaction(raw, response)

    async def _cmd_unknown(self, args: str, raw: str) -> None:
        """Handle unknown/unimplemented commands."""
        response = f"{FTP_NOT_IMPLEMENTED} Command not implemented."
        await self._send(response)
        await self._log_interaction(raw, response)


async def start_ftp_server(
    host: str = "0.0.0.0",
    port: int = FTP_PORT,
    log_callback: Optional[Callable[..., Awaitable]] = None,
) -> asyncio.Server:
    """
    Start the FTP honeypot server.

    Args:
        host: Bind address (default: all interfaces).
        port: Listen port (default: 21).
        log_callback: Async callback for logging interactions.

    Returns:
        The asyncio.Server instance for lifecycle management.
    """

    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        handler = FTPClientHandler(reader, writer, log_callback)
        await handler.handle()

    server = await asyncio.start_server(client_connected, host, port)
    logger.info(f"[FTP] Honeypot listening on {host}:{port}")
    return server
