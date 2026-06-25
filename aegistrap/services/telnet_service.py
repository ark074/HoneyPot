"""
AegisTrap Telnet Honeypot Service
===================================
Provides a realistic Telnet server on port 23 using asyncio streams.
Handles login prompts, credential acceptance, and relays commands
to the AI engine for dynamic response generation.
"""

import asyncio
import logging
from typing import Optional, Callable, Awaitable

from config import (
    TELNET_PORT,
    TELNET_BANNER,
    VALID_CREDENTIALS,
    MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT,
    SESSION_TIMEOUT_SECONDS,
)
from aegistrap.core.session_manager import session_manager, ai_bridge, AttackerSession

logger = logging.getLogger("aegistrap.telnet")

# Telnet protocol constants
IAC = bytes([255])   # Interpret As Command
WILL = bytes([251])
WONT = bytes([252])
DO = bytes([253])
DONT = bytes([254])
SGA = bytes([3])     # Suppress Go Ahead
ECHO = bytes([1])    # Echo


class TelnetClientHandler:
    """
    Handles a single Telnet client connection.
    Manages the login sequence, interactive shell, and session lifecycle.
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

    async def handle(self) -> None:
        """
        Main entry point for handling a telnet connection.
        Performs login then enters interactive shell mode.
        """
        peername = self._writer.get_extra_info("peername")
        self._ip = peername[0] if peername else "unknown"
        self._port = peername[1] if peername else 0

        logger.info(f"[Telnet] New connection from {self._ip}:{self._port}")

        try:
            # Send initial Telnet negotiations
            await self._negotiate()

            # Perform login sequence
            authenticated = await self._login_sequence()
            if not authenticated:
                self._writer.write(b"\r\nToo many failed attempts. Disconnecting.\r\n")
                await self._writer.drain()
                return

            # Create session and enter shell
            self._session = await session_manager.create_session(
                self._ip, self._port, "Telnet"
            )
            self._session.authenticated = True

            # Send login success banner
            await self._send_motd()

            # Enter interactive command loop
            await self._shell_loop()

        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            logger.info(f"[Telnet] Connection reset from {self._ip}:{self._port}")
        except asyncio.TimeoutError:
            logger.info(f"[Telnet] Connection timeout from {self._ip}:{self._port}")
        except Exception as e:
            logger.error(f"[Telnet] Unexpected error from {self._ip}:{self._port}: {e}")
        finally:
            # Cleanup
            if self._session:
                await session_manager.destroy_session(self._ip, self._port)
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            logger.info(f"[Telnet] Connection closed from {self._ip}:{self._port}")

    async def _negotiate(self) -> None:
        """Send Telnet option negotiations for proper terminal handling."""
        # Tell client we will echo (so password input works)
        self._writer.write(IAC + WILL + ECHO)
        # Tell client we will suppress go-ahead
        self._writer.write(IAC + WILL + SGA)
        # Request client to suppress go-ahead
        self._writer.write(IAC + DO + SGA)
        await self._writer.drain()

        # Give client a moment to respond to negotiations
        await asyncio.sleep(0.1)

        # Consume any negotiation responses from client
        try:
            if self._reader._buffer:
                await asyncio.wait_for(self._reader.read(1024), timeout=0.5)
        except (asyncio.TimeoutError, Exception):
            pass

    async def _login_sequence(self) -> bool:
        """
        Handle the login prompt sequence.
        Returns True if authentication succeeds, False otherwise.
        """
        failed_attempts = 0
        max_total_attempts = MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT + 2

        for attempt in range(max_total_attempts):
            # Display banner / login prompt
            self._writer.write(TELNET_BANNER.encode())
            await self._writer.drain()

            # Read username
            username = await self._read_line(echo=True)
            if username is None:
                return False
            username = username.strip()

            # Prompt for password (no echo)
            self._writer.write(b"Password: ")
            await self._writer.drain()

            # Disable echo for password
            self._writer.write(IAC + WILL + ECHO)
            await self._writer.drain()

            password = await self._read_line(echo=False)
            if password is None:
                return False
            password = password.strip()

            # Re-enable echo
            self._writer.write(IAC + WONT + ECHO)
            self._writer.write(b"\r\n")
            await self._writer.drain()

            # Log the credential attempt
            if self._log_callback:
                # Create a temporary session for logging auth attempts
                temp_session = await session_manager.create_session(
                    self._ip, self._port, "Telnet"
                )
                await self._log_callback(
                    session=temp_session,
                    input_received=f"LOGIN: {username}:{password}",
                    ai_response="(authentication attempt)",
                )
                await session_manager.destroy_session(self._ip, self._port)

            # Check credentials
            if (username, password) in VALID_CREDENTIALS:
                logger.info(
                    f"[Telnet] Auth accepted (valid creds): {username}:{password} "
                    f"from {self._ip}:{self._port}"
                )
                self._username = username
                return True

            failed_attempts += 1

            # Accept any credentials after threshold
            if failed_attempts > MAX_FAILED_ATTEMPTS_BEFORE_ACCEPT:
                logger.info(
                    f"[Telnet] Auth accepted (after {failed_attempts} failures): "
                    f"{username}:{password} from {self._ip}:{self._port}"
                )
                self._username = username
                return True

            # Show failure message
            self._writer.write(b"\r\nLogin incorrect\r\n\r\n")
            await self._writer.drain()
            logger.info(
                f"[Telnet] Auth rejected (attempt {failed_attempts}): "
                f"{username}:{password} from {self._ip}:{self._port}"
            )

        return False

    async def _send_motd(self) -> None:
        """Send the message of the day after successful login."""
        motd = (
            "\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
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
        self._writer.write(motd.encode())
        await self._writer.drain()

    async def _shell_loop(self) -> None:
        """
        Interactive shell loop. Displays prompt, reads commands,
        and returns AI-generated responses.
        """
        session = self._session
        session.username = getattr(self, "_username", "root")

        while not session.is_expired():
            # Display prompt
            prompt = f"{session.username}@corp-srv-prod-01:{session.virtual_fs.cwd}# "
            self._writer.write(prompt.encode())
            await self._writer.drain()

            # Read command
            try:
                command = await asyncio.wait_for(
                    self._read_line(echo=True), timeout=300
                )
            except asyncio.TimeoutError:
                self._writer.write(b"\r\nConnection timed out.\r\n")
                await self._writer.drain()
                break

            if command is None:
                break

            command = command.strip()
            if not command:
                continue

            # Handle exit commands
            if command in ("exit", "logout", "quit"):
                self._writer.write(b"logout\r\n")
                await self._writer.drain()
                break

            # Generate AI response
            try:
                response = await ai_bridge.generate_response(session, command)
            except Exception as e:
                logger.error(f"[Telnet] AI bridge error: {e}")
                response = f"bash: {command}: command not found"

            # Send response
            if response:
                formatted = response.replace("\n", "\r\n")
                if not formatted.endswith("\r\n"):
                    formatted += "\r\n"
                self._writer.write(formatted.encode())
                await self._writer.drain()

            # Log the interaction
            if self._log_callback:
                await self._log_callback(
                    session=session,
                    input_received=command,
                    ai_response=response,
                )

            # Update session activity
            session.update_activity()

    async def _read_line(self, echo: bool = True) -> Optional[str]:
        """
        Read a line of input from the telnet client character by character.
        Handles backspace and provides optional local echo.

        Args:
            echo: Whether to echo characters back to the client.

        Returns:
            The input line as a string, or None if connection closed.
        """
        line_buffer = []

        while True:
            try:
                data = await asyncio.wait_for(
                    self._reader.read(1), timeout=SESSION_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                return None

            if not data:
                return None

            byte = data[0]

            # Handle Telnet IAC sequences
            if byte == 255:
                # Read the command byte
                try:
                    cmd_data = await self._reader.read(1)
                    if cmd_data and cmd_data[0] in (251, 252, 253, 254):
                        # Option negotiation - read option byte
                        await self._reader.read(1)
                except Exception:
                    pass
                continue

            # Handle Enter (CR or LF)
            if byte in (13, 10):
                # Consume trailing LF after CR if present
                if byte == 13:
                    try:
                        next_byte = await asyncio.wait_for(
                            self._reader.read(1), timeout=0.1
                        )
                        if next_byte and next_byte[0] != 10:
                            # Not a LF, put it back conceptually (ignore for simplicity)
                            pass
                    except asyncio.TimeoutError:
                        pass

                if echo:
                    self._writer.write(b"\r\n")
                    await self._writer.drain()
                return "".join(line_buffer)

            # Handle Backspace (BS or DEL)
            if byte in (8, 127):
                if line_buffer:
                    line_buffer.pop()
                    if echo:
                        self._writer.write(b"\b \b")
                        await self._writer.drain()
                continue

            # Regular printable character
            if 32 <= byte < 127:
                line_buffer.append(chr(byte))
                if echo:
                    self._writer.write(bytes([byte]))
                    await self._writer.drain()


async def start_telnet_server(
    host: str = "0.0.0.0",
    port: int = TELNET_PORT,
    log_callback: Optional[Callable[..., Awaitable]] = None,
) -> asyncio.Server:
    """
    Start the Telnet honeypot server.

    Args:
        host: Bind address (default: all interfaces).
        port: Listen port (default: 23).
        log_callback: Async callback for logging interactions.

    Returns:
        The asyncio.Server instance for lifecycle management.
    """

    async def client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        handler = TelnetClientHandler(reader, writer, log_callback)
        await handler.handle()

    server = await asyncio.start_server(client_connected, host, port)
    logger.info(f"[Telnet] Honeypot listening on {host}:{port}")
    return server
