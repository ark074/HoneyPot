"""
AegisTrap - Multi-Service AI-Driven Honeypot Framework
========================================================
Main entry point that initializes and boots all honeypot services
concurrently using asyncio.

Services launched:
- SSH Honeypot    (port 2222)
- Telnet Honeypot (port 23)
- HTTP Honeypot   (ports 80, 8080)
- FTP Honeypot    (port 21)

All interactions are:
1. Processed through the SecurityGateway (rate limiting, payload capture)
2. Forwarded to the AI Context Bridge (Ollama LLM)
3. Logged to structured JSON (logs/honeypot_activity.json)
"""

import sys
import signal
import asyncio
import logging

from config import (
    SSH_PORT,
    TELNET_PORT,
    HTTP_PORT,
    HTTP_ALT_PORT,
    FTP_PORT,
    OLLAMA_HOST,
    OLLAMA_MODEL,
    RATE_LIMIT_REQUESTS_PER_MINUTE,
    SESSION_TIMEOUT_SECONDS,
    LOG_FILE,
)
from aegistrap.core.logger import (
    setup_console_logging,
    structured_logger,
    log_interaction,
)
from aegistrap.core.session_manager import session_manager, ai_bridge
from aegistrap.core.security import security_gateway
from aegistrap.services.ssh_service import start_ssh_server
from aegistrap.services.telnet_service import start_telnet_server
from aegistrap.services.http_service import start_http_servers
from aegistrap.services.ftp_service import start_ftp_server

logger = logging.getLogger("aegistrap.main")

# =============================================================================
# ASCII Banner
# =============================================================================
BANNER = r"""
    ___              _     _____                 
   /   \  ___  __ _(_)___/__   \_ __ __ _ _ __  
  / /\ / / _ \/ _` | / __|  / /\/ '__/ _` | '_ \ 
 / /_// |  __/ (_| | \__ \ / /  | | | (_| | |_) |
/___,'   \___|\__, |_|___/ \/   |_|  \__,_| .__/ 
              |___/                         |_|    

  Multi-Service AI-Driven Honeypot Framework v1.0.0
  ================================================
"""


def print_boot_config() -> None:
    """Print the boot configuration to console for operator visibility."""
    print(BANNER)
    print("  CONFIGURATION")
    print("  " + "=" * 50)
    print(f"  LLM Backend:     {OLLAMA_HOST}")
    print(f"  LLM Model:       {OLLAMA_MODEL}")
    print(f"  Log Output:      {LOG_FILE}")
    print(f"  Rate Limit:      {RATE_LIMIT_REQUESTS_PER_MINUTE} req/min/IP")
    print(f"  Session Timeout: {SESSION_TIMEOUT_SECONDS // 60} minutes")
    print()
    print("  SERVICE MATRIX")
    print("  " + "=" * 50)
    print(f"  [SSH]    0.0.0.0:{SSH_PORT}")
    print(f"  [Telnet] 0.0.0.0:{TELNET_PORT}")
    print(f"  [HTTP]   0.0.0.0:{HTTP_PORT}, 0.0.0.0:{HTTP_ALT_PORT}")
    print(f"  [FTP]    0.0.0.0:{FTP_PORT}")
    print()
    print("  SECURITY")
    print("  " + "=" * 50)
    print("  [+] Absolute isolation: Commands NEVER execute on host")
    print("  [+] Payload capture: wget/curl URLs logged to threat intel")
    print("  [+] Rate limiting: Active per-IP sliding window")
    print("  [+] Session throttle: Auto-disconnect after timeout")
    print()
    print("  " + "-" * 50)
    print("  Honeypot is ARMED and listening for connections...")
    print("  " + "-" * 50)
    print()


async def session_cleanup_task() -> None:
    """
    Background task that periodically cleans up expired sessions.
    Runs every 60 seconds to free resources from abandoned connections.
    """
    while True:
        try:
            await asyncio.sleep(60)
            cleaned = await session_manager.cleanup_expired()
            if cleaned > 0:
                logger.info(f"[Cleanup] Removed {cleaned} expired session(s)")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"[Cleanup] Error during session cleanup: {e}")


async def start_all_services() -> None:
    """
    Initialize and start all honeypot services concurrently.
    Handles graceful startup with error recovery per service.
    """
    # Initialize the structured logger
    await structured_logger.initialize()
    logger.info("[Boot] Structured logger initialized")

    # Track running services for cleanup
    services = []
    http_runners = []

    # --- Start SSH Service ---
    try:
        ssh_server = await start_ssh_server(
            host="0.0.0.0",
            port=SSH_PORT,
            log_callback=log_interaction,
        )
        services.append(("SSH", ssh_server))
        logger.info(f"[Boot] SSH service started on port {SSH_PORT}")
    except Exception as e:
        logger.error(f"[Boot] Failed to start SSH service: {e}")

    # --- Start Telnet Service ---
    try:
        telnet_server = await start_telnet_server(
            host="0.0.0.0",
            port=TELNET_PORT,
            log_callback=log_interaction,
        )
        services.append(("Telnet", telnet_server))
        logger.info(f"[Boot] Telnet service started on port {TELNET_PORT}")
    except Exception as e:
        logger.error(f"[Boot] Failed to start Telnet service: {e}")

    # --- Start HTTP Services (port 80 and 8080) ---
    try:
        http_runners = await start_http_servers(
            host="0.0.0.0",
            log_callback=log_interaction,
        )
        logger.info(
            f"[Boot] HTTP service started on ports {HTTP_PORT} and {HTTP_ALT_PORT}"
        )
    except Exception as e:
        logger.error(f"[Boot] Failed to start HTTP service: {e}")

    # --- Start FTP Service ---
    try:
        ftp_server = await start_ftp_server(
            host="0.0.0.0",
            port=FTP_PORT,
            log_callback=log_interaction,
        )
        services.append(("FTP", ftp_server))
        logger.info(f"[Boot] FTP service started on port {FTP_PORT}")
    except Exception as e:
        logger.error(f"[Boot] Failed to start FTP service: {e}")

    # --- Start Background Tasks ---
    cleanup_task = asyncio.create_task(session_cleanup_task())

    # Print summary
    active_count = len(services) + (1 if http_runners else 0)
    logger.info(
        f"[Boot] All services started. {active_count} service group(s) active. "
        f"Waiting for connections..."
    )

    # --- Wait for shutdown signal ---
    try:
        # Create a future that will never complete (keeps the event loop running)
        shutdown_event = asyncio.Event()

        # Register signal handlers for graceful shutdown
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, shutdown_event.set)

        await shutdown_event.wait()

    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        logger.info("[Shutdown] Initiating graceful shutdown...")

        # Cancel cleanup task
        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass

        # Close SSH server
        for name, server in services:
            try:
                if hasattr(server, "close"):
                    server.close()
                    if hasattr(server, "wait_closed"):
                        await server.wait_closed()
                logger.info(f"[Shutdown] {name} service stopped")
            except Exception as e:
                logger.error(f"[Shutdown] Error stopping {name}: {e}")

        # Close HTTP runners
        for runner in http_runners:
            try:
                await runner.cleanup()
            except Exception as e:
                logger.error(f"[Shutdown] Error stopping HTTP runner: {e}")
        logger.info("[Shutdown] HTTP service stopped")

        # Close AI bridge HTTP session
        await ai_bridge.close()
        logger.info("[Shutdown] AI bridge closed")

        logger.info("[Shutdown] AegisTrap shutdown complete. Goodbye.")


def main() -> None:
    """Main entry point for the AegisTrap honeypot."""
    # Setup console logging
    setup_console_logging(level=logging.INFO)

    # Print boot configuration
    print_boot_config()

    # Verify Python version
    if sys.version_info < (3, 11):
        logger.error(
            f"[Boot] Python 3.11+ required. Current: {sys.version_info.major}."
            f"{sys.version_info.minor}"
        )
        sys.exit(1)

    # Run the async main loop
    try:
        asyncio.run(start_all_services())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by operator. Shutting down...")
    except Exception as e:
        logger.critical(f"[Fatal] Unhandled exception: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
