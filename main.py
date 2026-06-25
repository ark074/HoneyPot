"""
AegisTrap - Multi-Service AI-Driven Honeypot Framework v2.0
=============================================================
Enhanced main entry point with full advanced module integration.

Core Services:
- SSH Honeypot (port 2222), Telnet (23), HTTP (80/8080), FTP (21)

Advanced Capabilities:
- GeoIP enrichment (MaxMind GeoLite2)
- MITRE ATT&CK auto-classification
- AI-powered attacker profiling
- Real-time threat intelligence feeds
- Dynamic honeytokens & breadcrumbs
- Network fingerprinting (HASSH/JA3)
- YARA malware scanning
- Adaptive AI persona engine
- Real-time WebSocket dashboard (port 9000)
- Multi-channel alerting (Slack/Discord/Telegram/Webhook)
- Session replay & forensic timeline
- Prometheus metrics for Grafana
"""

import sys
import signal
import asyncio
import logging

from config import (
    SSH_PORT, TELNET_PORT, HTTP_PORT, HTTP_ALT_PORT, FTP_PORT,
    OLLAMA_HOST, OLLAMA_MODEL,
    RATE_LIMIT_REQUESTS_PER_MINUTE, SESSION_TIMEOUT_SECONDS, LOG_FILE,
)
from aegistrap.core.logger import (
    setup_console_logging, structured_logger, log_interaction,
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

  Multi-Service AI-Driven Honeypot Framework v2.0
  ================================================
  Next-Gen Threat Intelligence & Deception Platform
"""


def print_boot_config() -> None:
    """Print the boot configuration to console."""
    print(BANNER)
    print("  CONFIGURATION")
    print("  " + "=" * 55)
    print(f"  LLM Backend:       {OLLAMA_HOST}")
    print(f"  LLM Model:         {OLLAMA_MODEL}")
    print(f"  Log Output:        {LOG_FILE}")
    print(f"  Rate Limit:        {RATE_LIMIT_REQUESTS_PER_MINUTE} req/min/IP")
    print(f"  Session Timeout:   {SESSION_TIMEOUT_SECONDS // 60} minutes")
    print()
    print("  HONEYPOT SERVICES")
    print("  " + "=" * 55)
    print(f"  [SSH]    0.0.0.0:{SSH_PORT}")
    print(f"  [Telnet] 0.0.0.0:{TELNET_PORT}")
    print(f"  [HTTP]   0.0.0.0:{HTTP_PORT}, 0.0.0.0:{HTTP_ALT_PORT}")
    print(f"  [FTP]    0.0.0.0:{FTP_PORT}")
    print(f"  [API]    0.0.0.0:9000 (Dashboard + WebSocket + Metrics)")
    print()
    print("  ADVANCED MODULES")
    print("  " + "=" * 55)
    print("  [+] GeoIP Enrichment        (MaxMind GeoLite2)")
    print("  [+] MITRE ATT&CK Mapping    (50+ technique patterns)")
    print("  [+] Attacker Profiling       (ML-based skill/intent)")
    print("  [+] Threat Intel Feeds       (abuse.ch, Shodan, Tor)")
    print("  [+] Dynamic Honeytokens      (AWS/API/JWT/SSH keys)")
    print("  [+] Network Fingerprinting   (HASSH, HTTP, TCP/IP)")
    print("  [+] YARA Scanning            (7+ built-in rules)")
    print("  [+] Adaptive Personas        (7 server types)")
    print("  [+] Real-Time Dashboard      (FastAPI + WebSocket)")
    print("  [+] Multi-Channel Alerts     (Slack/Discord/Telegram)")
    print("  [+] Session Replay           (Asciinema + Forensics)")
    print("  [+] Prometheus Metrics       (Grafana-ready)")
    print()
    print("  SECURITY HARDENING")
    print("  " + "=" * 55)
    print("  [+] Absolute isolation: Commands NEVER execute on host")
    print("  [+] Payload capture: wget/curl URLs logged to threat intel")
    print("  [+] Rate limiting: Active per-IP sliding window")
    print("  [+] Session throttle: Auto-disconnect after timeout")
    print()
    print("  " + "-" * 55)
    print("  Honeypot is ARMED and listening for connections...")
    print("  " + "-" * 55)
    print()


async def initialize_advanced_modules() -> None:
    """Initialize all advanced modules with graceful degradation."""
    # GeoIP Enrichment
    try:
        from aegistrap.advanced.geoip_enrichment import geoip_enrichment
        await geoip_enrichment.initialize()
        logger.info("[Boot] GeoIP enrichment initialized")
    except Exception as e:
        logger.warning(f"[Boot] GeoIP initialization skipped: {e}")

    # YARA Scanner
    try:
        from aegistrap.advanced.yara_scanner import yara_scanner
        await yara_scanner.initialize()
        logger.info("[Boot] YARA scanner initialized")
    except Exception as e:
        logger.warning(f"[Boot] YARA initialization skipped: {e}")

    # Threat Intelligence Feeds
    try:
        from aegistrap.advanced.threat_feeds import threat_feed_manager
        await threat_feed_manager.initialize()
        logger.info("[Boot] Threat intelligence feeds initialized")
    except Exception as e:
        logger.warning(f"[Boot] Threat feeds initialization skipped: {e}")

    # Modules that don't need async init
    logger.info("[Boot] MITRE ATT&CK classifier ready")
    logger.info("[Boot] Attacker profiler ready")
    logger.info("[Boot] Honeytoken manager ready")
    logger.info("[Boot] Fingerprint engine ready")
    logger.info("[Boot] Adaptive persona engine ready")
    logger.info("[Boot] Session recorder ready")
    logger.info("[Boot] Alert engine ready")


async def start_dashboard_api() -> None:
    """Start the FastAPI dashboard on port 9000."""
    try:
        import uvicorn
        from aegistrap.dashboard.api import create_dashboard_app

        app = create_dashboard_app()
        config = uvicorn.Config(
            app, host="0.0.0.0", port=9000,
            log_level="warning", access_log=False,
        )
        server = uvicorn.Server(config)
        # Run in background task
        asyncio.create_task(server.serve())
        logger.info("[Boot] Dashboard API started on port 9000")
    except ImportError as e:
        logger.warning(f"[Boot] Dashboard API not started (missing deps): {e}")
    except Exception as e:
        logger.error(f"[Boot] Dashboard API failed to start: {e}")


async def session_cleanup_task() -> None:
    """Background task for session cleanup every 60 seconds."""
    while True:
        try:
            await asyncio.sleep(60)
            cleaned = await session_manager.cleanup_expired()
            if cleaned > 0:
                logger.info(f"[Cleanup] Removed {cleaned} expired session(s)")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"[Cleanup] Error: {e}")


async def start_all_services() -> None:
    """Initialize and start all honeypot services concurrently."""
    # Initialize structured logger
    await structured_logger.initialize()
    logger.info("[Boot] Structured logger initialized")

    # Initialize advanced modules (graceful degradation)
    await initialize_advanced_modules()

    # Start Dashboard API
    await start_dashboard_api()

    # Track running services
    services = []
    http_runners = []

    # --- Start SSH Service ---
    try:
        ssh_server = await start_ssh_server(
            host="0.0.0.0", port=SSH_PORT, log_callback=log_interaction,
        )
        services.append(("SSH", ssh_server))
        logger.info(f"[Boot] SSH service started on port {SSH_PORT}")
    except Exception as e:
        logger.error(f"[Boot] Failed to start SSH service: {e}")

    # --- Start Telnet Service ---
    try:
        telnet_server = await start_telnet_server(
            host="0.0.0.0", port=TELNET_PORT, log_callback=log_interaction,
        )
        services.append(("Telnet", telnet_server))
        logger.info(f"[Boot] Telnet service started on port {TELNET_PORT}")
    except Exception as e:
        logger.error(f"[Boot] Failed to start Telnet service: {e}")

    # --- Start HTTP Services ---
    try:
        http_runners = await start_http_servers(
            host="0.0.0.0", log_callback=log_interaction,
        )
        logger.info(f"[Boot] HTTP service started on ports {HTTP_PORT}, {HTTP_ALT_PORT}")
    except Exception as e:
        logger.error(f"[Boot] Failed to start HTTP service: {e}")

    # --- Start FTP Service ---
    try:
        ftp_server = await start_ftp_server(
            host="0.0.0.0", port=FTP_PORT, log_callback=log_interaction,
        )
        services.append(("FTP", ftp_server))
        logger.info(f"[Boot] FTP service started on port {FTP_PORT}")
    except Exception as e:
        logger.error(f"[Boot] Failed to start FTP service: {e}")

    # --- Background Tasks ---
    cleanup_task = asyncio.create_task(session_cleanup_task())

    # Print summary
    active_count = len(services) + (1 if http_runners else 0)
    logger.info(
        f"[Boot] All services started. {active_count} service group(s) active. "
        f"Waiting for connections..."
    )

    # --- Wait for shutdown signal ---
    try:
        shutdown_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, shutdown_event.set)
        await shutdown_event.wait()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        logger.info("[Shutdown] Initiating graceful shutdown...")

        cleanup_task.cancel()
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass

        for name, server in services:
            try:
                if hasattr(server, "close"):
                    server.close()
                    if hasattr(server, "wait_closed"):
                        await server.wait_closed()
                logger.info(f"[Shutdown] {name} service stopped")
            except Exception as e:
                logger.error(f"[Shutdown] Error stopping {name}: {e}")

        for runner in http_runners:
            try:
                await runner.cleanup()
            except Exception:
                pass
        logger.info("[Shutdown] HTTP service stopped")

        await ai_bridge.close()

        # Shutdown advanced modules
        try:
            from aegistrap.advanced.threat_feeds import threat_feed_manager
            await threat_feed_manager.shutdown()
        except Exception:
            pass
        try:
            from aegistrap.advanced.alerting import alert_engine
            await alert_engine.shutdown()
        except Exception:
            pass

        logger.info("[Shutdown] AegisTrap shutdown complete. Goodbye.")


def main() -> None:
    """Main entry point for AegisTrap."""
    setup_console_logging(level=logging.INFO)
    print_boot_config()

    if sys.version_info < (3, 11):
        logger.error(
            f"[Boot] Python 3.11+ required. Current: "
            f"{sys.version_info.major}.{sys.version_info.minor}"
        )
        sys.exit(1)

    try:
        asyncio.run(start_all_services())
    except KeyboardInterrupt:
        print("\n[*] Interrupted by operator. Shutting down...")
    except Exception as e:
        logger.critical(f"[Fatal] Unhandled exception: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
