"""
AegisTrap Real-Time WebSocket Dashboard API
==============================================
Provides a FastAPI-based REST + WebSocket API for live monitoring.
Streams attack events in real-time to connected dashboard clients.

Free Tools Used:
- FastAPI (MIT license) - Modern async Python web framework
- WebSockets - Real-time bidirectional communication
- Prometheus client (Apache 2.0) - Metrics export for Grafana

Endpoints:
- GET  /api/v1/status          - System health & stats
- GET  /api/v1/sessions        - Active attacker sessions
- GET  /api/v1/sessions/{id}   - Session detail with full history
- GET  /api/v1/threats         - Recent threat intelligence hits
- GET  /api/v1/stats/mitre     - MITRE ATT&CK statistics
- GET  /api/v1/stats/geo       - Geographic attack distribution
- GET  /api/v1/stats/profiles  - Attacker profiling statistics
- GET  /api/v1/honeytokens     - Honeytoken status
- WS   /ws/live                - Real-time event stream
- GET  /metrics                - Prometheus metrics endpoint
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Set, Optional, Any
from datetime import datetime, timezone
from dataclasses import dataclass, field

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

logger = logging.getLogger("aegistrap.dashboard")



# =============================================================================
# Dashboard Configuration
# =============================================================================
DASHBOARD_PORT = 9000
MAX_WEBSOCKET_CLIENTS = 50
EVENT_BUFFER_SIZE = 1000  # Keep last N events in memory


@dataclass
class DashboardEvent:
    """A single event for the real-time dashboard stream."""
    event_type: str          # attack, auth, threat, honeytoken, session_start, session_end
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    data: Dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps({
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "data": self.data,
        })


class WebSocketManager:
    """
    Manages WebSocket connections for real-time event streaming.
    Handles client registration, broadcast, and cleanup.
    """

    def __init__(self, max_clients: int = MAX_WEBSOCKET_CLIENTS):
        self._clients: Set[WebSocket] = set()
        self._max_clients = max_clients
        self._lock = asyncio.Lock()
        self._event_buffer: List[DashboardEvent] = []
        self._total_events_sent: int = 0

    async def connect(self, websocket: WebSocket) -> bool:
        """Accept a new WebSocket connection."""
        if len(self._clients) >= self._max_clients:
            await websocket.close(code=1013, reason="Max clients reached")
            return False

        await websocket.accept()
        async with self._lock:
            self._clients.add(websocket)

        logger.info(
            f"[Dashboard] WebSocket client connected. "
            f"Active: {len(self._clients)}"
        )

        # Send recent event history to new client
        for event in self._event_buffer[-50:]:
            try:
                await websocket.send_text(event.to_json())
            except Exception:
                break

        return True

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket client."""
        async with self._lock:
            self._clients.discard(websocket)
        logger.info(
            f"[Dashboard] WebSocket client disconnected. "
            f"Active: {len(self._clients)}"
        )

    async def broadcast(self, event: DashboardEvent) -> None:
        """Broadcast an event to all connected WebSocket clients."""
        # Add to buffer
        self._event_buffer.append(event)
        if len(self._event_buffer) > EVENT_BUFFER_SIZE:
            self._event_buffer = self._event_buffer[-EVENT_BUFFER_SIZE:]

        # Broadcast to all clients
        message = event.to_json()
        disconnected = set()

        for client in self._clients.copy():
            try:
                await client.send_text(message)
                self._total_events_sent += 1
            except Exception:
                disconnected.add(client)

        # Cleanup disconnected clients
        if disconnected:
            async with self._lock:
                self._clients -= disconnected

    @property
    def client_count(self) -> int:
        return len(self._clients)

    @property
    def total_events(self) -> int:
        return self._total_events_sent


# =============================================================================
# Prometheus Metrics
# =============================================================================

class PrometheusMetrics:
    """Simple Prometheus metrics collector for Grafana integration."""

    def __init__(self):
        self._counters: Dict[str, int] = {
            "aegistrap_connections_total": 0,
            "aegistrap_commands_total": 0,
            "aegistrap_auth_attempts_total": 0,
            "aegistrap_auth_success_total": 0,
            "aegistrap_threats_detected_total": 0,
            "aegistrap_honeytokens_triggered_total": 0,
            "aegistrap_rate_limit_blocks_total": 0,
        }
        self._gauges: Dict[str, float] = {
            "aegistrap_active_sessions": 0,
            "aegistrap_websocket_clients": 0,
            "aegistrap_threat_feeds_iocs": 0,
            "aegistrap_uptime_seconds": 0,
        }
        self._start_time = time.time()

    def increment(self, metric: str, value: int = 1) -> None:
        if metric in self._counters:
            self._counters[metric] += value

    def set_gauge(self, metric: str, value: float) -> None:
        if metric in self._gauges:
            self._gauges[metric] = value

    def export(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []
        self._gauges["aegistrap_uptime_seconds"] = time.time() - self._start_time

        for name, value in self._counters.items():
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")

        for name, value in self._gauges.items():
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")

        return "\n".join(lines) + "\n"



# =============================================================================
# FastAPI Application
# =============================================================================

# Global instances
ws_manager = WebSocketManager()
metrics = PrometheusMetrics()


def create_dashboard_app() -> FastAPI:
    """Create and configure the FastAPI dashboard application."""

    app = FastAPI(
        title="AegisTrap Dashboard API",
        description="Real-time honeypot monitoring and threat intelligence dashboard",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # CORS for frontend dashboard access
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # =========================================================================
    # REST API Endpoints
    # =========================================================================

    @app.get("/api/v1/status")
    async def get_status():
        """System health and overview statistics."""
        from aegistrap.core.session_manager import session_manager
        from aegistrap.core.security import security_gateway

        return {
            "status": "operational",
            "version": "1.0.0",
            "uptime_seconds": time.time() - metrics._start_time,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "active_sessions": session_manager.active_session_count,
            "websocket_clients": ws_manager.client_count,
            "total_events_streamed": ws_manager.total_events,
            "security": security_gateway.get_security_stats(),
        }

    @app.get("/api/v1/sessions")
    async def get_sessions():
        """List all active attacker sessions."""
        from aegistrap.core.session_manager import session_manager

        sessions = []
        for key, session in session_manager._sessions.items():
            sessions.append({
                "session_id": session.session_id,
                "attacker_ip": session.attacker_ip,
                "attacker_port": session.attacker_port,
                "service": session.service,
                "username": session.username,
                "authenticated": session.authenticated,
                "request_count": session.request_count,
                "created_at": datetime.fromtimestamp(
                    session.created_at, tz=timezone.utc
                ).isoformat(),
                "last_activity": datetime.fromtimestamp(
                    session.last_activity, tz=timezone.utc
                ).isoformat(),
                "cwd": session.virtual_fs.cwd,
            })
        return {"sessions": sessions, "count": len(sessions)}

    @app.get("/api/v1/sessions/{session_id}")
    async def get_session_detail(session_id: str):
        """Get detailed info for a specific session."""
        from aegistrap.core.session_manager import session_manager
        from aegistrap.advanced.attacker_profiler import attacker_profiler
        from aegistrap.advanced.mitre_attack import mitre_classifier

        session = await session_manager.get_session_by_id(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        profile = attacker_profiler.get_profile(session_id)
        mitre_chain = mitre_classifier.get_session_summary(session_id)

        return {
            "session": {
                "session_id": session.session_id,
                "attacker_ip": session.attacker_ip,
                "service": session.service,
                "username": session.username,
                "request_count": session.request_count,
                "chat_history_length": len(session.chat_history),
                "virtual_fs": {
                    "cwd": session.virtual_fs.cwd,
                    "files": list(session.virtual_fs.files.keys()),
                    "directories": session.virtual_fs.directories,
                },
            },
            "profile": profile.to_dict() if profile else None,
            "mitre_attack": mitre_chain,
        }

    @app.get("/api/v1/threats")
    async def get_threats():
        """Get recent threat intelligence matches."""
        from aegistrap.core.security import security_gateway

        threats = security_gateway.payload_capture.threat_intel
        return {
            "threats": [
                {
                    "timestamp": t.timestamp,
                    "attacker_ip": t.attacker_ip,
                    "session_id": t.session_id,
                    "threat_type": t.threat_type,
                    "indicator": t.indicator,
                    "severity": t.severity,
                }
                for t in threats[-100:]  # Last 100
            ],
            "total_count": len(threats),
        }

    @app.get("/api/v1/stats/mitre")
    async def get_mitre_stats():
        """MITRE ATT&CK classification statistics."""
        from aegistrap.advanced.mitre_attack import mitre_classifier
        return mitre_classifier.get_global_stats()

    @app.get("/api/v1/stats/geo")
    async def get_geo_stats():
        """Geographic attack distribution."""
        from aegistrap.advanced.geoip_enrichment import geoip_enrichment

        # Aggregate country stats from cache
        country_counts: Dict[str, int] = {}
        for ip, result in geoip_enrichment._cache.items():
            country = result.country_code
            country_counts[country] = country_counts.get(country, 0) + 1

        return {
            "countries": country_counts,
            "total_unique_ips": len(geoip_enrichment._cache),
            "cache_stats": geoip_enrichment.get_cache_stats(),
        }

    @app.get("/api/v1/stats/profiles")
    async def get_profile_stats():
        """Attacker profiling statistics."""
        from aegistrap.advanced.attacker_profiler import attacker_profiler
        return attacker_profiler.get_global_stats()

    @app.get("/api/v1/stats/fingerprints")
    async def get_fingerprint_stats():
        """Network fingerprinting statistics."""
        from aegistrap.advanced.fingerprinting import fingerprint_engine
        return fingerprint_engine.get_stats()

    @app.get("/api/v1/stats/feeds")
    async def get_feed_stats():
        """Threat intelligence feed statistics."""
        from aegistrap.advanced.threat_feeds import threat_feed_manager
        return threat_feed_manager.get_stats()

    @app.get("/api/v1/honeytokens")
    async def get_honeytokens():
        """Honeytoken deployment and trigger status."""
        from aegistrap.advanced.honeytokens import honeytoken_manager

        triggered = honeytoken_manager.get_triggered_tokens()
        return {
            "stats": honeytoken_manager.get_stats(),
            "triggered_tokens": [t.to_dict() for t in triggered],
        }

    @app.get("/metrics")
    async def prometheus_metrics():
        """Prometheus-compatible metrics endpoint for Grafana."""
        return PlainTextResponse(
            content=metrics.export(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    # =========================================================================
    # WebSocket Endpoint
    # =========================================================================

    @app.websocket("/ws/live")
    async def websocket_live(websocket: WebSocket):
        """Real-time event stream via WebSocket."""
        connected = await ws_manager.connect(websocket)
        if not connected:
            return

        try:
            while True:
                # Keep connection alive; handle client messages
                data = await websocket.receive_text()
                # Clients can send filter preferences
                try:
                    msg = json.loads(data)
                    if msg.get("type") == "ping":
                        await websocket.send_text(
                            json.dumps({"type": "pong", "timestamp": time.time()})
                        )
                except json.JSONDecodeError:
                    pass
        except WebSocketDisconnect:
            await ws_manager.disconnect(websocket)
        except Exception:
            await ws_manager.disconnect(websocket)

    return app


# =============================================================================
# Event Publishing Helpers
# =============================================================================

async def publish_attack_event(
    session_id: str,
    attacker_ip: str,
    service: str,
    command: str,
    response: str,
) -> None:
    """Publish an attack command event to the dashboard."""
    event = DashboardEvent(
        event_type="attack",
        data={
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "service": service,
            "command": command,
            "response": response[:200],
        },
    )
    await ws_manager.broadcast(event)
    metrics.increment("aegistrap_commands_total")


async def publish_auth_event(
    attacker_ip: str,
    service: str,
    username: str,
    password: str,
    success: bool,
) -> None:
    """Publish an authentication event to the dashboard."""
    event = DashboardEvent(
        event_type="auth",
        data={
            "attacker_ip": attacker_ip,
            "service": service,
            "username": username,
            "password": password,
            "success": success,
        },
    )
    await ws_manager.broadcast(event)
    metrics.increment("aegistrap_auth_attempts_total")
    if success:
        metrics.increment("aegistrap_auth_success_total")


async def publish_threat_event(
    attacker_ip: str,
    threat_type: str,
    indicator: str,
    severity: str,
) -> None:
    """Publish a threat detection event to the dashboard."""
    event = DashboardEvent(
        event_type="threat",
        data={
            "attacker_ip": attacker_ip,
            "threat_type": threat_type,
            "indicator": indicator,
            "severity": severity,
        },
    )
    await ws_manager.broadcast(event)
    metrics.increment("aegistrap_threats_detected_total")


async def publish_session_event(
    event_type: str,  # "session_start" or "session_end"
    session_id: str,
    attacker_ip: str,
    service: str,
) -> None:
    """Publish session lifecycle events to the dashboard."""
    event = DashboardEvent(
        event_type=event_type,
        data={
            "session_id": session_id,
            "attacker_ip": attacker_ip,
            "service": service,
        },
    )
    await ws_manager.broadcast(event)
    if event_type == "session_start":
        metrics.increment("aegistrap_connections_total")
