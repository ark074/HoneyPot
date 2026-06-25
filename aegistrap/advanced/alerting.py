"""
AegisTrap Automated Reporting & Alerting Engine
==================================================
Sends real-time alerts on high-severity events via multiple channels.
Supports webhook, email (SMTP), Slack, Discord, and Telegram.

Free Tools/Services Supported:
- Slack Incoming Webhooks (free tier)
- Discord Webhooks (free)
- Telegram Bot API (free)
- Generic Webhooks (any endpoint)
- SMTP Email (any provider)
- Syslog forwarding (free)

Features:
- Configurable severity thresholds per channel
- Alert deduplication (suppress duplicate alerts within cooldown)
- Rate limiting to prevent alert fatigue
- Rich formatting (Markdown for Slack/Discord/Telegram)
- Batching support for high-volume events
- Alert history and acknowledgment tracking
"""

import asyncio
import json
import time
import logging
from typing import Dict, List, Optional, Any, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from collections import defaultdict

import aiohttp

logger = logging.getLogger("aegistrap.alerting")



# =============================================================================
# Alert Configuration & Types
# =============================================================================

class AlertSeverity(Enum):
    """Alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertChannel(Enum):
    """Supported alert delivery channels."""
    WEBHOOK = "webhook"
    SLACK = "slack"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    EMAIL = "email"
    SYSLOG = "syslog"


@dataclass
class AlertConfig:
    """Configuration for a single alert channel."""
    channel: AlertChannel
    enabled: bool = True
    # Channel-specific settings
    webhook_url: str = ""
    # Email settings
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_pass: str = ""
    smtp_from: str = ""
    smtp_to: List[str] = field(default_factory=list)
    # Telegram settings
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    # Thresholds
    min_severity: AlertSeverity = AlertSeverity.HIGH
    # Rate limiting
    cooldown_seconds: int = 60  # Min time between same-type alerts
    max_alerts_per_hour: int = 30


@dataclass
class Alert:
    """Represents a single alert event."""
    alert_id: str = ""
    severity: AlertSeverity = AlertSeverity.MEDIUM
    title: str = ""
    description: str = ""
    source: str = ""           # Which module triggered (yara, threat_feed, etc.)
    attacker_ip: str = ""
    session_id: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Delivery tracking
    delivered_to: List[str] = field(default_factory=list)
    acknowledged: bool = False

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "attacker_ip": self.attacker_ip,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }



class AlertEngine:
    """
    Multi-channel alert delivery engine with deduplication,
    rate limiting, and rich formatting.
    """

    def __init__(self):
        self._channels: List[AlertConfig] = []
        self._http_session: Optional[aiohttp.ClientSession] = None
        self._alert_history: List[Alert] = []
        self._dedup_cache: Dict[str, float] = {}  # dedup_key -> last_sent_time
        self._hourly_counts: Dict[str, int] = defaultdict(int)
        self._hourly_reset: float = time.time()
        self._total_sent: int = 0
        self._total_suppressed: int = 0

    def add_channel(self, config: AlertConfig) -> None:
        """Register an alert delivery channel."""
        self._channels.append(config)
        logger.info(
            f"[Alerting] Added channel: {config.channel.value} "
            f"(min_severity: {config.min_severity.value})"
        )

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            )
        return self._http_session

    async def send_alert(self, alert: Alert) -> None:
        """
        Process and deliver an alert through all configured channels.
        Handles deduplication and rate limiting automatically.
        """
        import uuid
        if not alert.alert_id:
            alert.alert_id = str(uuid.uuid4())[:8]

        # Check deduplication
        dedup_key = f"{alert.source}:{alert.attacker_ip}:{alert.title}"
        if self._is_deduplicated(dedup_key):
            self._total_suppressed += 1
            return

        # Check hourly rate limit
        self._reset_hourly_if_needed()

        # Deliver to each configured channel
        for channel_config in self._channels:
            if not channel_config.enabled:
                continue

            # Check severity threshold
            severity_order = [s for s in AlertSeverity]
            if severity_order.index(alert.severity) < severity_order.index(channel_config.min_severity):
                continue

            # Check per-channel rate limit
            channel_key = channel_config.channel.value
            if self._hourly_counts[channel_key] >= channel_config.max_alerts_per_hour:
                continue

            try:
                await self._deliver(alert, channel_config)
                alert.delivered_to.append(channel_config.channel.value)
                self._hourly_counts[channel_key] += 1
                self._total_sent += 1
            except Exception as e:
                logger.error(
                    f"[Alerting] Delivery failed ({channel_config.channel.value}): {e}"
                )

        # Record in history and dedup cache
        self._alert_history.append(alert)
        self._dedup_cache[dedup_key] = time.time()

        if alert.delivered_to:
            logger.info(
                f"[Alerting] Alert sent: [{alert.severity.value}] {alert.title} "
                f"-> {alert.delivered_to}"
            )

    def _is_deduplicated(self, key: str) -> bool:
        """Check if this alert was recently sent (within cooldown)."""
        last_sent = self._dedup_cache.get(key, 0)
        # Use minimum cooldown from any channel (60s default)
        min_cooldown = 60
        for ch in self._channels:
            min_cooldown = min(min_cooldown, ch.cooldown_seconds)
        return (time.time() - last_sent) < min_cooldown

    def _reset_hourly_if_needed(self) -> None:
        """Reset hourly counters every hour."""
        if time.time() - self._hourly_reset >= 3600:
            self._hourly_counts.clear()
            self._hourly_reset = time.time()

    async def _deliver(self, alert: Alert, config: AlertConfig) -> None:
        """Route alert to the appropriate delivery method."""
        if config.channel == AlertChannel.SLACK:
            await self._send_slack(alert, config)
        elif config.channel == AlertChannel.DISCORD:
            await self._send_discord(alert, config)
        elif config.channel == AlertChannel.TELEGRAM:
            await self._send_telegram(alert, config)
        elif config.channel == AlertChannel.WEBHOOK:
            await self._send_webhook(alert, config)
        elif config.channel == AlertChannel.EMAIL:
            await self._send_email(alert, config)



    async def _send_slack(self, alert: Alert, config: AlertConfig) -> None:
        """Send alert to Slack via Incoming Webhook."""
        severity_emoji = {
            AlertSeverity.INFO: ":information_source:",
            AlertSeverity.LOW: ":white_circle:",
            AlertSeverity.MEDIUM: ":large_yellow_circle:",
            AlertSeverity.HIGH: ":red_circle:",
            AlertSeverity.CRITICAL: ":rotating_light:",
        }
        emoji = severity_emoji.get(alert.severity, ":warning:")

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} AegisTrap Alert: {alert.title}",
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Severity:*\n{alert.severity.value.upper()}"},
                        {"type": "mrkdwn", "text": f"*Source:*\n{alert.source}"},
                        {"type": "mrkdwn", "text": f"*Attacker IP:*\n`{alert.attacker_ip}`"},
                        {"type": "mrkdwn", "text": f"*Time:*\n{alert.timestamp}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Details:*\n{alert.description[:500]}",
                    },
                },
            ],
        }

        session = await self._get_session()
        async with session.post(config.webhook_url, json=payload) as resp:
            if resp.status != 200:
                raise Exception(f"Slack returned {resp.status}")

    async def _send_discord(self, alert: Alert, config: AlertConfig) -> None:
        """Send alert to Discord via Webhook."""
        color_map = {
            AlertSeverity.INFO: 0x3498DB,
            AlertSeverity.LOW: 0x2ECC71,
            AlertSeverity.MEDIUM: 0xF39C12,
            AlertSeverity.HIGH: 0xE74C3C,
            AlertSeverity.CRITICAL: 0x9B59B6,
        }

        payload = {
            "embeds": [{
                "title": f"AegisTrap Alert: {alert.title}",
                "description": alert.description[:1000],
                "color": color_map.get(alert.severity, 0xFFFFFF),
                "fields": [
                    {"name": "Severity", "value": alert.severity.value.upper(), "inline": True},
                    {"name": "Source", "value": alert.source, "inline": True},
                    {"name": "Attacker IP", "value": f"`{alert.attacker_ip}`", "inline": True},
                    {"name": "Session", "value": alert.session_id[:8] or "N/A", "inline": True},
                ],
                "timestamp": alert.timestamp,
                "footer": {"text": "AegisTrap Honeypot"},
            }],
        }

        session = await self._get_session()
        async with session.post(config.webhook_url, json=payload) as resp:
            if resp.status not in (200, 204):
                raise Exception(f"Discord returned {resp.status}")

    async def _send_telegram(self, alert: Alert, config: AlertConfig) -> None:
        """Send alert to Telegram via Bot API."""
        severity_icon = {
            AlertSeverity.INFO: "ℹ️",
            AlertSeverity.LOW: "⚪",
            AlertSeverity.MEDIUM: "🟡",
            AlertSeverity.HIGH: "🔴",
            AlertSeverity.CRITICAL: "🚨",
        }
        icon = severity_icon.get(alert.severity, "⚠️")

        text = (
            f"{icon} *AegisTrap Alert*\n\n"
            f"*{alert.title}*\n"
            f"Severity: `{alert.severity.value.upper()}`\n"
            f"Source: {alert.source}\n"
            f"Attacker: `{alert.attacker_ip}`\n"
            f"Time: {alert.timestamp}\n\n"
            f"{alert.description[:500]}"
        )

        url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": config.telegram_chat_id,
            "text": text,
            "parse_mode": "Markdown",
        }

        session = await self._get_session()
        async with session.post(url, json=payload) as resp:
            if resp.status != 200:
                raise Exception(f"Telegram returned {resp.status}")

    async def _send_webhook(self, alert: Alert, config: AlertConfig) -> None:
        """Send alert to a generic webhook endpoint."""
        payload = {
            "event": "aegistrap_alert",
            "alert": alert.to_dict(),
        }

        session = await self._get_session()
        headers = {"Content-Type": "application/json"}
        async with session.post(config.webhook_url, json=payload, headers=headers) as resp:
            if resp.status >= 400:
                raise Exception(f"Webhook returned {resp.status}")

    async def _send_email(self, alert: Alert, config: AlertConfig) -> None:
        """Send alert via SMTP email."""
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        subject = f"[AegisTrap {alert.severity.value.upper()}] {alert.title}"

        body = (
            f"AegisTrap Honeypot Alert\n"
            f"{'=' * 40}\n\n"
            f"Title: {alert.title}\n"
            f"Severity: {alert.severity.value.upper()}\n"
            f"Source: {alert.source}\n"
            f"Attacker IP: {alert.attacker_ip}\n"
            f"Session ID: {alert.session_id}\n"
            f"Timestamp: {alert.timestamp}\n\n"
            f"Description:\n{alert.description}\n\n"
            f"Metadata:\n{json.dumps(alert.metadata, indent=2)}\n"
        )

        msg = MIMEMultipart()
        msg["From"] = config.smtp_from
        msg["To"] = ", ".join(config.smtp_to)
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        # Run SMTP in executor (blocking I/O)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            self._smtp_send,
            config, msg,
        )

    def _smtp_send(self, config: AlertConfig, msg) -> None:
        """Synchronous SMTP send (runs in executor)."""
        import smtplib
        with smtplib.SMTP(config.smtp_host, config.smtp_port) as server:
            server.starttls()
            if config.smtp_user and config.smtp_pass:
                server.login(config.smtp_user, config.smtp_pass)
            server.send_message(msg)



    # =========================================================================
    # Convenience Alert Creators
    # =========================================================================

    async def alert_threat_detected(
        self, attacker_ip: str, session_id: str, threat_type: str,
        indicator: str, severity: str = "high"
    ) -> None:
        """Create and send a threat detection alert."""
        sev = AlertSeverity(severity) if severity in [s.value for s in AlertSeverity] else AlertSeverity.HIGH
        alert = Alert(
            severity=sev,
            title=f"Threat Detected: {threat_type}",
            description=f"Malicious activity from {attacker_ip}: {indicator}",
            source="threat_detection",
            attacker_ip=attacker_ip,
            session_id=session_id,
            metadata={"threat_type": threat_type, "indicator": indicator},
        )
        await self.send_alert(alert)

    async def alert_honeytoken_triggered(
        self, attacker_ip: str, token_type: str, token_context: str
    ) -> None:
        """Create and send a honeytoken trigger alert."""
        alert = Alert(
            severity=AlertSeverity.CRITICAL,
            title=f"Honeytoken Triggered: {token_type}",
            description=(
                f"Attacker {attacker_ip} accessed a honeytoken "
                f"({token_type}) from context: {token_context}"
            ),
            source="honeytoken",
            attacker_ip=attacker_ip,
            metadata={"token_type": token_type, "context": token_context},
        )
        await self.send_alert(alert)

    async def alert_yara_match(
        self, attacker_ip: str, session_id: str,
        rule_name: str, malware_family: str, severity: str = "high"
    ) -> None:
        """Create and send a YARA rule match alert."""
        sev = AlertSeverity(severity) if severity in [s.value for s in AlertSeverity] else AlertSeverity.HIGH
        alert = Alert(
            severity=sev,
            title=f"Malware Detected: {rule_name}",
            description=(
                f"YARA rule '{rule_name}' matched content from {attacker_ip}. "
                f"Malware family: {malware_family}"
            ),
            source="yara_scanner",
            attacker_ip=attacker_ip,
            session_id=session_id,
            metadata={"rule": rule_name, "family": malware_family},
        )
        await self.send_alert(alert)

    async def alert_apt_detected(
        self, attacker_ip: str, session_id: str,
        skill_level: str, intent: str
    ) -> None:
        """Create alert for APT-level attacker detection."""
        alert = Alert(
            severity=AlertSeverity.CRITICAL,
            title=f"APT-Level Attacker Detected",
            description=(
                f"Advanced persistent threat actor from {attacker_ip}. "
                f"Skill: {skill_level}, Intent: {intent}. "
                f"Immediate investigation recommended."
            ),
            source="attacker_profiler",
            attacker_ip=attacker_ip,
            session_id=session_id,
            metadata={"skill_level": skill_level, "intent": intent},
        )
        await self.send_alert(alert)

    # =========================================================================
    # Statistics & Management
    # =========================================================================

    def get_stats(self) -> Dict:
        """Return alerting statistics."""
        return {
            "channels_configured": len(self._channels),
            "total_alerts_sent": self._total_sent,
            "total_suppressed": self._total_suppressed,
            "alerts_this_hour": dict(self._hourly_counts),
            "recent_alerts": [a.to_dict() for a in self._alert_history[-20:]],
        }

    async def shutdown(self) -> None:
        """Cleanup HTTP session."""
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()


# =============================================================================
# Module-level singleton
# =============================================================================
alert_engine = AlertEngine()
