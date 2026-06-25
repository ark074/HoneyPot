"""
AegisTrap Unified Command Processing Pipeline
================================================
The central integration layer that wires ALL advanced modules into a
single async processing flow. Every attacker command flows through
this pipeline before reaching the LLM and after receiving a response.

Processing Order:
1. Rate Limiting (SecurityGateway)
2. Session Throttle Check
3. GeoIP Enrichment (first command only)
4. Threat Feed IP Check (first command only)
5. Attacker Profiler - record command
6. MITRE ATT&CK Classification
7. YARA Scanning (on command text)
8. Security Gateway - payload analysis (wget/curl interception)
9. Honeytoken usage detection
10. AI Response Generation (Ollama via AIContextBridge)
11. Adaptive Persona integration
12. Session Replay recording
13. Dashboard event publishing
14. Alerting (on high-severity events)
15. Structured JSON logging

This module is the ONLY thing services should call for command processing.
"""

import asyncio
import logging
from typing import Optional, List, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field

from aegistrap.core.session_manager import (
    session_manager, ai_bridge, AttackerSession,
)
from aegistrap.core.security import security_gateway

logger = logging.getLogger("aegistrap.pipeline")


@dataclass
class PipelineResult:
    """Result of processing a single command through the pipeline."""
    response: str = ""
    blocked: bool = False
    block_reason: str = ""
    session_expired: bool = False
    mitre_techniques: List[str] = field(default_factory=list)
    threats_detected: List[Dict[str, Any]] = field(default_factory=list)
    yara_matches: List[str] = field(default_factory=list)
    honeytoken_triggered: bool = False
    from_cache: bool = False


class CommandPipeline:
    """
    Unified command processing pipeline.
    All honeypot services route commands through this single entry point.
    Advanced modules degrade gracefully if not initialized.
    """

    def __init__(self):
        self._initialized = False
        # Optional module references (set during init)
        self._profiler = None
        self._mitre = None
        self._geoip = None
        self._threat_feeds = None
        self._honeytokens = None
        self._fingerprint = None
        self._yara = None
        self._personas = None
        self._recorder = None
        self._alerting = None
        self._dashboard = None

    async def initialize(self) -> None:
        """
        Load references to all advanced modules.
        Uses try/except for each to ensure graceful degradation.
        """
        try:
            from aegistrap.advanced.attacker_profiler import attacker_profiler
            self._profiler = attacker_profiler
        except Exception:
            pass

        try:
            from aegistrap.advanced.mitre_attack import mitre_classifier
            self._mitre = mitre_classifier
        except Exception:
            pass

        try:
            from aegistrap.advanced.geoip_enrichment import geoip_enrichment
            self._geoip = geoip_enrichment
        except Exception:
            pass

        try:
            from aegistrap.advanced.threat_feeds import threat_feed_manager
            self._threat_feeds = threat_feed_manager
        except Exception:
            pass

        try:
            from aegistrap.advanced.honeytokens import honeytoken_manager
            self._honeytokens = honeytoken_manager
        except Exception:
            pass

        try:
            from aegistrap.advanced.fingerprinting import fingerprint_engine
            self._fingerprint = fingerprint_engine
        except Exception:
            pass

        try:
            from aegistrap.advanced.yara_scanner import yara_scanner
            self._yara = yara_scanner
        except Exception:
            pass

        try:
            from aegistrap.advanced.adaptive_personas import persona_engine
            self._personas = persona_engine
        except Exception:
            pass

        try:
            from aegistrap.advanced.session_replay import session_recorder
            self._recorder = session_recorder
        except Exception:
            pass

        try:
            from aegistrap.advanced.alerting import alert_engine
            self._alerting = alert_engine
        except Exception:
            pass

        try:
            from aegistrap.dashboard import api as dashboard_api
            self._dashboard = dashboard_api
        except Exception:
            pass

        self._initialized = True
        logger.info("[Pipeline] Unified command pipeline initialized")

    # =========================================================================
    # Session Lifecycle
    # =========================================================================

    async def on_session_start(
        self,
        session: AttackerSession,
        ssh_client_version: str = "",
        http_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Called when a new attacker session begins.
        Performs initial enrichment: GeoIP, fingerprinting, threat feed check,
        honeytoken breadcrumb generation, and session recording start.
        """
        ip = session.attacker_ip
        sid = session.session_id

        # 1. GeoIP Enrichment
        if self._geoip:
            try:
                geo = await self._geoip.lookup(ip)
                logger.info(
                    f"[Pipeline] GeoIP: {ip} -> {geo.country_code}/{geo.city} "
                    f"ASN:{geo.asn} Risk:{geo.risk_score}"
                )
            except Exception as e:
                logger.debug(f"[Pipeline] GeoIP failed for {ip}: {e}")

        # 2. Threat Feed IP check
        if self._threat_feeds:
            try:
                ioc = self._threat_feeds.check_ip(ip)
                if ioc:
                    logger.warning(
                        f"[Pipeline] KNOWN THREAT: {ip} matches feed "
                        f"'{ioc.source_feed}' ({ioc.threat_type}: {ioc.malware_family})"
                    )
                    if self._alerting:
                        await self._alerting.alert_threat_detected(
                            ip, sid, "known_threat_ip",
                            f"IP in {ioc.source_feed}: {ioc.malware_family}",
                            severity="high",
                        )
                # Also check Tor exit node
                if self._threat_feeds.is_tor_exit(ip):
                    logger.info(f"[Pipeline] Tor exit node detected: {ip}")
            except Exception as e:
                logger.debug(f"[Pipeline] Threat feed check failed: {e}")

        # 3. Fingerprinting (SSH or HTTP)
        if self._fingerprint:
            try:
                if ssh_client_version:
                    ssh_fp = self._fingerprint.fingerprint_ssh(ssh_client_version)
                    self._fingerprint.register_fingerprint(
                        sid, ip, ssh_fp=ssh_fp
                    )
                if http_headers:
                    ua = http_headers.get("User-Agent", "")
                    http_fp = self._fingerprint.fingerprint_http(ua, http_headers)
                    self._fingerprint.register_fingerprint(
                        sid, ip, http_fp=http_fp
                    )
            except Exception as e:
                logger.debug(f"[Pipeline] Fingerprinting error: {e}")

        # 4. Profiler - start session
        if self._profiler:
            try:
                self._profiler.start_session(sid, ip)
            except Exception:
                pass

        # 5. Honeytoken breadcrumbs - generate for this session's virtual FS
        if self._honeytokens:
            try:
                breadcrumbs = self._honeytokens.generate_session_breadcrumbs(sid)
                # Inject breadcrumb file paths into the session's virtual filesystem
                for path, bc in breadcrumbs.items():
                    session.virtual_fs.files[bc.file_path] = bc.content
            except Exception as e:
                logger.debug(f"[Pipeline] Honeytoken generation error: {e}")

        # 6. Adaptive Persona assignment
        if self._personas:
            try:
                self._personas.assign_persona(sid, session.service)
            except Exception:
                pass

        # 7. Session Replay - start recording
        if self._recorder:
            try:
                self._recorder.start_recording(
                    sid, ip, session.attacker_port,
                    session.service, session.username,
                )
            except Exception:
                pass

        # 8. Register session throttle
        security_gateway.session_throttler.register_session(sid)

        # 9. Dashboard event
        if self._dashboard:
            try:
                await self._dashboard.publish_session_event(
                    "session_start", sid, ip, session.service
                )
            except Exception:
                pass

        logger.info(
            f"[Pipeline] Session started: {sid[:8]} | {ip} | {session.service}"
        )

    async def on_session_end(self, session: AttackerSession) -> None:
        """
        Called when an attacker session ends.
        Finalizes profiling, recordings, and publishes session summary.
        """
        sid = session.session_id
        ip = session.attacker_ip

        # Finalize profiler
        profile_summary = None
        if self._profiler:
            try:
                profile = self._profiler.end_session(sid)
                if profile:
                    profile_summary = profile.to_dict()
                    # Alert on APT-level attackers
                    if profile.skill_level.value == "apt_level" and self._alerting:
                        await self._alerting.alert_apt_detected(
                            ip, sid, profile.skill_level.value,
                            profile.primary_intent.value,
                        )
            except Exception:
                pass

        # GeoIP data for recording
        geo_data = None
        if self._geoip:
            try:
                geo = await self._geoip.lookup(ip)
                geo_data = geo.to_dict()
            except Exception:
                pass

        # End session replay recording
        if self._recorder:
            try:
                await self._recorder.end_recording(
                    sid,
                    profiler_summary=profile_summary,
                    geo_data=geo_data,
                )
            except Exception:
                pass

        # Clear MITRE chain
        if self._mitre:
            try:
                self._mitre.clear_session(sid)
            except Exception:
                pass

        # Clear persona
        if self._personas:
            try:
                self._personas.end_session(sid)
            except Exception:
                pass

        # Remove throttle tracking
        security_gateway.session_throttler.remove_session(sid)

        # Dashboard event
        if self._dashboard:
            try:
                await self._dashboard.publish_session_event(
                    "session_end", sid, ip, session.service
                )
            except Exception:
                pass

        logger.info(
            f"[Pipeline] Session ended: {sid[:8]} | {ip} | "
            f"commands={session.request_count}"
        )

    # =========================================================================
    # Command Processing (the main pipeline)
    # =========================================================================

    async def process_command(
        self,
        session: AttackerSession,
        command: str,
        log_callback: Optional[Callable[..., Awaitable]] = None,
    ) -> PipelineResult:
        """
        Process a single attacker command through the full pipeline.

        This is THE main entry point that all services (SSH, Telnet, FTP)
        call for every command received from an attacker.

        Args:
            session: The attacker's current session.
            command: The raw command string from the attacker.
            log_callback: Optional logging callback function.

        Returns:
            PipelineResult with the response and analysis metadata.
        """
        result = PipelineResult()
        sid = session.session_id
        ip = session.attacker_ip

        # =====================================================================
        # Step 1: Session expiration check
        # =====================================================================
        if session.is_expired():
            result.session_expired = True
            result.blocked = True
            result.block_reason = "session_expired"
            return result

        # =====================================================================
        # Step 2: Security Gateway (rate limit + payload capture + throttle)
        # =====================================================================
        try:
            allowed, override_response, threats = await security_gateway.process_command(
                command, ip, sid
            )
            if not allowed:
                result.blocked = True
                result.block_reason = "rate_limited"
                result.response = override_response or ""
                return result

            if threats:
                result.threats_detected = [
                    {"type": t.threat_type, "indicator": t.indicator, "severity": t.severity}
                    for t in threats
                ]
                # Alert on critical threats
                if self._alerting:
                    for t in threats:
                        if t.severity == "critical":
                            await self._alerting.alert_threat_detected(
                                ip, sid, t.threat_type, t.indicator, t.severity
                            )

            # If security gateway provided a simulated response (wget/curl), use it
            if override_response:
                result.response = override_response
                # Still do analysis below but skip LLM call
        except Exception as e:
            logger.error(f"[Pipeline] Security gateway error: {e}")

        # =====================================================================
        # Step 3: Attacker Profiler - record command timing
        # =====================================================================
        if self._profiler:
            try:
                self._profiler.record_command(sid, command)
            except Exception:
                pass

        # =====================================================================
        # Step 4: MITRE ATT&CK Classification
        # =====================================================================
        if self._mitre:
            try:
                techniques = self._mitre.classify_command(command, sid)
                result.mitre_techniques = [t.technique_id for t in techniques]
            except Exception:
                pass

        # =====================================================================
        # Step 5: YARA Scanning on command text
        # =====================================================================
        if self._yara:
            try:
                yara_matches = await self._yara.scan_text(command, f"cmd:{sid[:8]}")
                if yara_matches:
                    result.yara_matches = [m.rule_name for m in yara_matches]
                    logger.warning(
                        f"[Pipeline] YARA match on command from {ip}: "
                        f"{[m.rule_name for m in yara_matches]}"
                    )
                    if self._alerting:
                        for m in yara_matches:
                            await self._alerting.alert_yara_match(
                                ip, sid, m.rule_name, m.malware_family, m.severity
                            )
            except Exception:
                pass

        # =====================================================================
        # Step 6: Threat Feed URL/domain check (extract from command)
        # =====================================================================
        if self._threat_feeds:
            try:
                import re
                urls = re.findall(r'https?://[^\s\'"<>|;`$(){}]+', command)
                if urls:
                    matches = self._threat_feeds.check_all(urls=urls)
                    if matches:
                        for m in matches:
                            result.threats_detected.append(
                                {"type": "known_malicious_url", "indicator": m.indicator,
                                 "severity": "critical"}
                            )
                        if self._alerting:
                            for m in matches:
                                await self._alerting.alert_threat_detected(
                                    ip, sid, "known_malicious_url",
                                    m.indicator, "critical"
                                )
            except Exception:
                pass

        # =====================================================================
        # Step 7: Honeytoken usage detection
        # =====================================================================
        if self._honeytokens:
            try:
                triggered = await self._honeytokens.check_usage(command, ip)
                if triggered:
                    result.honeytoken_triggered = True
                    logger.warning(
                        f"[Pipeline] HONEYTOKEN triggered by {ip}: "
                        f"{[t.token_type.value for t in triggered]}"
                    )
                    if self._alerting:
                        for t in triggered:
                            await self._alerting.alert_honeytoken_triggered(
                                ip, t.token_type.value, t.context
                            )
            except Exception:
                pass

        # =====================================================================
        # Step 8: Generate AI Response (if not already provided by security gateway)
        # =====================================================================
        if not result.response:
            try:
                # Check cache first
                cache_key = session.get_cache_key(command)
                if cache_key in session.response_cache:
                    result.response = session.response_cache[cache_key]
                    result.from_cache = True
                else:
                    result.response = await ai_bridge.generate_response(session, command)
            except Exception as e:
                logger.error(f"[Pipeline] AI bridge error: {e}")
                result.response = f"bash: {command}: command not found"

        # =====================================================================
        # Step 9: Adaptive Persona check (adapt after every 5 commands)
        # =====================================================================
        if self._personas and session.request_count > 0 and session.request_count % 5 == 0:
            try:
                # Get recent commands from profiler
                recent = []
                if self._profiler and sid in self._profiler._command_sequences:
                    recent = self._profiler._command_sequences[sid][-10:]
                if recent:
                    self._personas.adapt_persona(sid, recent)
                # Track engagement
                self._personas.track_engagement(sid, command)
            except Exception:
                pass

        # =====================================================================
        # Step 10: Session Replay - record input and output
        # =====================================================================
        if self._recorder:
            try:
                self._recorder.record_input(
                    sid, command, mitre_techniques=result.mitre_techniques
                )
                self._recorder.record_output(sid, result.response)
            except Exception:
                pass

        # =====================================================================
        # Step 11: Dashboard event publishing
        # =====================================================================
        if self._dashboard:
            try:
                await self._dashboard.publish_attack_event(
                    sid, ip, session.service, command, result.response
                )
            except Exception:
                pass

        # =====================================================================
        # Step 12: Structured logging
        # =====================================================================
        if log_callback:
            try:
                await log_callback(
                    session=session,
                    input_received=command,
                    ai_response=result.response,
                )
            except Exception:
                pass

        # Update session activity counter
        session.update_activity()

        return result

    # =========================================================================
    # Specialized Processing Methods
    # =========================================================================

    async def process_auth_attempt(
        self,
        session: AttackerSession,
        username: str,
        password: str,
        success: bool,
        log_callback: Optional[Callable[..., Awaitable]] = None,
    ) -> None:
        """
        Process an authentication attempt through the pipeline.
        Used by SSH, Telnet, and FTP for credential capture & analysis.
        """
        ip = session.attacker_ip
        sid = session.session_id

        # Dashboard auth event
        if self._dashboard:
            try:
                await self._dashboard.publish_auth_event(
                    ip, session.service, username, password, success
                )
            except Exception:
                pass

        # Session replay
        if self._recorder:
            try:
                self._recorder.record_auth(sid, username, password, success)
            except Exception:
                pass

        # Threat feed check on credentials (some botnets use specific passwords)
        if self._threat_feeds and not success:
            try:
                # Botnet passwords often contain specific patterns
                botnet_passwords = [
                    "mirai", "admin", "vizxv", "default", "root",
                    "1234", "juantech", "pass", "xc3511", "GM8182",
                ]
                if password.lower() in botnet_passwords:
                    logger.info(
                        f"[Pipeline] Known botnet credential pattern: "
                        f"{username}:{password} from {ip}"
                    )
            except Exception:
                pass

        # Log via callback
        if log_callback:
            try:
                await log_callback(
                    session=session,
                    input_received=f"AUTH: {username}:{password}",
                    ai_response=f"{'accepted' if success else 'rejected'}",
                )
            except Exception:
                pass

    async def process_file_upload(
        self,
        session: AttackerSession,
        filename: str,
        data: bytes,
        log_callback: Optional[Callable[..., Awaitable]] = None,
    ) -> List[str]:
        """
        Process a file upload (FTP STOR, HTTP POST) through YARA scanning
        and threat analysis.

        Returns:
            List of YARA rule names that matched.
        """
        sid = session.session_id
        ip = session.attacker_ip
        matched_rules = []

        # YARA scan the uploaded content
        if self._yara:
            try:
                matches = await self._yara.scan_data(data, filename)
                if matches:
                    matched_rules = [m.rule_name for m in matches]
                    logger.warning(
                        f"[Pipeline] YARA match on upload '{filename}' from {ip}: "
                        f"{matched_rules}"
                    )
                    if self._alerting:
                        for m in matches:
                            await self._alerting.alert_yara_match(
                                ip, sid, m.rule_name, m.malware_family, m.severity
                            )
            except Exception as e:
                logger.debug(f"[Pipeline] YARA scan error on upload: {e}")

        # Session replay - record file access
        if self._recorder:
            try:
                self._recorder.record_file_access(sid, "upload", filename)
            except Exception:
                pass

        # Threat feed - check if filename matches known malware hashes
        if self._threat_feeds and len(data) > 0:
            try:
                import hashlib
                file_md5 = hashlib.md5(data).hexdigest()
                file_sha256 = hashlib.sha256(data).hexdigest()
                match = self._threat_feeds.check_hash(file_md5)
                if not match:
                    match = self._threat_feeds.check_hash(file_sha256)
                if match:
                    logger.warning(
                        f"[Pipeline] Uploaded file matches known malware hash: "
                        f"{match.malware_family} ({match.source_feed})"
                    )
                    if self._alerting:
                        await self._alerting.alert_threat_detected(
                            ip, sid, "known_malware_hash",
                            f"{filename} ({file_sha256[:16]}...)", "critical"
                        )
            except Exception:
                pass

        # Log
        if log_callback:
            try:
                await log_callback(
                    session=session,
                    input_received=f"FILE_UPLOAD: {filename} ({len(data)} bytes)",
                    ai_response=f"YARA: {matched_rules}" if matched_rules else "(clean)",
                )
            except Exception:
                pass

        return matched_rules

    async def enrich_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Full IP enrichment: GeoIP + threat feeds + Shodan InternetDB.
        Used by dashboard API and on-demand lookups.
        """
        enrichment = {}

        if self._geoip:
            try:
                geo = await self._geoip.lookup(ip)
                enrichment["geo"] = geo.to_dict()
            except Exception:
                pass

        if self._threat_feeds:
            try:
                ioc = self._threat_feeds.check_ip(ip)
                if ioc:
                    enrichment["threat_feed"] = ioc.to_dict()
                enrichment["is_tor"] = self._threat_feeds.is_tor_exit(ip)

                # Shodan InternetDB (free, no API key)
                shodan_data = await self._threat_feeds.enrich_ip(ip)
                if shodan_data:
                    enrichment["shodan"] = shodan_data.to_dict()
            except Exception:
                pass

        return enrichment if enrichment else None


# =============================================================================
# Module-level singleton
# =============================================================================
command_pipeline = CommandPipeline()
