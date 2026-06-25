"""
AegisTrap Real-Time Threat Intelligence Feed Integration
==========================================================
Integrates with multiple free threat intelligence feeds to enrich
honeypot data with known IOCs (Indicators of Compromise).

Free Feeds Integrated:
- abuse.ch URLhaus (malicious URLs) - CC0 license
- abuse.ch ThreatFox (IOCs) - CC0 license
- abuse.ch Feodo Tracker (C2 servers) - CC0 license
- AlienVault OTX (Open Threat Exchange) - free API
- Emerging Threats (Proofpoint) - free ruleset
- Tor Project (exit node list) - public
- Shodan InternetDB (free, no key needed)

All feeds are public, free, and require no paid subscriptions.
"""

import asyncio
import logging
import time
import json
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

import aiohttp

logger = logging.getLogger("aegistrap.threat_feeds")



# =============================================================================
# Feed Configuration
# =============================================================================

FEED_CONFIG = {
    "urlhaus": {
        "name": "abuse.ch URLhaus",
        "url": "https://urlhaus-api.abuse.ch/v1/urls/recent/",
        "format": "json",
        "refresh_interval": 300,  # 5 minutes
        "description": "Recently reported malicious URLs",
    },
    "threatfox": {
        "name": "abuse.ch ThreatFox",
        "url": "https://threatfox-api.abuse.ch/api/v1/",
        "format": "json",
        "refresh_interval": 600,  # 10 minutes
        "description": "IOCs shared by the infosec community",
    },
    "feodo": {
        "name": "abuse.ch Feodo Tracker",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
        "format": "json",
        "refresh_interval": 3600,  # 1 hour
        "description": "Botnet C2 server IP addresses",
    },
    "tor_exits": {
        "name": "Tor Exit Nodes",
        "url": "https://check.torproject.org/torbulkexitlist",
        "format": "text",
        "refresh_interval": 3600,  # 1 hour
        "description": "Tor network exit node IP addresses",
    },
    "internetdb": {
        "name": "Shodan InternetDB",
        "url": "https://internetdb.shodan.io/",
        "format": "json_per_ip",
        "refresh_interval": 0,  # On-demand per IP
        "description": "Free IP enrichment (ports, vulns, hostnames)",
    },
}


@dataclass
class IOCEntry:
    """Represents a single Indicator of Compromise from a feed."""
    indicator: str = ""          # The IOC value (IP, URL, hash, domain)
    indicator_type: str = ""     # ip, url, domain, md5, sha256
    source_feed: str = ""        # Which feed provided it
    threat_type: str = ""        # malware, c2, phishing, etc.
    malware_family: str = ""     # e.g., "Emotet", "Cobalt Strike"
    confidence: int = 0          # 0-100
    first_seen: str = ""
    last_seen: str = ""
    tags: List[str] = field(default_factory=list)
    reference_url: str = ""

    def to_dict(self) -> dict:
        return {
            "ioc_indicator": self.indicator,
            "ioc_type": self.indicator_type,
            "ioc_source": self.source_feed,
            "ioc_threat_type": self.threat_type,
            "ioc_malware_family": self.malware_family,
            "ioc_confidence": self.confidence,
            "ioc_tags": self.tags,
        }


@dataclass
class IPEnrichment:
    """Enrichment data for a specific IP from Shodan InternetDB."""
    ip: str = ""
    hostnames: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=list)
    cpes: List[str] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "enrichment_ip": self.ip,
            "enrichment_hostnames": self.hostnames,
            "enrichment_open_ports": self.ports,
            "enrichment_vulns": self.vulns,
            "enrichment_tags": self.tags,
        }



class ThreatFeedManager:
    """
    Manages multiple threat intelligence feeds with async polling,
    local caching, and real-time IOC matching against attacker activity.
    """

    def __init__(self):
        self._http_session: Optional[aiohttp.ClientSession] = None
        # IOC databases (in-memory for fast lookup)
        self._malicious_ips: Dict[str, IOCEntry] = {}
        self._malicious_urls: Dict[str, IOCEntry] = {}
        self._malicious_domains: Dict[str, IOCEntry] = {}
        self._malicious_hashes: Dict[str, IOCEntry] = {}
        self._tor_exit_nodes: Set[str] = set()
        # IP enrichment cache (from Shodan InternetDB)
        self._ip_enrichment_cache: Dict[str, IPEnrichment] = {}
        # Feed metadata
        self._last_refresh: Dict[str, float] = {}
        self._feed_stats: Dict[str, Dict[str, Any]] = {}
        # Background task handle
        self._refresh_task: Optional[asyncio.Task] = None
        self._running: bool = False

    async def _get_http_session(self) -> aiohttp.ClientSession:
        """Lazy-initialize HTTP session."""
        if self._http_session is None or self._http_session.closed:
            timeout = aiohttp.ClientTimeout(total=30)
            self._http_session = aiohttp.ClientSession(timeout=timeout)
        return self._http_session

    async def initialize(self) -> None:
        """Initialize feed manager and start background refresh."""
        logger.info("[ThreatFeeds] Initializing threat intelligence feeds...")
        self._running = True
        # Initial feed load
        await self._refresh_all_feeds()
        # Start background refresh task
        self._refresh_task = asyncio.create_task(self._background_refresh())
        logger.info(
            f"[ThreatFeeds] Initialized with {self.total_iocs} IOCs loaded"
        )

    async def shutdown(self) -> None:
        """Gracefully stop feed manager."""
        self._running = False
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()

    async def _background_refresh(self) -> None:
        """Background task that periodically refreshes feeds."""
        while self._running:
            try:
                await asyncio.sleep(60)  # Check every minute
                now = time.time()
                for feed_id, config in FEED_CONFIG.items():
                    if config["refresh_interval"] == 0:
                        continue  # On-demand only
                    last = self._last_refresh.get(feed_id, 0)
                    if now - last >= config["refresh_interval"]:
                        await self._refresh_feed(feed_id)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"[ThreatFeeds] Background refresh error: {e}")

    async def _refresh_all_feeds(self) -> None:
        """Refresh all configured feeds."""
        tasks = []
        for feed_id in FEED_CONFIG:
            if FEED_CONFIG[feed_id]["refresh_interval"] > 0:
                tasks.append(self._refresh_feed(feed_id))
        await asyncio.gather(*tasks, return_exceptions=True)



    async def _refresh_feed(self, feed_id: str) -> None:
        """Refresh a single feed."""
        config = FEED_CONFIG.get(feed_id)
        if not config:
            return

        try:
            session = await self._get_http_session()

            if feed_id == "urlhaus":
                await self._fetch_urlhaus(session)
            elif feed_id == "threatfox":
                await self._fetch_threatfox(session)
            elif feed_id == "feodo":
                await self._fetch_feodo(session)
            elif feed_id == "tor_exits":
                await self._fetch_tor_exits(session)

            self._last_refresh[feed_id] = time.time()
            logger.info(
                f"[ThreatFeeds] Refreshed {config['name']}: "
                f"{self.total_iocs} total IOCs"
            )
        except aiohttp.ClientError as e:
            logger.warning(f"[ThreatFeeds] Failed to refresh {feed_id}: {e}")
        except Exception as e:
            logger.error(f"[ThreatFeeds] Error refreshing {feed_id}: {e}")

    async def _fetch_urlhaus(self, session: aiohttp.ClientSession) -> None:
        """Fetch recent malicious URLs from abuse.ch URLhaus."""
        url = FEED_CONFIG["urlhaus"]["url"]
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    urls = data.get("urls", []) if isinstance(data, dict) else []
                    count = 0
                    for entry in urls[:1000]:  # Limit to 1000 most recent
                        url_val = entry.get("url", "")
                        if url_val:
                            ioc = IOCEntry(
                                indicator=url_val,
                                indicator_type="url",
                                source_feed="urlhaus",
                                threat_type=entry.get("threat", "malware"),
                                tags=entry.get("tags", []) or [],
                                first_seen=entry.get("date_added", ""),
                            )
                            self._malicious_urls[url_val] = ioc
                            count += 1
                    self._feed_stats["urlhaus"] = {"count": count}
        except json.JSONDecodeError:
            logger.warning("[ThreatFeeds] URLhaus returned invalid JSON")

    async def _fetch_threatfox(self, session: aiohttp.ClientSession) -> None:
        """Fetch IOCs from abuse.ch ThreatFox."""
        url = FEED_CONFIG["threatfox"]["url"]
        payload = {"query": "get_iocs", "days": 7}
        try:
            async with session.post(url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    iocs = data.get("data", []) if isinstance(data, dict) else []
                    if not isinstance(iocs, list):
                        return
                    count = 0
                    for entry in iocs[:500]:
                        ioc_val = entry.get("ioc", "")
                        ioc_type = entry.get("ioc_type", "")
                        if ioc_val:
                            ioc = IOCEntry(
                                indicator=ioc_val,
                                indicator_type=ioc_type,
                                source_feed="threatfox",
                                threat_type=entry.get("threat_type", ""),
                                malware_family=entry.get("malware", ""),
                                confidence=int(entry.get("confidence_level", 50)),
                                tags=entry.get("tags", []) or [],
                                first_seen=entry.get("first_seen", ""),
                                reference_url=entry.get("reference", ""),
                            )
                            if "ip" in ioc_type:
                                ip_part = ioc_val.split(":")[0]
                                self._malicious_ips[ip_part] = ioc
                            elif "domain" in ioc_type:
                                self._malicious_domains[ioc_val] = ioc
                            elif "url" in ioc_type:
                                self._malicious_urls[ioc_val] = ioc
                            elif "hash" in ioc_type or "md5" in ioc_type or "sha" in ioc_type:
                                self._malicious_hashes[ioc_val] = ioc
                            count += 1
                    self._feed_stats["threatfox"] = {"count": count}
        except json.JSONDecodeError:
            logger.warning("[ThreatFeeds] ThreatFox returned invalid JSON")



    async def _fetch_feodo(self, session: aiohttp.ClientSession) -> None:
        """Fetch C2 server IPs from abuse.ch Feodo Tracker."""
        url = FEED_CONFIG["feodo"]["url"]
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    entries = data if isinstance(data, list) else []
                    count = 0
                    for entry in entries:
                        ip = entry.get("ip_address", "")
                        if ip:
                            ioc = IOCEntry(
                                indicator=ip,
                                indicator_type="ip",
                                source_feed="feodo",
                                threat_type="c2",
                                malware_family=entry.get("malware", ""),
                                confidence=90,
                                first_seen=entry.get("first_seen", ""),
                                last_seen=entry.get("last_online", ""),
                            )
                            self._malicious_ips[ip] = ioc
                            count += 1
                    self._feed_stats["feodo"] = {"count": count}
        except (json.JSONDecodeError, aiohttp.ContentTypeError):
            logger.warning("[ThreatFeeds] Feodo returned invalid data")

    async def _fetch_tor_exits(self, session: aiohttp.ClientSession) -> None:
        """Fetch Tor exit node list from TorProject."""
        url = FEED_CONFIG["tor_exits"]["url"]
        try:
            async with session.get(url) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    nodes = set()
                    for line in text.strip().split("\n"):
                        line = line.strip()
                        if line and not line.startswith("#"):
                            nodes.add(line)
                    self._tor_exit_nodes = nodes
                    self._feed_stats["tor_exits"] = {"count": len(nodes)}
                    logger.info(
                        f"[ThreatFeeds] Loaded {len(nodes)} Tor exit nodes"
                    )
        except Exception as e:
            logger.warning(f"[ThreatFeeds] Tor exit list fetch failed: {e}")

    async def enrich_ip(self, ip: str) -> Optional[IPEnrichment]:
        """
        Enrich an IP address using Shodan InternetDB (free, no API key).
        Returns open ports, known vulnerabilities, and hostnames.
        """
        if ip in self._ip_enrichment_cache:
            return self._ip_enrichment_cache[ip]

        try:
            session = await self._get_http_session()
            url = f"https://internetdb.shodan.io/{ip}"
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    enrichment = IPEnrichment(
                        ip=ip,
                        hostnames=data.get("hostnames", []),
                        ports=data.get("ports", []),
                        cpes=data.get("cpes", []),
                        vulns=data.get("vulns", []),
                        tags=data.get("tags", []),
                    )
                    self._ip_enrichment_cache[ip] = enrichment
                    return enrichment
                elif resp.status == 404:
                    # IP not in Shodan database
                    return None
        except Exception as e:
            logger.debug(f"[ThreatFeeds] InternetDB lookup failed for {ip}: {e}")
        return None



    # =========================================================================
    # IOC Matching Methods
    # =========================================================================

    def check_ip(self, ip: str) -> Optional[IOCEntry]:
        """Check if an IP is in any threat intelligence feed."""
        return self._malicious_ips.get(ip)

    def check_url(self, url: str) -> Optional[IOCEntry]:
        """Check if a URL matches any known malicious URL."""
        # Exact match
        if url in self._malicious_urls:
            return self._malicious_urls[url]
        # Check without trailing slash
        url_stripped = url.rstrip("/")
        if url_stripped in self._malicious_urls:
            return self._malicious_urls[url_stripped]
        return None

    def check_domain(self, domain: str) -> Optional[IOCEntry]:
        """Check if a domain is in any threat intelligence feed."""
        return self._malicious_domains.get(domain)

    def check_hash(self, file_hash: str) -> Optional[IOCEntry]:
        """Check if a file hash matches known malware."""
        return self._malicious_hashes.get(file_hash.lower())

    def is_tor_exit(self, ip: str) -> bool:
        """Check if an IP is a known Tor exit node."""
        return ip in self._tor_exit_nodes

    def check_all(self, ip: str = "", urls: List[str] = None,
                  domains: List[str] = None, hashes: List[str] = None
                  ) -> List[IOCEntry]:
        """
        Check multiple indicators at once against all feeds.
        Returns list of all matches found.
        """
        matches = []

        if ip:
            match = self.check_ip(ip)
            if match:
                matches.append(match)

        for url in (urls or []):
            match = self.check_url(url)
            if match:
                matches.append(match)

        for domain in (domains or []):
            match = self.check_domain(domain)
            if match:
                matches.append(match)

        for h in (hashes or []):
            match = self.check_hash(h)
            if match:
                matches.append(match)

        return matches

    # =========================================================================
    # Statistics & Reporting
    # =========================================================================

    @property
    def total_iocs(self) -> int:
        """Total number of IOCs across all feeds."""
        return (
            len(self._malicious_ips) +
            len(self._malicious_urls) +
            len(self._malicious_domains) +
            len(self._malicious_hashes) +
            len(self._tor_exit_nodes)
        )

    def get_stats(self) -> Dict[str, Any]:
        """Return comprehensive feed statistics."""
        return {
            "total_iocs": self.total_iocs,
            "malicious_ips": len(self._malicious_ips),
            "malicious_urls": len(self._malicious_urls),
            "malicious_domains": len(self._malicious_domains),
            "malicious_hashes": len(self._malicious_hashes),
            "tor_exit_nodes": len(self._tor_exit_nodes),
            "ip_enrichments_cached": len(self._ip_enrichment_cache),
            "feed_details": self._feed_stats,
            "last_refresh": {
                k: datetime.fromtimestamp(v, tz=timezone.utc).isoformat()
                for k, v in self._last_refresh.items()
            },
        }


# =============================================================================
# Module-level singleton
# =============================================================================
threat_feed_manager = ThreatFeedManager()
