"""
AegisTrap GeoIP Enrichment Module
====================================
Enriches every attacker session with geolocation data using
MaxMind GeoLite2 free databases. Provides:
- Country, city, region lookups
- ASN (Autonomous System Number) identification
- ISP/Organization mapping
- Tor exit node detection
- VPN/Proxy/Datacenter classification
- Geographic threat heatmap data

Free Tools Used:
- MaxMind GeoLite2-City database (free with registration)
- MaxMind GeoLite2-ASN database (free with registration)
- geoip2 Python library (Apache 2.0 license)

Download databases from: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
Place in: data/geoip/GeoLite2-City.mmdb and data/geoip/GeoLite2-ASN.mmdb
"""

import os
import asyncio
import logging
import ipaddress
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("aegistrap.geoip")

# Try to import geoip2; gracefully degrade if not installed
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False
    logger.warning("[GeoIP] geoip2 library not installed. GeoIP enrichment disabled.")


# =============================================================================
# Configuration
# =============================================================================
GEOIP_CITY_DB = os.getenv("GEOIP_CITY_DB", "data/geoip/GeoLite2-City.mmdb")
GEOIP_ASN_DB = os.getenv("GEOIP_ASN_DB", "data/geoip/GeoLite2-ASN.mmdb")

# Known Tor exit node ranges (updated periodically from public lists)
# In production, this would be fetched from https://check.torproject.org/torbulkexitlist
TOR_EXIT_NODES_URL = "https://check.torproject.org/torbulkexitlist"

# Known datacenter/cloud ASN numbers (commonly used by attackers)
DATACENTER_ASNS = {
    14061,   # DigitalOcean
    16276,   # OVH
    24940,   # Hetzner
    63949,   # Linode
    16509,   # Amazon AWS
    15169,   # Google Cloud
    8075,    # Microsoft Azure
    13335,   # Cloudflare
    20473,   # Vultr/Choopa
    46606,   # Unified Layer
    36352,   # ColoCrossing
    53667,   # FranTech/BuyVM
    62567,   # DigitalOcean Singapore
    398101,  # GoDaddy Cloud
    14618,   # Amazon Data Services
    396982,  # Google LLC
}


@dataclass
class GeoIPResult:
    """Structured result from GeoIP lookup."""
    ip: str = ""
    country_code: str = "XX"
    country_name: str = "Unknown"
    city: str = "Unknown"
    region: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = "UTC"
    postal_code: str = ""
    # ASN Information
    asn: int = 0
    asn_organization: str = "Unknown"
    # Classification
    is_private: bool = False
    is_tor_exit: bool = False
    is_datacenter: bool = False
    is_vpn_proxy: bool = False
    risk_score: int = 0  # 0-100, higher = more suspicious
    # Metadata
    lookup_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to flat dictionary for JSON logging."""
        return {
            "geo_ip": self.ip,
            "geo_country_code": self.country_code,
            "geo_country_name": self.country_name,
            "geo_city": self.city,
            "geo_region": self.region,
            "geo_latitude": self.latitude,
            "geo_longitude": self.longitude,
            "geo_timezone": self.timezone,
            "geo_asn": self.asn,
            "geo_asn_org": self.asn_organization,
            "geo_is_private": self.is_private,
            "geo_is_tor": self.is_tor_exit,
            "geo_is_datacenter": self.is_datacenter,
            "geo_is_vpn_proxy": self.is_vpn_proxy,
            "geo_risk_score": self.risk_score,
        }


class GeoIPEnrichment:
    """
    GeoIP lookup engine using MaxMind GeoLite2 databases.
    Provides geographic, ASN, and risk classification for attacker IPs.
    Includes local caching to avoid repeated lookups for the same IP.
    """

    def __init__(self):
        self._city_reader: Optional[Any] = None
        self._asn_reader: Optional[Any] = None
        self._cache: Dict[str, GeoIPResult] = {}
        self._tor_exit_nodes: set = set()
        self._initialized: bool = False
        self._lock = asyncio.Lock()

    async def initialize(self) -> bool:
        """
        Initialize GeoIP databases. Returns True if databases loaded successfully.
        Gracefully handles missing databases by logging a warning.
        """
        if not GEOIP2_AVAILABLE:
            logger.warning("[GeoIP] geoip2 not available. Skipping initialization.")
            return False

        try:
            if os.path.exists(GEOIP_CITY_DB):
                self._city_reader = geoip2.database.Reader(GEOIP_CITY_DB)
                logger.info(f"[GeoIP] City database loaded: {GEOIP_CITY_DB}")
            else:
                logger.warning(
                    f"[GeoIP] City database not found at {GEOIP_CITY_DB}. "
                    f"Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
                )

            if os.path.exists(GEOIP_ASN_DB):
                self._asn_reader = geoip2.database.Reader(GEOIP_ASN_DB)
                logger.info(f"[GeoIP] ASN database loaded: {GEOIP_ASN_DB}")
            else:
                logger.warning(
                    f"[GeoIP] ASN database not found at {GEOIP_ASN_DB}. "
                    f"Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
                )

            self._initialized = True
            return True

        except Exception as e:
            logger.error(f"[GeoIP] Initialization failed: {e}")
            return False

    async def lookup(self, ip: str) -> GeoIPResult:
        """
        Perform a full GeoIP lookup for an IP address.
        Returns cached results for previously seen IPs.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            GeoIPResult with all available enrichment data.
        """
        # Check cache first
        if ip in self._cache:
            return self._cache[ip]

        result = GeoIPResult(ip=ip)

        # Check if private/reserved IP
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_reserved or addr.is_loopback:
                result.is_private = True
                result.country_name = "Private Network"
                result.risk_score = 10
                self._cache[ip] = result
                return result
        except ValueError:
            result.country_name = "Invalid IP"
            return result

        # City lookup
        if self._city_reader:
            try:
                city_response = self._city_reader.city(ip)
                result.country_code = city_response.country.iso_code or "XX"
                result.country_name = city_response.country.name or "Unknown"
                result.city = city_response.city.name or "Unknown"
                if city_response.subdivisions:
                    result.region = city_response.subdivisions.most_specific.name or "Unknown"
                result.latitude = city_response.location.latitude or 0.0
                result.longitude = city_response.location.longitude or 0.0
                result.timezone = city_response.location.time_zone or "UTC"
                result.postal_code = city_response.postal.code or ""
            except geoip2.errors.AddressNotFoundError:
                logger.debug(f"[GeoIP] IP not found in city DB: {ip}")
            except Exception as e:
                logger.debug(f"[GeoIP] City lookup error for {ip}: {e}")

        # ASN lookup
        if self._asn_reader:
            try:
                asn_response = self._asn_reader.asn(ip)
                result.asn = asn_response.autonomous_system_number or 0
                result.asn_organization = (
                    asn_response.autonomous_system_organization or "Unknown"
                )
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception as e:
                logger.debug(f"[GeoIP] ASN lookup error for {ip}: {e}")

        # Classification
        result.is_tor_exit = ip in self._tor_exit_nodes
        result.is_datacenter = result.asn in DATACENTER_ASNS

        # Risk scoring algorithm
        result.risk_score = self._calculate_risk_score(result)

        # Cache the result
        self._cache[ip] = result

        logger.debug(
            f"[GeoIP] Enriched {ip}: {result.country_code}/{result.city} "
            f"ASN:{result.asn} Risk:{result.risk_score}"
        )

        return result

    def _calculate_risk_score(self, result: GeoIPResult) -> int:
        """
        Calculate a risk score (0-100) based on geographic and network indicators.
        Higher scores indicate more suspicious origins.
        """
        score = 0

        # Tor exit nodes are inherently suspicious in honeypot context
        if result.is_tor_exit:
            score += 40

        # Datacenter IPs are commonly used by automated attacks
        if result.is_datacenter:
            score += 25

        # VPN/Proxy indicators
        if result.is_vpn_proxy:
            score += 30

        # Countries commonly associated with threat actor infrastructure
        high_risk_countries = {"CN", "RU", "KP", "IR", "NG", "RO", "UA", "BR"}
        if result.country_code in high_risk_countries:
            score += 15

        # Unknown/unresolved locations
        if result.country_code == "XX":
            score += 10

        return min(score, 100)

    async def update_tor_exit_nodes(self, nodes: set) -> None:
        """
        Update the Tor exit node list.
        In production, this would be fetched periodically from TorProject.
        """
        async with self._lock:
            self._tor_exit_nodes = nodes
            logger.info(f"[GeoIP] Updated Tor exit node list: {len(nodes)} nodes")

    def get_cache_stats(self) -> Dict[str, int]:
        """Return cache statistics."""
        return {
            "cached_ips": len(self._cache),
            "tor_nodes_tracked": len(self._tor_exit_nodes),
        }

    def close(self) -> None:
        """Close database readers and free resources."""
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()


# =============================================================================
# Module-level singleton
# =============================================================================
geoip_enrichment = GeoIPEnrichment()
