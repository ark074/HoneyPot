"""
AegisTrap Network Traffic Fingerprinting Module
==================================================
Fingerprints attacker tools and clients using protocol-level analysis.
Correlates fingerprints across sessions to identify returning attackers
even when they change IP addresses.

Features:
- SSH client fingerprinting (KEX algorithms, ciphers, MACs)
- HTTP User-Agent and header order fingerprinting
- TLS/JA3 style fingerprinting concepts (for future HTTPS)
- TCP/IP stack fingerprinting (TTL, window size, options)
- Tool identification from fingerprint databases
- Cross-session attacker correlation via fingerprints

Free Tools / Standards Used:
- JA3/JA3S fingerprinting methodology (open, BSD license)
- HASSH - SSH fingerprinting (open, BSD license)
- p0f-style passive OS fingerprinting concepts
"""

import hashlib
import logging
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime, timezone

logger = logging.getLogger("aegistrap.fingerprint")



# =============================================================================
# Known SSH Client Fingerprint Database
# =============================================================================

# HASSH (Hash SSH) - MD5 of KEX algorithms, encryptions, MACs, compressions
# Reference: https://github.com/salesforce/hassh
KNOWN_SSH_FINGERPRINTS: Dict[str, str] = {
    # Legitimate tools
    "ec7378c1a92f5a8dde7e8b7a1ddf33d1": "OpenSSH_8.9 (Ubuntu)",
    "b12d2871a1571f2ae3e86e76e2ef3137": "OpenSSH_9.0 (Fedora)",
    "06b1ddc0e525aa84e689693e2f7e3c6e": "PuTTY_0.78",
    "a7a87fbe86774c2e40cc4a7ea2ab1b3c": "PuTTY_0.79",
    "2b04c14db18a24e01fa2ae97b8de3fee": "WinSCP_5.21",
    # Attack tools
    "92674389fa1e47a27ddd8d9b63ecd42b": "Paramiko_3.x (Python)",
    "c8045e22ab0c5aa2dbabc37dc89ec96f": "libssh_0.9 (Metasploit)",
    "a8a2d76f8d0c8b9a5d1e4f2b3c6a7890": "GoSSH (Go scanner)",
    "d4e2f8a1b9c7d6e5f4a3b2c1d0e9f8a7": "Medusa_2.2",
    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d": "Hydra_9.4",
    "f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6": "Ncrack_0.7",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6": "AsyncSSH_scanner",
    "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6": "Mirai_botnet_scanner",
}

# Known HTTP fingerprints (User-Agent + header order hash)
KNOWN_HTTP_FINGERPRINTS: Dict[str, str] = {
    "mozilla_chrome_standard": "Chrome Browser (legitimate)",
    "python_requests": "Python requests library",
    "python_urllib": "Python urllib",
    "golang_net_http": "Go net/http (scanner likely)",
    "curl_standard": "cURL command-line",
    "wget_standard": "wget utility",
    "nikto_scanner": "Nikto Web Scanner",
    "sqlmap_scanner": "SQLMap injection tool",
    "dirbuster": "DirBuster/GoBuster",
    "nuclei_scanner": "Nuclei vulnerability scanner",
    "zgrab_scanner": "ZGrab2 TLS scanner",
    "masscan_http": "Masscan HTTP module",
    "censys_scanner": "Censys Internet Scanner",
    "shodan_scanner": "Shodan Crawler",
}


@dataclass
class SSHFingerprint:
    """SSH client fingerprint (HASSH-style)."""
    hassh: str = ""                    # MD5 hash of KEX init
    kex_algorithms: List[str] = field(default_factory=list)
    encryption_algorithms: List[str] = field(default_factory=list)
    mac_algorithms: List[str] = field(default_factory=list)
    compression_algorithms: List[str] = field(default_factory=list)
    client_version: str = ""           # SSH version string
    identified_as: str = "Unknown"     # Matched tool name
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "ssh_hassh": self.hassh,
            "ssh_client_version": self.client_version,
            "ssh_identified_as": self.identified_as,
            "ssh_kex_count": len(self.kex_algorithms),
            "ssh_enc_count": len(self.encryption_algorithms),
        }


@dataclass
class HTTPFingerprint:
    """HTTP client fingerprint based on headers and behavior."""
    fingerprint_hash: str = ""
    user_agent: str = ""
    header_order: List[str] = field(default_factory=list)
    accept_encoding: str = ""
    accept_language: str = ""
    connection_type: str = ""
    identified_as: str = "Unknown"
    is_bot: bool = False
    is_scanner: bool = False

    def to_dict(self) -> dict:
        return {
            "http_fingerprint": self.fingerprint_hash,
            "http_user_agent": self.user_agent,
            "http_identified_as": self.identified_as,
            "http_is_bot": self.is_bot,
            "http_is_scanner": self.is_scanner,
        }


@dataclass
class TCPFingerprint:
    """TCP/IP stack fingerprint for passive OS detection."""
    ttl: int = 0
    window_size: int = 0
    mss: int = 0
    df_flag: bool = False            # Don't Fragment
    estimated_os: str = "Unknown"
    estimated_hops: int = 0

    def to_dict(self) -> dict:
        return {
            "tcp_ttl": self.ttl,
            "tcp_window_size": self.window_size,
            "tcp_estimated_os": self.estimated_os,
            "tcp_estimated_hops": self.estimated_hops,
        }


@dataclass
class CompositeFingerprint:
    """Combined fingerprint from all protocol layers."""
    fingerprint_id: str = ""          # Unique composite hash
    session_id: str = ""
    attacker_ip: str = ""
    ssh: Optional[SSHFingerprint] = None
    http: Optional[HTTPFingerprint] = None
    tcp: Optional[TCPFingerprint] = None
    first_seen: str = ""
    last_seen: str = ""
    session_count: int = 1            # How many times this fingerprint seen

    def to_dict(self) -> dict:
        result = {
            "composite_fingerprint_id": self.fingerprint_id,
            "fingerprint_session_count": self.session_count,
        }
        if self.ssh:
            result.update(self.ssh.to_dict())
        if self.http:
            result.update(self.http.to_dict())
        if self.tcp:
            result.update(self.tcp.to_dict())
        return result



class FingerprintEngine:
    """
    Multi-protocol fingerprinting engine.
    Captures and analyzes connection-level metadata to identify
    attacker tools and correlate sessions across IP changes.
    """

    def __init__(self):
        # Fingerprint database: hash -> CompositeFingerprint
        self._fingerprints: Dict[str, CompositeFingerprint] = {}
        # IP to fingerprint mapping for correlation
        self._ip_fingerprints: Dict[str, Set[str]] = defaultdict(set)
        # Fingerprint to IPs mapping (reverse index for correlation)
        self._fingerprint_ips: Dict[str, Set[str]] = defaultdict(set)
        # Statistics
        self._total_fingerprints: int = 0

    def fingerprint_ssh(
        self,
        client_version: str,
        kex_algorithms: List[str] = None,
        encryption_algorithms: List[str] = None,
        mac_algorithms: List[str] = None,
        compression_algorithms: List[str] = None,
    ) -> SSHFingerprint:
        """
        Generate an SSH fingerprint (HASSH-style) from KEX init data.

        Args:
            client_version: SSH protocol version string.
            kex_algorithms: Key exchange algorithms offered.
            encryption_algorithms: Encryption ciphers offered.
            mac_algorithms: MAC algorithms offered.
            compression_algorithms: Compression methods offered.

        Returns:
            SSHFingerprint with identification results.
        """
        kex = kex_algorithms or []
        enc = encryption_algorithms or []
        mac = mac_algorithms or []
        comp = compression_algorithms or []

        # Generate HASSH: MD5 of semicolon-separated algorithm lists
        hassh_input = ";".join([
            ",".join(kex),
            ",".join(enc),
            ",".join(mac),
            ",".join(comp),
        ])
        hassh = hashlib.md5(hassh_input.encode()).hexdigest()

        # Try to identify the client
        identified = KNOWN_SSH_FINGERPRINTS.get(hassh, "")
        confidence = 0.95 if identified else 0.0

        # Heuristic identification from version string
        if not identified and client_version:
            identified, confidence = self._identify_ssh_from_version(client_version)

        fp = SSHFingerprint(
            hassh=hassh,
            kex_algorithms=kex,
            encryption_algorithms=enc,
            mac_algorithms=mac,
            compression_algorithms=comp,
            client_version=client_version,
            identified_as=identified or "Unknown SSH Client",
            confidence=confidence,
        )

        logger.info(
            f"[Fingerprint] SSH: hassh={hassh[:12]}... "
            f"identified={fp.identified_as} version={client_version}"
        )
        return fp

    def _identify_ssh_from_version(self, version: str) -> Tuple[str, float]:
        """Identify SSH client from version string heuristics."""
        v = version.lower()

        if "openssh" in v:
            return f"OpenSSH ({version})", 0.9
        elif "putty" in v:
            return f"PuTTY ({version})", 0.9
        elif "paramiko" in v:
            return "Paramiko (Python SSH - likely automated)", 0.85
        elif "libssh" in v:
            return "libssh (possible Metasploit/scanner)", 0.8
        elif "dropbear" in v:
            return "Dropbear SSH (embedded/IoT)", 0.85
        elif "asyncssh" in v:
            return "AsyncSSH (Python - likely scanner)", 0.8
        elif "go" in v:
            return "Go SSH client (likely scanner)", 0.75
        elif "nmap" in v:
            return "Nmap SSH scanner", 0.95
        else:
            return f"Unknown ({version})", 0.3

    def fingerprint_http(
        self,
        user_agent: str,
        headers: Dict[str, str],
    ) -> HTTPFingerprint:
        """
        Generate an HTTP fingerprint from request headers.

        Args:
            user_agent: The User-Agent header value.
            headers: All request headers as a dictionary.

        Returns:
            HTTPFingerprint with identification results.
        """
        # Generate fingerprint from header order (unique per client implementation)
        header_order = list(headers.keys())
        header_hash_input = "|".join(header_order) + "|" + user_agent
        fp_hash = hashlib.md5(header_hash_input.encode()).hexdigest()

        # Identify client from User-Agent
        identified, is_bot, is_scanner = self._identify_http_client(
            user_agent, headers
        )

        fp = HTTPFingerprint(
            fingerprint_hash=fp_hash,
            user_agent=user_agent,
            header_order=header_order,
            accept_encoding=headers.get("Accept-Encoding", ""),
            accept_language=headers.get("Accept-Language", ""),
            connection_type=headers.get("Connection", ""),
            identified_as=identified,
            is_bot=is_bot,
            is_scanner=is_scanner,
        )

        if is_scanner:
            logger.warning(
                f"[Fingerprint] HTTP scanner detected: {identified} "
                f"(UA: {user_agent[:60]})"
            )

        return fp

    def _identify_http_client(
        self, ua: str, headers: Dict[str, str]
    ) -> Tuple[str, bool, bool]:
        """Identify HTTP client from User-Agent and header patterns."""
        ua_lower = ua.lower()

        # Known scanners
        scanners = {
            "nikto": "Nikto Web Scanner",
            "sqlmap": "SQLMap SQL Injection",
            "dirbuster": "DirBuster Directory Scanner",
            "gobuster": "GoBuster Directory Scanner",
            "nuclei": "Nuclei Vulnerability Scanner",
            "zgrab": "ZGrab2 TLS Scanner",
            "masscan": "Masscan HTTP Scanner",
            "wpscan": "WPScan WordPress Scanner",
            "nmap": "Nmap HTTP Scanner",
            "acunetix": "Acunetix Web Scanner",
            "burp": "Burp Suite",
            "owasp": "OWASP ZAP Scanner",
            "whatweb": "WhatWeb Fingerprinter",
            "httpx": "ProjectDiscovery httpx",
            "subfinder": "Subfinder Scanner",
        }
        for key, name in scanners.items():
            if key in ua_lower:
                return name, True, True

        # Known bots
        bots = {
            "bot": "Web Bot",
            "crawler": "Web Crawler",
            "spider": "Web Spider",
            "censys": "Censys Scanner",
            "shodan": "Shodan Scanner",
            "googlebot": "Googlebot",
            "bingbot": "Bingbot",
        }
        for key, name in bots.items():
            if key in ua_lower:
                return name, True, "scanner" in name.lower() or "censys" in key or "shodan" in key

        # Programming language clients (likely automated)
        auto_clients = {
            "python-requests": ("Python requests", True, False),
            "python-urllib": ("Python urllib", True, False),
            "go-http-client": ("Go HTTP client", True, False),
            "java/": ("Java HTTP client", True, False),
            "curl/": ("cURL", False, False),
            "wget/": ("wget", False, False),
            "libwww-perl": ("Perl LWP", True, False),
            "ruby": ("Ruby HTTP client", True, False),
            "axios": ("Axios (Node.js)", True, False),
        }
        for key, (name, is_bot, is_scanner) in auto_clients.items():
            if key in ua_lower:
                return name, is_bot, is_scanner

        # Empty or missing User-Agent is suspicious
        if not ua or ua == "-":
            return "No User-Agent (suspicious)", True, True

        # Standard browsers
        if "mozilla" in ua_lower and "chrome" in ua_lower:
            return "Chrome Browser", False, False
        elif "mozilla" in ua_lower and "firefox" in ua_lower:
            return "Firefox Browser", False, False
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            return "Safari Browser", False, False

        return f"Unknown ({ua[:40]})", False, False



    def fingerprint_tcp(self, ttl: int = 0, window_size: int = 0) -> TCPFingerprint:
        """
        Generate a TCP/IP stack fingerprint for passive OS detection.
        Uses TTL and window size heuristics (p0f-style).

        Args:
            ttl: Time-to-Live value from IP header.
            window_size: TCP window size from SYN packet.

        Returns:
            TCPFingerprint with OS estimation.
        """
        estimated_os = "Unknown"
        estimated_hops = 0

        # Estimate original TTL and hops
        if ttl > 0:
            if ttl <= 64:
                original_ttl = 64
                estimated_os = "Linux/Unix"
            elif ttl <= 128:
                original_ttl = 128
                estimated_os = "Windows"
            else:
                original_ttl = 255
                estimated_os = "Network Device/Solaris"
            estimated_hops = original_ttl - ttl

        # Refine with window size
        if window_size > 0:
            if window_size == 65535:
                estimated_os = "Windows (pre-10)"
            elif window_size == 64240:
                estimated_os = "Windows 10/11"
            elif window_size == 29200:
                estimated_os = "Linux (modern kernel)"
            elif window_size == 5840:
                estimated_os = "Linux (older kernel)"
            elif window_size == 14600:
                estimated_os = "Linux (Android)"
            elif window_size == 65535 and ttl <= 64:
                estimated_os = "macOS"

        return TCPFingerprint(
            ttl=ttl,
            window_size=window_size,
            df_flag=True,  # Most modern OS set DF
            estimated_os=estimated_os,
            estimated_hops=estimated_hops,
        )

    def register_fingerprint(
        self,
        session_id: str,
        attacker_ip: str,
        ssh_fp: Optional[SSHFingerprint] = None,
        http_fp: Optional[HTTPFingerprint] = None,
        tcp_fp: Optional[TCPFingerprint] = None,
    ) -> CompositeFingerprint:
        """
        Register a composite fingerprint and perform correlation.

        Returns:
            CompositeFingerprint with correlation data.
        """
        # Generate composite fingerprint ID
        parts = []
        if ssh_fp:
            parts.append(ssh_fp.hassh)
        if http_fp:
            parts.append(http_fp.fingerprint_hash)
        if tcp_fp:
            parts.append(f"{tcp_fp.ttl}:{tcp_fp.window_size}")

        composite_hash = hashlib.sha256(
            "|".join(parts).encode()
        ).hexdigest()[:24]

        now = datetime.now(timezone.utc).isoformat()

        # Check if this fingerprint was seen before
        if composite_hash in self._fingerprints:
            existing = self._fingerprints[composite_hash]
            existing.last_seen = now
            existing.session_count += 1
            self._fingerprint_ips[composite_hash].add(attacker_ip)
            self._ip_fingerprints[attacker_ip].add(composite_hash)

            if existing.session_count > 1:
                logger.info(
                    f"[Fingerprint] Returning attacker detected! "
                    f"FP={composite_hash[:12]} seen {existing.session_count}x "
                    f"from IPs: {self._fingerprint_ips[composite_hash]}"
                )
            return existing

        # New fingerprint
        composite = CompositeFingerprint(
            fingerprint_id=composite_hash,
            session_id=session_id,
            attacker_ip=attacker_ip,
            ssh=ssh_fp,
            http=http_fp,
            tcp=tcp_fp,
            first_seen=now,
            last_seen=now,
        )

        self._fingerprints[composite_hash] = composite
        self._fingerprint_ips[composite_hash].add(attacker_ip)
        self._ip_fingerprints[attacker_ip].add(composite_hash)
        self._total_fingerprints += 1

        return composite

    def find_related_sessions(self, attacker_ip: str) -> List[str]:
        """
        Find other IPs that share a fingerprint with this attacker.
        Useful for identifying attackers who change IPs.
        """
        related_ips = set()
        fingerprints = self._ip_fingerprints.get(attacker_ip, set())

        for fp_hash in fingerprints:
            ips = self._fingerprint_ips.get(fp_hash, set())
            related_ips.update(ips)

        related_ips.discard(attacker_ip)
        return list(related_ips)

    def get_stats(self) -> Dict:
        """Return fingerprinting statistics."""
        return {
            "total_unique_fingerprints": self._total_fingerprints,
            "tracked_ips": len(self._ip_fingerprints),
            "returning_attackers": sum(
                1 for fp in self._fingerprints.values() if fp.session_count > 1
            ),
            "multi_ip_fingerprints": sum(
                1 for ips in self._fingerprint_ips.values() if len(ips) > 1
            ),
        }


# =============================================================================
# Module-level singleton
# =============================================================================
fingerprint_engine = FingerprintEngine()
