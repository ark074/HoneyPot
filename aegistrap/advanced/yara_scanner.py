"""
AegisTrap YARA Rule Scanning Engine
======================================
Scans files uploaded via FTP/HTTP and command payloads against
YARA rules to identify known malware families, packers, exploits,
and suspicious patterns.

Free Tools Used:
- yara-python (Apache 2.0 license) - YARA rule matching engine
- Community YARA rules (various open licenses)
- Custom honeypot-specific rules

Sources for free YARA rules:
- https://github.com/Yara-Rules/rules (GPL-2.0)
- https://github.com/InQuest/awesome-yara
- https://github.com/elastic/protections-artifacts
- https://github.com/Neo23x0/signature-base (CC BY-NC 4.0)

Place .yar/.yara rule files in: data/yara_rules/
"""

import os
import asyncio
import hashlib
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("aegistrap.yara")

# Try to import yara; gracefully degrade if not installed
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("[YARA] yara-python not installed. Scanning disabled.")



# =============================================================================
# Configuration
# =============================================================================
YARA_RULES_DIR = os.getenv("YARA_RULES_DIR", "data/yara_rules")
MAX_SCAN_SIZE = 10 * 1024 * 1024  # 10MB max file size for scanning


@dataclass
class YARAMatch:
    """Represents a single YARA rule match."""
    rule_name: str = ""
    rule_namespace: str = ""
    tags: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    strings_matched: List[str] = field(default_factory=list)
    # Context
    scanned_file: str = ""         # Filename or identifier
    scanned_hash_md5: str = ""
    scanned_hash_sha256: str = ""
    scanned_size: int = 0
    # Enrichment
    malware_family: str = ""
    severity: str = "medium"       # low, medium, high, critical
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "yara_rule": self.rule_name,
            "yara_namespace": self.rule_namespace,
            "yara_tags": self.tags,
            "yara_malware_family": self.malware_family,
            "yara_severity": self.severity,
            "yara_file": self.scanned_file,
            "yara_md5": self.scanned_hash_md5,
            "yara_sha256": self.scanned_hash_sha256,
            "yara_size": self.scanned_size,
            "yara_strings_count": len(self.strings_matched),
        }


# =============================================================================
# Built-in YARA Rules (for when no external rules are loaded)
# =============================================================================

BUILTIN_RULES = """
rule Mirai_Botnet_Indicators {
    meta:
        description = "Detects Mirai botnet variant indicators"
        author = "AegisTrap"
        severity = "critical"
        malware_family = "Mirai"
    strings:
        $s1 = "/bin/busybox" ascii
        $s2 = "ECCHI" ascii
        $s3 = "dvrHelper" ascii
        $s4 = "cd /tmp || cd /var/run || cd /mnt" ascii
        $s5 = "wget http" ascii
        $s6 = "tftp" ascii
        $s7 = "chmod 777" ascii
        $s8 = "/bin/busybox ECCHI" ascii
    condition:
        3 of them
}

rule Cryptominer_Generic {
    meta:
        description = "Detects generic cryptocurrency miner indicators"
        author = "AegisTrap"
        severity = "high"
        malware_family = "Cryptominer"
    strings:
        $s1 = "stratum+tcp://" ascii
        $s2 = "xmrig" ascii nocase
        $s3 = "cryptonight" ascii nocase
        $s4 = "monero" ascii nocase
        $s5 = "pool.minergate" ascii
        $s6 = "hashrate" ascii
        $s7 = "mining_pool" ascii
        $s8 = "--donate-level" ascii
    condition:
        2 of them
}

rule Reverse_Shell_Script {
    meta:
        description = "Detects reverse shell script patterns"
        author = "AegisTrap"
        severity = "critical"
        malware_family = "ReverseShell"
    strings:
        $bash1 = "bash -i >& /dev/tcp/" ascii
        $bash2 = "/bin/bash -c 'bash -i" ascii
        $nc1 = "nc -e /bin/" ascii
        $nc2 = "ncat -e /bin/" ascii
        $py1 = "socket.socket" ascii
        $py2 = "subprocess.call" ascii
        $py3 = "pty.spawn" ascii
        $perl1 = "socket(SOCKET" ascii
        $php1 = "fsockopen(" ascii
        $php2 = "exec(" ascii
    condition:
        any of ($bash*) or (any of ($nc*)) or
        (2 of ($py*)) or (all of ($perl*)) or (all of ($php*))
}

rule Linux_Exploit_Payload {
    meta:
        description = "Detects common Linux exploit payload patterns"
        author = "AegisTrap"
        severity = "critical"
        malware_family = "Exploit"
    strings:
        $elf = { 7f 45 4c 46 }
        $shellcode1 = { 31 c0 50 68 2f 2f 73 68 }
        $shellcode2 = { 6a 0b 58 99 52 }
        $nop_sled = { 90 90 90 90 90 90 90 90 }
        $priv1 = "dirty_pipe" ascii nocase
        $priv2 = "dirty_cow" ascii nocase
        $priv3 = "CVE-20" ascii
    condition:
        ($elf at 0 and (any of ($shellcode*) or $nop_sled)) or
        any of ($priv*)
}

rule Webshell_Generic {
    meta:
        description = "Detects generic webshell patterns"
        author = "AegisTrap"
        severity = "high"
        malware_family = "Webshell"
    strings:
        $php1 = "eval(base64_decode(" ascii
        $php2 = "eval(gzinflate(" ascii
        $php3 = "system($_" ascii
        $php4 = "passthru($_" ascii
        $php5 = "shell_exec($_" ascii
        $php6 = "<?php eval(" ascii
        $asp1 = "eval(Request" ascii
        $jsp1 = "Runtime.getRuntime().exec" ascii
    condition:
        any of them
}

rule SSH_Key_Exfiltration {
    meta:
        description = "Detects SSH private key content in uploads"
        author = "AegisTrap"
        severity = "high"
        malware_family = "DataTheft"
    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $ec = "-----BEGIN EC PRIVATE KEY-----" ascii
        $dsa = "-----BEGIN DSA PRIVATE KEY-----" ascii
    condition:
        any of them
}

rule Ransomware_Note {
    meta:
        description = "Detects ransomware note indicators"
        author = "AegisTrap"
        severity = "critical"
        malware_family = "Ransomware"
    strings:
        $s1 = "your files have been encrypted" ascii nocase
        $s2 = "bitcoin" ascii nocase
        $s3 = "decrypt" ascii nocase
        $s4 = "ransom" ascii nocase
        $s5 = "wallet" ascii nocase
        $s6 = ".onion" ascii
        $s7 = "payment" ascii nocase
    condition:
        3 of them
}

rule Credential_Harvester {
    meta:
        description = "Detects credential harvesting tool patterns"
        author = "AegisTrap"
        severity = "high"
        malware_family = "CredHarvester"
    strings:
        $s1 = "/etc/shadow" ascii
        $s2 = "password" ascii
        $s3 = "credential" ascii
        $s4 = "mimikatz" ascii nocase
        $s5 = "hashdump" ascii
        $s6 = "secretsdump" ascii
        $s7 = "lazagne" ascii nocase
    condition:
        3 of them
}
"""



class YARAScanner:
    """
    YARA-based malware and payload scanning engine.
    Loads rules from disk and built-in definitions, then scans
    uploaded files, command payloads, and captured data.
    """

    def __init__(self, rules_dir: str = YARA_RULES_DIR):
        self._rules_dir = rules_dir
        self._compiled_rules: Optional[Any] = None
        self._initialized: bool = False
        self._scan_count: int = 0
        self._match_count: int = 0
        self._matches_history: List[YARAMatch] = []
        self._lock = asyncio.Lock()

    async def initialize(self) -> bool:
        """
        Initialize YARA engine by compiling all available rules.
        Returns True if at least built-in rules were compiled.
        """
        if not YARA_AVAILABLE:
            logger.warning("[YARA] yara-python not available. Skipping init.")
            return False

        try:
            rule_sources = {}

            # Load built-in rules
            rule_sources["builtin"] = BUILTIN_RULES

            # Load rules from disk
            if os.path.isdir(self._rules_dir):
                for filename in os.listdir(self._rules_dir):
                    if filename.endswith((".yar", ".yara")):
                        filepath = os.path.join(self._rules_dir, filename)
                        try:
                            with open(filepath, "r") as f:
                                rule_sources[filename] = f.read()
                        except IOError as e:
                            logger.warning(
                                f"[YARA] Could not read rule file {filepath}: {e}"
                            )

            # Compile all rules
            self._compiled_rules = yara.compile(sources=rule_sources)
            self._initialized = True

            logger.info(
                f"[YARA] Initialized with {len(rule_sources)} rule source(s) "
                f"from {self._rules_dir}"
            )
            return True

        except yara.SyntaxError as e:
            logger.error(f"[YARA] Rule compilation error: {e}")
            # Fall back to built-in only
            try:
                self._compiled_rules = yara.compile(
                    sources={"builtin": BUILTIN_RULES}
                )
                self._initialized = True
                logger.info("[YARA] Initialized with built-in rules only")
                return True
            except Exception as e2:
                logger.error(f"[YARA] Built-in rule compilation failed: {e2}")
                return False

        except Exception as e:
            logger.error(f"[YARA] Initialization error: {e}")
            return False

    async def scan_data(
        self, data: bytes, identifier: str = "unknown"
    ) -> List[YARAMatch]:
        """
        Scan raw bytes against all loaded YARA rules.

        Args:
            data: Raw bytes to scan.
            identifier: Filename or description for logging.

        Returns:
            List of YARAMatch objects for all rule hits.
        """
        if not self._initialized or not self._compiled_rules:
            return []

        if len(data) > MAX_SCAN_SIZE:
            logger.warning(
                f"[YARA] Data too large to scan ({len(data)} bytes): {identifier}"
            )
            data = data[:MAX_SCAN_SIZE]

        # Calculate hashes
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

        matches = []

        try:
            async with self._lock:
                # yara.match is CPU-bound; run in executor for async safety
                loop = asyncio.get_event_loop()
                raw_matches = await loop.run_in_executor(
                    None, self._compiled_rules.match, None, data
                )

            self._scan_count += 1

            for match in raw_matches:
                # Extract matched strings (limit for logging)
                strings_matched = []
                for string_match in match.strings[:10]:
                    if hasattr(string_match, 'instances'):
                        for instance in string_match.instances[:3]:
                            strings_matched.append(repr(instance.matched_data[:50]))
                    else:
                        strings_matched.append(str(string_match)[:50])

                # Determine severity from rule meta
                meta = match.meta if hasattr(match, 'meta') else {}
                severity = meta.get("severity", "medium")
                malware_family = meta.get("malware_family", "Unknown")

                yara_match = YARAMatch(
                    rule_name=match.rule,
                    rule_namespace=match.namespace,
                    tags=list(match.tags) if hasattr(match, 'tags') else [],
                    meta=meta,
                    strings_matched=strings_matched,
                    scanned_file=identifier,
                    scanned_hash_md5=md5,
                    scanned_hash_sha256=sha256,
                    scanned_size=len(data),
                    malware_family=malware_family,
                    severity=severity,
                )
                matches.append(yara_match)

            if matches:
                self._match_count += len(matches)
                self._matches_history.extend(matches)

                logger.warning(
                    f"[YARA] {len(matches)} rule(s) matched for "
                    f"'{identifier}' (md5={md5[:8]}...): "
                    f"{[m.rule_name for m in matches]}"
                )

        except Exception as e:
            logger.error(f"[YARA] Scan error for '{identifier}': {e}")

        return matches

    async def scan_text(
        self, text: str, identifier: str = "command"
    ) -> List[YARAMatch]:
        """
        Scan text content (commands, scripts) against YARA rules.

        Args:
            text: Text string to scan.
            identifier: Description for logging.

        Returns:
            List of YARAMatch objects.
        """
        return await self.scan_data(text.encode("utf-8", errors="replace"), identifier)

    async def scan_file(self, filepath: str) -> List[YARAMatch]:
        """
        Scan a file on disk against YARA rules.

        Args:
            filepath: Path to the file to scan.

        Returns:
            List of YARAMatch objects.
        """
        try:
            with open(filepath, "rb") as f:
                data = f.read(MAX_SCAN_SIZE)
            return await self.scan_data(data, os.path.basename(filepath))
        except IOError as e:
            logger.error(f"[YARA] Cannot read file {filepath}: {e}")
            return []

    def get_stats(self) -> Dict:
        """Return scanning statistics."""
        return {
            "initialized": self._initialized,
            "total_scans": self._scan_count,
            "total_matches": self._match_count,
            "recent_matches": [
                m.to_dict() for m in self._matches_history[-20:]
            ],
            "rules_loaded": bool(self._compiled_rules),
        }

    def get_all_matches(self) -> List[YARAMatch]:
        """Return all historical matches."""
        return self._matches_history.copy()


# =============================================================================
# Module-level singleton
# =============================================================================
yara_scanner = YARAScanner()
