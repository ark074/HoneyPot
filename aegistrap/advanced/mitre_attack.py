"""
AegisTrap MITRE ATT&CK Auto-Classification Engine
====================================================
Automatically maps attacker commands and behaviors to MITRE ATT&CK
techniques, tactics, and procedures (TTPs). Provides real-time
classification for threat intelligence enrichment.

Free Tools Used:
- MITRE ATT&CK Framework (open, CC BY 4.0 license)
- Pattern-based classification engine (custom)
- STIX/TAXII compatible output format

Reference: https://attack.mitre.org/
"""

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger("aegistrap.mitre")


@dataclass
class ATTACKTechnique:
    """Represents a single MITRE ATT&CK technique match."""
    technique_id: str         # e.g., "T1059.004"
    technique_name: str       # e.g., "Unix Shell"
    tactic: str              # e.g., "Execution"
    tactic_id: str           # e.g., "TA0002"
    confidence: float = 0.0  # 0.0 - 1.0
    description: str = ""
    data_source: str = ""    # What triggered the detection
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for logging."""
        return {
            "mitre_technique_id": self.technique_id,
            "mitre_technique_name": self.technique_name,
            "mitre_tactic": self.tactic,
            "mitre_tactic_id": self.tactic_id,
            "mitre_confidence": self.confidence,
            "mitre_description": self.description,
        }


@dataclass
class AttackChainAnalysis:
    """Represents the full ATT&CK chain observed in a session."""
    session_id: str = ""
    techniques: List[ATTACKTechnique] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    overall_sophistication: str = "low"  # low, medium, high, advanced
    campaign_indicators: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "attack_chain_session": self.session_id,
            "techniques_count": len(self.techniques),
            "kill_chain_phases": self.kill_chain_phases,
            "sophistication_level": self.overall_sophistication,
            "campaign_indicators": self.campaign_indicators,
            "techniques": [t.to_dict() for t in self.techniques],
        }


# =============================================================================
# MITRE ATT&CK Technique Pattern Database
# Maps regex patterns to ATT&CK technique IDs
# =============================================================================

TECHNIQUE_PATTERNS: List[Tuple[re.Pattern, str, str, str, str, float]] = [
    # Format: (pattern, technique_id, technique_name, tactic, tactic_id, confidence)

    # =========================================================================
    # TA0001 - Initial Access
    # =========================================================================
    (re.compile(r'\b(ssh|telnet|ftp)\b.*\b(brute|force|hydra|medusa|ncrack)\b', re.I),
     "T1110.001", "Password Guessing", "Credential Access", "TA0006", 0.9),

    (re.compile(r'\b(admin|root|administrator)\b.*\b(password|pass|pwd|123456|admin)\b', re.I),
     "T1078.001", "Default Accounts", "Initial Access", "TA0001", 0.7),

    # =========================================================================
    # TA0002 - Execution
    # =========================================================================
    (re.compile(r'\bbash\s+-[ic]\b|\bsh\s+-[ic]\b', re.I),
     "T1059.004", "Unix Shell", "Execution", "TA0002", 0.95),

    (re.compile(r'\bpython[23]?\s+-c\b|\bpython[23]?\s+.*\.py\b', re.I),
     "T1059.006", "Python", "Execution", "TA0002", 0.9),

    (re.compile(r'\bperl\s+-e\b|\bruby\s+-e\b', re.I),
     "T1059", "Command and Scripting Interpreter", "Execution", "TA0002", 0.85),

    (re.compile(r'\bcrontab\b|\b/etc/cron', re.I),
     "T1053.003", "Cron", "Execution", "TA0002", 0.85),

    (re.compile(r'\bat\s+\d|atq|atrm\b', re.I),
     "T1053.002", "At", "Execution", "TA0002", 0.8),

    (re.compile(r'\bnohup\b.*&|\bdisown\b|\bscreen\s+-[dDmS]', re.I),
     "T1059.004", "Unix Shell (Background Exec)", "Execution", "TA0002", 0.7),

    # =========================================================================
    # TA0003 - Persistence
    # =========================================================================
    (re.compile(r'/etc/rc\.local|/etc/init\.d|systemctl\s+enable|update-rc\.d', re.I),
     "T1037.004", "RC Scripts", "Persistence", "TA0003", 0.9),

    (re.compile(r'\.bashrc|\.bash_profile|\.profile|/etc/profile', re.I),
     "T1546.004", "Unix Shell Configuration Modification", "Persistence", "TA0003", 0.85),

    (re.compile(r'authorized_keys|\.ssh/.*key', re.I),
     "T1098.004", "SSH Authorized Keys", "Persistence", "TA0003", 0.95),

    (re.compile(r'crontab\s+-[el]|/etc/cron\.\w+/', re.I),
     "T1053.003", "Cron (Persistence)", "Persistence", "TA0003", 0.9),

    (re.compile(r'/etc/systemd/system/.*\.service|systemctl\s+daemon-reload', re.I),
     "T1543.002", "Systemd Service", "Persistence", "TA0003", 0.9),

    (re.compile(r'LD_PRELOAD|/etc/ld\.so\.preload', re.I),
     "T1574.006", "Dynamic Linker Hijacking", "Persistence", "TA0003", 0.95),

    # =========================================================================
    # TA0004 - Privilege Escalation
    # =========================================================================
    (re.compile(r'\bsudo\b|\bsu\s+-\b|\bsu\s+root\b', re.I),
     "T1548.003", "Sudo and Sudo Caching", "Privilege Escalation", "TA0004", 0.7),

    (re.compile(r'find\s+.*-perm\s+[+-/]?[46][0-7]{3}|find.*suid|find.*-perm.*4000', re.I),
     "T1548.001", "Setuid and Setgid", "Privilege Escalation", "TA0004", 0.9),

    (re.compile(r'/etc/shadow|/etc/passwd.*:.*:\d+:0:', re.I),
     "T1003.008", "Unshadowed Credentials", "Credential Access", "TA0006", 0.85),

    (re.compile(r'kernel.*exploit|dirty.*cow|dirty.*pipe|CVE-\d{4}', re.I),
     "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation", "TA0004", 0.95),

    (re.compile(r'getcap|setcap|capabilities', re.I),
     "T1548", "Abuse Elevation Control (Capabilities)", "Privilege Escalation", "TA0004", 0.8),

    # =========================================================================
    # TA0005 - Defense Evasion
    # =========================================================================
    (re.compile(r'history\s+-[cdw]|unset\s+HISTFILE|HISTSIZE=0|export\s+HISTFILE=/dev/null', re.I),
     "T1070.003", "Clear Command History", "Defense Evasion", "TA0005", 0.95),

    (re.compile(r'\brm\s+.*\.(log|history|bash_history)', re.I),
     "T1070.002", "Clear Linux or Mac System Logs", "Defense Evasion", "TA0005", 0.9),

    (re.compile(r'iptables\s+-[AIFDR]|ufw\s+(disable|allow|delete)', re.I),
     "T1562.004", "Disable or Modify System Firewall", "Defense Evasion", "TA0005", 0.9),

    (re.compile(r'systemctl\s+(stop|disable|mask)\s+(auditd|rsyslog|syslog|apparmor|selinux)', re.I),
     "T1562.001", "Disable or Modify Tools", "Defense Evasion", "TA0005", 0.95),

    (re.compile(r'touch\s+-[trad]|timestomp', re.I),
     "T1070.006", "Timestomp", "Defense Evasion", "TA0005", 0.9),

    (re.compile(r'base64\s+-d|base64\s+--decode|openssl\s+enc', re.I),
     "T1140", "Deobfuscate/Decode Files", "Defense Evasion", "TA0005", 0.8),

    (re.compile(r'chattr\s+\+i|chattr\s+\+a', re.I),
     "T1222.002", "Linux File Permissions Modification", "Defense Evasion", "TA0005", 0.85),

    # =========================================================================
    # TA0006 - Credential Access
    # =========================================================================
    (re.compile(r'cat\s+/etc/shadow|/etc/passwd|/etc/security', re.I),
     "T1003.008", "/etc/passwd and /etc/shadow", "Credential Access", "TA0006", 0.9),

    (re.compile(r'\b(mimikatz|lazagne|hashcat|john)\b', re.I),
     "T1003", "OS Credential Dumping", "Credential Access", "TA0006", 0.95),

    (re.compile(r'find.*\.(pem|key|p12|pfx|jks)|grep.*password.*-r', re.I),
     "T1552.004", "Private Keys", "Credential Access", "TA0006", 0.85),

    (re.compile(r'aws\s+configure|\.aws/credentials|AWS_ACCESS_KEY', re.I),
     "T1552.005", "Cloud Instance Metadata API", "Credential Access", "TA0006", 0.9),

    (re.compile(r'169\.254\.169\.254|metadata\.google|metadata\.azure', re.I),
     "T1552.005", "Cloud Instance Metadata API", "Credential Access", "TA0006", 0.95),

    # =========================================================================
    # TA0007 - Discovery
    # =========================================================================
    (re.compile(r'\buname\s+-a\b|\bhostname\b|\bcat\s+/etc/(os-release|issue|hostname)', re.I),
     "T1082", "System Information Discovery", "Discovery", "TA0007", 0.8),

    (re.compile(r'\bwhoami\b|\bid\b|\bgroups\b', re.I),
     "T1033", "System Owner/User Discovery", "Discovery", "TA0007", 0.75),

    (re.compile(r'\bifconfig\b|\bip\s+(addr|a|route|r)\b|\bnetstat\b|\bss\s+-', re.I),
     "T1016", "System Network Configuration Discovery", "Discovery", "TA0007", 0.8),

    (re.compile(r'\bps\s+(aux|ef|fax)\b|\btop\b|\bhtop\b', re.I),
     "T1057", "Process Discovery", "Discovery", "TA0007", 0.75),

    (re.compile(r'\bfind\s+/\b|\bls\s+-[laR].*(/etc|/var|/opt|/home)\b', re.I),
     "T1083", "File and Directory Discovery", "Discovery", "TA0007", 0.7),

    (re.compile(r'\bcat\s+/etc/hosts\b|\bnslookup\b|\bdig\b|\bhost\s+\w', re.I),
     "T1018", "Remote System Discovery", "Discovery", "TA0007", 0.8),

    (re.compile(r'\bdf\s+-[hT]\b|\blsblk\b|\bfdisk\s+-l\b|\bmount\b', re.I),
     "T1082", "System Information Discovery (Storage)", "Discovery", "TA0007", 0.7),

    (re.compile(r'\benv\b|\bprintenv\b|\bset\b.*export', re.I),
     "T1082", "System Information Discovery (Env)", "Discovery", "TA0007", 0.65),

    (re.compile(r'cat\s+/proc/(version|cpuinfo|meminfo)|lscpu|free\s+-', re.I),
     "T1082", "System Information Discovery (Hardware)", "Discovery", "TA0007", 0.7),

    (re.compile(r'arp\s+-[an]|ip\s+neigh', re.I),
     "T1016.001", "Internet Connection Discovery", "Discovery", "TA0007", 0.8),

    (re.compile(r'last\b|lastlog\b|who\b|w\b|users\b', re.I),
     "T1033", "System Owner/User Discovery (Login)", "Discovery", "TA0007", 0.7),

    # =========================================================================
    # TA0008 - Lateral Movement
    # =========================================================================
    (re.compile(r'\bssh\s+\w+@|sshpass\b|ssh-copy-id\b', re.I),
     "T1021.004", "SSH", "Lateral Movement", "TA0008", 0.9),

    (re.compile(r'\bnmap\b|\bmasscan\b|\bzmap\b', re.I),
     "T1046", "Network Service Discovery (Scanning)", "Discovery", "TA0007", 0.9),

    (re.compile(r'smbclient|rpcclient|psexec|wmiexec|evil-winrm', re.I),
     "T1021.002", "SMB/Windows Admin Shares", "Lateral Movement", "TA0008", 0.9),

    # =========================================================================
    # TA0009 - Collection
    # =========================================================================
    (re.compile(r'\btar\s+[cxz].*\.(tar|gz|tgz|zip|bz2)\b', re.I),
     "T1560.001", "Archive via Utility", "Collection", "TA0009", 0.8),

    (re.compile(r'find.*-name.*\.(doc|pdf|xls|sql|csv|conf|key|pem)', re.I),
     "T1005", "Data from Local System", "Collection", "TA0009", 0.85),

    (re.compile(r'mysqldump|pg_dump|mongodump', re.I),
     "T1005", "Data from Local System (Database)", "Collection", "TA0009", 0.9),

    # =========================================================================
    # TA0010 - Exfiltration
    # =========================================================================
    (re.compile(r'\bcurl\s+.*-[dFT].*http|wget\s+--post', re.I),
     "T1048.003", "Exfiltration Over Unencrypted Protocol", "Exfiltration", "TA0010", 0.85),

    (re.compile(r'\bscp\s+.*@|rsync\s+.*@|\bsftp\b', re.I),
     "T1048.002", "Exfiltration Over Asymmetric Encrypted Channel", "Exfiltration", "TA0010", 0.85),

    (re.compile(r'nc\s+-[wlp].*<|/dev/tcp/', re.I),
     "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "TA0010", 0.9),

    # =========================================================================
    # TA0011 - Command and Control
    # =========================================================================
    (re.compile(r'\bnc\s+-[elp]|\bncat\b.*-[el]|\bsocat\b', re.I),
     "T1095", "Non-Application Layer Protocol", "Command and Control", "TA0011", 0.9),

    (re.compile(r'bash\s+-i\s+>&\s*/dev/tcp|python.*socket.*connect', re.I),
     "T1071.001", "Web Protocols (Reverse Shell)", "Command and Control", "TA0011", 0.95),

    (re.compile(r'\bwget\b.*\.(sh|py|pl|elf|bin)\b|\bcurl\b.*\|.*sh\b', re.I),
     "T1105", "Ingress Tool Transfer", "Command and Control", "TA0011", 0.9),

    (re.compile(r'tor|proxychains|socks[45]|chisel|frp|ngrok', re.I),
     "T1090", "Proxy", "Command and Control", "TA0011", 0.9),

    # =========================================================================
    # TA0040 - Impact
    # =========================================================================
    (re.compile(r'\brm\s+-rf\s+/|\bmkfs\b|\bdd\s+if=/dev/(zero|urandom)\s+of=/', re.I),
     "T1485", "Data Destruction", "Impact", "TA0040", 0.95),

    (re.compile(r'openssl\s+enc.*-aes|gpg\s+--encrypt|7z\s+a\s+-p', re.I),
     "T1486", "Data Encrypted for Impact", "Impact", "TA0040", 0.9),

    (re.compile(r'xmrig|minerd|cryptonight|stratum\+tcp|monero', re.I),
     "T1496", "Resource Hijacking (Cryptomining)", "Impact", "TA0040", 0.95),

    (re.compile(r':(){ :\|:& };:|fork\s*bomb|stress\s+-|hping3', re.I),
     "T1499", "Endpoint Denial of Service", "Impact", "TA0040", 0.9),
]


class MITREClassifier:
    """
    MITRE ATT&CK classification engine.
    Analyzes attacker commands and maps them to ATT&CK techniques
    in real-time. Builds a kill chain analysis per session.
    """

    def __init__(self):
        # Track techniques per session for kill chain analysis
        self._session_chains: Dict[str, AttackChainAnalysis] = {}

    def classify_command(
        self, command: str, session_id: str = ""
    ) -> List[ATTACKTechnique]:
        """
        Classify a single command against MITRE ATT&CK techniques.

        Args:
            command: The raw attacker command string.
            session_id: The session ID for kill chain tracking.

        Returns:
            List of matching ATTACKTechnique objects.
        """
        matches = []

        for pattern, tech_id, tech_name, tactic, tactic_id, confidence in TECHNIQUE_PATTERNS:
            if pattern.search(command):
                technique = ATTACKTechnique(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    tactic_id=tactic_id,
                    confidence=confidence,
                    data_source=command[:200],
                )
                matches.append(technique)

        # Update session kill chain
        if session_id and matches:
            self._update_chain(session_id, matches)

        if matches:
            logger.info(
                f"[MITRE] Command classified: {len(matches)} technique(s) matched "
                f"for: {command[:80]}"
            )

        return matches

    def _update_chain(
        self, session_id: str, techniques: List[ATTACKTechnique]
    ) -> None:
        """Update the kill chain analysis for a session."""
        if session_id not in self._session_chains:
            self._session_chains[session_id] = AttackChainAnalysis(
                session_id=session_id
            )

        chain = self._session_chains[session_id]
        chain.techniques.extend(techniques)

        # Update kill chain phases
        for tech in techniques:
            if tech.tactic not in chain.kill_chain_phases:
                chain.kill_chain_phases.append(tech.tactic)

        # Recalculate sophistication
        chain.overall_sophistication = self._assess_sophistication(chain)

    def _assess_sophistication(self, chain: AttackChainAnalysis) -> str:
        """
        Assess the overall sophistication of an attack chain.
        Based on breadth of tactics, technique diversity, and specific indicators.
        """
        num_tactics = len(chain.kill_chain_phases)
        num_techniques = len(set(t.technique_id for t in chain.techniques))
        high_confidence = sum(1 for t in chain.techniques if t.confidence >= 0.9)

        # Advanced: Multiple tactics with high-confidence techniques
        if num_tactics >= 5 and high_confidence >= 4:
            return "advanced"
        # High: Multiple tactics or numerous techniques
        elif num_tactics >= 3 or num_techniques >= 5:
            return "high"
        # Medium: Some variety in techniques
        elif num_tactics >= 2 or num_techniques >= 3:
            return "medium"
        # Low: Basic scanning or single-technique usage
        else:
            return "low"

    def get_session_chain(self, session_id: str) -> Optional[AttackChainAnalysis]:
        """Get the full ATT&CK chain analysis for a session."""
        return self._session_chains.get(session_id)

    def get_session_summary(self, session_id: str) -> Dict:
        """Get a summary of ATT&CK activity for a session."""
        chain = self._session_chains.get(session_id)
        if not chain:
            return {"techniques_count": 0, "sophistication": "none"}
        return chain.to_dict()

    def get_global_stats(self) -> Dict:
        """Return global classification statistics."""
        all_techniques = []
        for chain in self._session_chains.values():
            all_techniques.extend(chain.techniques)

        technique_counts = {}
        tactic_counts = {}
        for t in all_techniques:
            technique_counts[t.technique_id] = technique_counts.get(t.technique_id, 0) + 1
            tactic_counts[t.tactic] = tactic_counts.get(t.tactic, 0) + 1

        return {
            "total_sessions_analyzed": len(self._session_chains),
            "total_techniques_detected": len(all_techniques),
            "unique_techniques": len(technique_counts),
            "top_techniques": sorted(
                technique_counts.items(), key=lambda x: x[1], reverse=True
            )[:10],
            "tactic_distribution": tactic_counts,
        }

    def clear_session(self, session_id: str) -> None:
        """Remove session data when a session ends."""
        self._session_chains.pop(session_id, None)


# =============================================================================
# Module-level singleton
# =============================================================================
mitre_classifier = MITREClassifier()
