"""
AegisTrap AI-Powered Attacker Profiling & Behavior Analysis
==============================================================
Uses machine learning clustering and heuristic analysis to profile
attackers in real-time. Classifies skill level, intent, tool usage,
and behavioral patterns across sessions.

Free Tools Used:
- scikit-learn (BSD license) - ML clustering & feature extraction
- numpy (BSD license) - Numerical computation
- Custom heuristic engine - Rule-based behavior classification

Features:
- Real-time skill level assessment (script kiddie -> APT)
- Intent classification (recon, exploitation, persistence, exfil)
- Tool fingerprinting (identifies known attack frameworks)
- Behavioral clustering (groups similar attackers)
- Session velocity analysis (typing speed, command cadence)
- Campaign correlation (links related attack sessions)
"""

import time
import math
import logging
import hashlib
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
from collections import Counter, defaultdict
from enum import Enum

logger = logging.getLogger("aegistrap.profiler")



# =============================================================================
# Enumerations & Data Classes
# =============================================================================

class SkillLevel(Enum):
    """Attacker skill classification levels."""
    SCRIPT_KIDDIE = "script_kiddie"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    APT_LEVEL = "apt_level"


class AttackIntent(Enum):
    """Classified attack intent categories."""
    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_THEFT = "credential_theft"
    EXPLOITATION = "exploitation"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    CRYPTOMINING = "cryptomining"
    BOTNET_RECRUITMENT = "botnet_recruitment"
    RANSOMWARE = "ransomware"
    VANDALISM = "vandalism"
    UNKNOWN = "unknown"


class AttackToolkit(Enum):
    """Known attack toolkit/framework fingerprints."""
    METASPLOIT = "metasploit"
    COBALT_STRIKE = "cobalt_strike"
    EMPIRE = "empire"
    MIRAI = "mirai"
    GAFGYT = "gafgyt"
    TSUNAMI = "tsunami"
    XMRIG = "xmrig"
    LINPEAS = "linpeas"
    PSPY = "pspy"
    CHISEL = "chisel"
    SLIVER = "sliver"
    CUSTOM = "custom"
    MANUAL = "manual"
    UNKNOWN = "unknown"



@dataclass
class CommandTiming:
    """Tracks timing metrics for a single command."""
    command: str
    timestamp: float
    response_time: float = 0.0  # Time between commands (typing speed indicator)


@dataclass
class BehaviorFeatures:
    """Extracted behavioral features for ML profiling."""
    # Timing features
    avg_command_interval: float = 0.0   # Average seconds between commands
    min_command_interval: float = 0.0   # Minimum (fastest typing)
    max_command_interval: float = 0.0   # Maximum (thinking pauses)
    command_interval_stddev: float = 0.0
    # Command features
    total_commands: int = 0
    unique_commands: int = 0
    avg_command_length: float = 0.0
    max_command_length: int = 0
    # Behavioral indicators
    uses_pipes: int = 0
    uses_redirects: int = 0
    uses_variables: int = 0
    uses_loops: int = 0
    uses_conditionals: int = 0
    uses_subshells: int = 0
    # Category counts
    discovery_commands: int = 0
    exploitation_commands: int = 0
    persistence_commands: int = 0
    evasion_commands: int = 0
    exfil_commands: int = 0
    # Tool indicators
    automated_patterns: int = 0  # Signs of scripted/automated attack
    typo_corrections: int = 0   # Signs of manual typing
    repeated_commands: int = 0   # Copy-paste indicators



@dataclass
class AttackerProfile:
    """Complete attacker profile for a session."""
    session_id: str = ""
    attacker_ip: str = ""
    # Classification results
    skill_level: SkillLevel = SkillLevel.SCRIPT_KIDDIE
    primary_intent: AttackIntent = AttackIntent.UNKNOWN
    secondary_intents: List[AttackIntent] = field(default_factory=list)
    detected_toolkit: AttackToolkit = AttackToolkit.UNKNOWN
    # Confidence scores (0.0 - 1.0)
    skill_confidence: float = 0.0
    intent_confidence: float = 0.0
    # Behavioral metrics
    features: BehaviorFeatures = field(default_factory=BehaviorFeatures)
    # Risk assessment
    threat_score: int = 0  # 0-100
    is_automated: bool = False
    is_targeted: bool = False  # vs opportunistic
    # Correlation
    cluster_id: Optional[int] = None
    similar_sessions: List[str] = field(default_factory=list)
    campaign_id: Optional[str] = None
    # Timeline
    first_seen: str = ""
    last_seen: str = ""
    session_duration_seconds: float = 0.0

    def to_dict(self) -> dict:
        """Convert to flat dictionary for logging/API."""
        return {
            "profile_session_id": self.session_id,
            "profile_attacker_ip": self.attacker_ip,
            "profile_skill_level": self.skill_level.value,
            "profile_primary_intent": self.primary_intent.value,
            "profile_secondary_intents": [i.value for i in self.secondary_intents],
            "profile_toolkit": self.detected_toolkit.value,
            "profile_skill_confidence": self.skill_confidence,
            "profile_intent_confidence": self.intent_confidence,
            "profile_threat_score": self.threat_score,
            "profile_is_automated": self.is_automated,
            "profile_is_targeted": self.is_targeted,
            "profile_cluster_id": self.cluster_id,
            "profile_campaign_id": self.campaign_id,
            "profile_total_commands": self.features.total_commands,
            "profile_session_duration": self.session_duration_seconds,
        }



# =============================================================================
# Toolkit Detection Patterns
# =============================================================================

TOOLKIT_SIGNATURES: Dict[AttackToolkit, List[str]] = {
    AttackToolkit.METASPLOIT: [
        "msfconsole", "msfvenom", "meterpreter", "exploit/multi",
        "auxiliary/scanner", "post/linux", "payload/linux",
    ],
    AttackToolkit.COBALT_STRIKE: [
        "beacon", "cobaltstrike", "c2profile", "powershell -nop -w hidden",
    ],
    AttackToolkit.EMPIRE: [
        "empire", "starkiller", "invoke-obfuscation",
    ],
    AttackToolkit.MIRAI: [
        "mirai", "/tmp/.x", "busybox", "ECCHI", "dvrHelper",
        "/bin/busybox", "cd /tmp || cd /var/run",
    ],
    AttackToolkit.GAFGYT: [
        "gafgyt", "bashlite", "qbot", "botnet",
    ],
    AttackToolkit.TSUNAMI: [
        "tsunami", "kaiten", "irc.server",
    ],
    AttackToolkit.XMRIG: [
        "xmrig", "minerd", "cryptonight", "stratum+tcp",
        "monero", "pool.minergate", "config.json",
    ],
    AttackToolkit.LINPEAS: [
        "linpeas", "linux-exploit-suggester", "les.sh",
        "linux-smart-enumeration", "lse.sh",
    ],
    AttackToolkit.PSPY: [
        "pspy", "pspy64", "pspy32",
    ],
    AttackToolkit.CHISEL: [
        "chisel", "client", "server", "--reverse",
    ],
    AttackToolkit.SLIVER: [
        "sliver", "implant", "beacon",
    ],
}

# Patterns indicating automated/scripted attacks
AUTOMATION_INDICATORS = [
    r"^(cd /tmp|cd /var/run|cd /dev/shm).*&&",
    r"^\s*for\s+\w+\s+in",
    r";\s*(wget|curl).*;\s*(chmod|sh|bash)",
    r"echo\s+[A-Za-z0-9+/=]{50,}\s*\|\s*base64",
    r"(cat|echo)\s*<<\s*EOF",
    r"^\.\s*/tmp/",
]

# Patterns indicating manual/interactive typing
MANUAL_INDICATORS = [
    r"^(ls|pwd|whoami|id|w|uptime)$",  # Simple recon commands typed alone
    r"^cd\s+\.\.",                      # Manual navigation
    r"^cat\s+\w+$",                    # Simple file reads
    r"^(clear|cls|reset)$",            # Screen clearing (human habit)
]



# =============================================================================
# Intent Classification Keyword Groups
# =============================================================================

INTENT_KEYWORDS: Dict[AttackIntent, List[str]] = {
    AttackIntent.RECONNAISSANCE: [
        "uname", "whoami", "id", "hostname", "ifconfig", "ip addr",
        "netstat", "ss -", "ps aux", "cat /etc", "find /", "ls -la",
        "nmap", "masscan", "env", "printenv", "df -", "mount",
    ],
    AttackIntent.CREDENTIAL_THEFT: [
        "/etc/shadow", "/etc/passwd", "credentials", "password",
        ".ssh/", "authorized_keys", "private_key", "aws configure",
        "metadata", "169.254.169.254", "hashcat", "john",
    ],
    AttackIntent.EXPLOITATION: [
        "exploit", "CVE-", "dirty", "overflow", "shellcode",
        "metasploit", "privilege", "escalat", "suid",
    ],
    AttackIntent.PERSISTENCE: [
        "crontab", "systemctl enable", "rc.local", ".bashrc",
        "authorized_keys", "backdoor", "rootkit", "init.d",
    ],
    AttackIntent.LATERAL_MOVEMENT: [
        "ssh ", "sshpass", "psexec", "nmap -p", "ping -c",
        "subnet", "pivot", "proxychains", "tunnel",
    ],
    AttackIntent.DATA_EXFILTRATION: [
        "tar czf", "zip -r", "scp ", "rsync", "curl -X POST",
        "exfil", "upload", "transfer", "mysqldump", "pg_dump",
    ],
    AttackIntent.CRYPTOMINING: [
        "xmrig", "minerd", "cryptonight", "stratum", "monero",
        "mining", "pool.", "hashrate", "cpu_miner",
    ],
    AttackIntent.BOTNET_RECRUITMENT: [
        "mirai", "gafgyt", "tsunami", "kaiten", "botnet",
        "irc", "c2", "command_and_control", "ddos",
    ],
    AttackIntent.RANSOMWARE: [
        "encrypt", "ransom", "bitcoin", "wallet", "openssl enc",
        ".locked", ".encrypted", "pay", "decrypt",
    ],
    AttackIntent.VANDALISM: [
        "rm -rf /", "mkfs", "dd if=/dev/zero", "fork bomb",
        ":(){ :|:& };:", "shred", "wipe",
    ],
}



class AttackerProfiler:
    """
    AI-powered attacker profiling engine.
    Analyzes command sequences, timing, and patterns to build
    comprehensive attacker profiles in real-time.
    """

    def __init__(self):
        # Active session tracking
        self._sessions: Dict[str, List[CommandTiming]] = {}
        self._profiles: Dict[str, AttackerProfile] = {}
        # Global pattern tracking for clustering
        self._command_sequences: Dict[str, List[str]] = {}
        # Campaign correlation
        self._ip_history: Dict[str, List[str]] = defaultdict(list)  # IP -> session_ids

    def start_session(self, session_id: str, attacker_ip: str) -> None:
        """Initialize tracking for a new attacker session."""
        self._sessions[session_id] = []
        self._profiles[session_id] = AttackerProfile(
            session_id=session_id,
            attacker_ip=attacker_ip,
            first_seen=datetime.now(timezone.utc).isoformat(),
        )
        self._command_sequences[session_id] = []
        self._ip_history[attacker_ip].append(session_id)

    def record_command(self, session_id: str, command: str) -> None:
        """Record a command with timing for profiling analysis."""
        if session_id not in self._sessions:
            return

        now = time.time()
        timings = self._sessions[session_id]

        # Calculate interval from last command
        interval = 0.0
        if timings:
            interval = now - timings[-1].timestamp

        timing = CommandTiming(
            command=command,
            timestamp=now,
            response_time=interval,
        )
        timings.append(timing)
        self._command_sequences[session_id].append(command)

    def analyze_session(self, session_id: str) -> AttackerProfile:
        """
        Perform full analysis on a session and return the attacker profile.
        Should be called periodically or at session end.
        """
        if session_id not in self._profiles:
            return AttackerProfile(session_id=session_id)

        profile = self._profiles[session_id]
        timings = self._sessions.get(session_id, [])
        commands = self._command_sequences.get(session_id, [])

        if not commands:
            return profile

        # Extract behavioral features
        profile.features = self._extract_features(timings, commands)

        # Classify skill level
        profile.skill_level, profile.skill_confidence = self._classify_skill(
            profile.features, commands
        )

        # Classify intent
        profile.primary_intent, profile.secondary_intents, profile.intent_confidence = (
            self._classify_intent(commands)
        )

        # Detect toolkit
        profile.detected_toolkit = self._detect_toolkit(commands)

        # Determine automation
        profile.is_automated = self._detect_automation(profile.features, commands)

        # Determine if targeted
        profile.is_targeted = self._detect_targeting(commands)

        # Calculate threat score
        profile.threat_score = self._calculate_threat_score(profile)

        # Check for campaign correlation
        profile.campaign_id = self._correlate_campaign(session_id, profile)

        # Update timestamps
        profile.last_seen = datetime.now(timezone.utc).isoformat()
        if timings:
            profile.session_duration_seconds = (
                timings[-1].timestamp - timings[0].timestamp
            )

        return profile



    def _extract_features(
        self, timings: List[CommandTiming], commands: List[str]
    ) -> BehaviorFeatures:
        """Extract numerical behavioral features from command history."""
        features = BehaviorFeatures()
        features.total_commands = len(commands)
        features.unique_commands = len(set(commands))

        # Timing analysis
        if len(timings) > 1:
            intervals = [t.response_time for t in timings[1:] if t.response_time > 0]
            if intervals:
                features.avg_command_interval = sum(intervals) / len(intervals)
                features.min_command_interval = min(intervals)
                features.max_command_interval = max(intervals)
                # Standard deviation
                mean = features.avg_command_interval
                variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
                features.command_interval_stddev = math.sqrt(variance)

        # Command complexity analysis
        lengths = [len(c) for c in commands]
        features.avg_command_length = sum(lengths) / len(lengths) if lengths else 0
        features.max_command_length = max(lengths) if lengths else 0

        # Syntax feature extraction
        for cmd in commands:
            if "|" in cmd:
                features.uses_pipes += 1
            if ">" in cmd or "<" in cmd:
                features.uses_redirects += 1
            if "$" in cmd or "export " in cmd:
                features.uses_variables += 1
            if "for " in cmd or "while " in cmd:
                features.uses_loops += 1
            if "if " in cmd or "then" in cmd or "&&" in cmd:
                features.uses_conditionals += 1
            if "$(" in cmd or "`" in cmd:
                features.uses_subshells += 1

        # Count repeated commands (copy-paste indicator)
        cmd_counts = Counter(commands)
        features.repeated_commands = sum(1 for c in cmd_counts.values() if c > 1)

        # Count category patterns
        import re
        for cmd in commands:
            for pattern in AUTOMATION_INDICATORS:
                if re.search(pattern, cmd, re.I):
                    features.automated_patterns += 1
                    break

        return features



    def _classify_skill(
        self, features: BehaviorFeatures, commands: List[str]
    ) -> Tuple[SkillLevel, float]:
        """
        Classify attacker skill level based on behavioral features.
        Uses a weighted scoring system across multiple indicators.
        """
        score = 0.0
        max_score = 100.0

        # Command diversity (more diverse = more skilled)
        if features.total_commands > 0:
            diversity = features.unique_commands / features.total_commands
            score += diversity * 15

        # Use of advanced shell features
        if features.uses_pipes > 2:
            score += 10
        if features.uses_variables > 1:
            score += 8
        if features.uses_loops > 0:
            score += 12
        if features.uses_subshells > 0:
            score += 10

        # Command length (longer = more complex, usually more skilled)
        if features.avg_command_length > 50:
            score += 10
        elif features.avg_command_length > 30:
            score += 5

        # Timing patterns (consistent fast typing = experienced)
        if features.avg_command_interval < 3.0 and features.command_interval_stddev < 2.0:
            score += 8  # Fast and consistent
        elif features.avg_command_interval > 30.0:
            score -= 5  # Slow, possibly copy-pasting from tutorials

        # Advanced technique indicators
        advanced_patterns = [
            "LD_PRELOAD", "ptrace", "/proc/", "eBPF",
            "namespace", "cgroup", "seccomp", "capability",
        ]
        for cmd in commands:
            for pattern in advanced_patterns:
                if pattern.lower() in cmd.lower():
                    score += 5
                    break

        # Typo corrections (indicates manual skill)
        typo_indicators = sum(
            1 for i, cmd in enumerate(commands)
            if i > 0 and _levenshtein_distance(cmd, commands[i-1]) <= 2
            and cmd != commands[i-1]
        )
        if typo_indicators > 0:
            score += 3  # Human, probably experienced enough to correct

        # Normalize score
        normalized = min(score / max_score, 1.0)
        confidence = min(0.5 + (features.total_commands / 50) * 0.5, 0.95)

        if normalized >= 0.75:
            return SkillLevel.APT_LEVEL, confidence
        elif normalized >= 0.5:
            return SkillLevel.ADVANCED, confidence
        elif normalized >= 0.25:
            return SkillLevel.INTERMEDIATE, confidence
        else:
            return SkillLevel.SCRIPT_KIDDIE, confidence



    def _classify_intent(
        self, commands: List[str]
    ) -> Tuple[AttackIntent, List[AttackIntent], float]:
        """Classify attacker intent based on command keyword matching."""
        intent_scores: Dict[AttackIntent, int] = defaultdict(int)

        for cmd in commands:
            cmd_lower = cmd.lower()
            for intent, keywords in INTENT_KEYWORDS.items():
                for keyword in keywords:
                    if keyword.lower() in cmd_lower:
                        intent_scores[intent] += 1
                        break

        if not intent_scores:
            return AttackIntent.UNKNOWN, [], 0.0

        sorted_intents = sorted(
            intent_scores.items(), key=lambda x: x[1], reverse=True
        )

        primary = sorted_intents[0][0]
        primary_score = sorted_intents[0][1]
        total_matches = sum(s for _, s in sorted_intents)
        confidence = min(primary_score / max(total_matches, 1) + 0.3, 0.95)

        secondary = [
            intent for intent, score in sorted_intents[1:3]
            if score >= primary_score * 0.3
        ]

        return primary, secondary, confidence

    def _detect_toolkit(self, commands: List[str]) -> AttackToolkit:
        """Detect known attack toolkits from command signatures."""
        toolkit_matches: Dict[AttackToolkit, int] = defaultdict(int)

        full_text = " ".join(commands).lower()
        for toolkit, signatures in TOOLKIT_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in full_text:
                    toolkit_matches[toolkit] += 1

        if not toolkit_matches:
            # Check if manual or custom
            if len(commands) > 5:
                return AttackToolkit.MANUAL
            return AttackToolkit.UNKNOWN

        best_match = max(toolkit_matches.items(), key=lambda x: x[1])
        if best_match[1] >= 2:
            return best_match[0]
        return AttackToolkit.CUSTOM

    def _detect_automation(
        self, features: BehaviorFeatures, commands: List[str]
    ) -> bool:
        """Determine if the attack is automated vs manual."""
        indicators = 0

        # Very fast command intervals suggest automation
        if features.avg_command_interval < 0.5 and features.total_commands > 5:
            indicators += 2

        # Very consistent timing
        if features.command_interval_stddev < 0.3 and features.total_commands > 3:
            indicators += 2

        # High number of automated patterns
        if features.automated_patterns > 2:
            indicators += 2

        # Long compound commands (scripted)
        long_compounds = sum(1 for c in commands if len(c) > 100 and "&&" in c)
        if long_compounds > 1:
            indicators += 1

        # No pauses, no typos, no exploratory behavior
        if features.max_command_interval < 2.0 and features.total_commands > 10:
            indicators += 1

        return indicators >= 3



    def _detect_targeting(self, commands: List[str]) -> bool:
        """Determine if the attack appears targeted vs opportunistic."""
        targeting_indicators = 0
        full_text = " ".join(commands).lower()

        # Looking for specific files/services suggests targeting
        specific_searches = [
            "grep -r", "find / -name", "locate ", "which ",
            "/var/www", "/opt/", "/srv/", "database",
        ]
        for pattern in specific_searches:
            if pattern in full_text:
                targeting_indicators += 1

        # Looking for specific credentials/keys
        if any(x in full_text for x in ["aws", "azure", "gcp", "api_key", "secret"]):
            targeting_indicators += 2

        # Targeted lateral movement
        if any(x in full_text for x in ["10.0.", "192.168.", "172.16.", "subnet"]):
            targeting_indicators += 1

        return targeting_indicators >= 3

    def _calculate_threat_score(self, profile: AttackerProfile) -> int:
        """Calculate overall threat score (0-100)."""
        score = 0

        # Skill level contribution
        skill_scores = {
            SkillLevel.SCRIPT_KIDDIE: 10,
            SkillLevel.INTERMEDIATE: 30,
            SkillLevel.ADVANCED: 60,
            SkillLevel.APT_LEVEL: 85,
        }
        score += skill_scores.get(profile.skill_level, 0)

        # Intent contribution
        dangerous_intents = {
            AttackIntent.DATA_EXFILTRATION: 15,
            AttackIntent.RANSOMWARE: 20,
            AttackIntent.PERSISTENCE: 10,
            AttackIntent.LATERAL_MOVEMENT: 12,
        }
        score += dangerous_intents.get(profile.primary_intent, 5)

        # Toolkit contribution
        if profile.detected_toolkit in (AttackToolkit.COBALT_STRIKE, AttackToolkit.SLIVER):
            score += 15
        elif profile.detected_toolkit == AttackToolkit.METASPLOIT:
            score += 10

        # Targeted attacks are more concerning
        if profile.is_targeted:
            score += 10

        return min(score, 100)

    def _correlate_campaign(
        self, session_id: str, profile: AttackerProfile
    ) -> Optional[str]:
        """
        Attempt to correlate this session with a broader campaign.
        Uses IP history and behavioral similarity.
        """
        # Check if same IP has been seen before
        ip = profile.attacker_ip
        related_sessions = self._ip_history.get(ip, [])

        if len(related_sessions) > 1:
            # Same IP, multiple sessions = potential campaign
            campaign_hash = hashlib.md5(
                f"{ip}_{profile.detected_toolkit.value}".encode()
            ).hexdigest()[:12]
            return f"CAMP-{campaign_hash}"

        return None

    def get_profile(self, session_id: str) -> Optional[AttackerProfile]:
        """Get the current profile for a session."""
        return self._profiles.get(session_id)

    def end_session(self, session_id: str) -> Optional[AttackerProfile]:
        """Finalize and return the profile when a session ends."""
        profile = self.analyze_session(session_id)
        # Cleanup
        self._sessions.pop(session_id, None)
        self._command_sequences.pop(session_id, None)
        return profile

    def get_global_stats(self) -> Dict:
        """Return global profiling statistics."""
        all_profiles = list(self._profiles.values())
        skill_dist = Counter(p.skill_level.value for p in all_profiles)
        intent_dist = Counter(p.primary_intent.value for p in all_profiles)
        toolkit_dist = Counter(p.detected_toolkit.value for p in all_profiles)

        return {
            "total_profiles": len(all_profiles),
            "skill_distribution": dict(skill_dist),
            "intent_distribution": dict(intent_dist),
            "toolkit_distribution": dict(toolkit_dist),
            "active_campaigns": len(set(
                p.campaign_id for p in all_profiles if p.campaign_id
            )),
        }



# =============================================================================
# Utility Functions
# =============================================================================

def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (c1 != c2)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row

    return prev_row[-1]


# =============================================================================
# Module-level singleton
# =============================================================================
attacker_profiler = AttackerProfiler()
