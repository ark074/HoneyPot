"""
AegisTrap Adaptive AI Personality Engine
==========================================
Dynamically switches between multiple server personas based on
attacker behavior, service targeted, and profiling results.
Maximizes attacker engagement time by adapting the deception
to what the attacker expects to find.

Features:
- Multiple pre-built server personas (web server, database, IoT, etc.)
- Dynamic persona selection based on attacker behavior analysis
- Persona-specific filesystem layouts, command responses, and banners
- Behavior-triggered persona escalation (reveal more when probed deeper)
- Custom prompt injection per persona for Ollama LLM
- Engagement time optimization (keep attackers hooked longer)

This is a unique differentiator - most honeypots are static;
AegisTrap adapts in real-time to match attacker expectations.
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("aegistrap.personas")



# =============================================================================
# Persona Definitions
# =============================================================================

class PersonaType(Enum):
    """Available server persona types."""
    CORPORATE_UBUNTU = "corporate_ubuntu"
    WEB_SERVER_NGINX = "web_server_nginx"
    DATABASE_SERVER = "database_server"
    DOCKER_HOST = "docker_host"
    KUBERNETES_NODE = "kubernetes_node"
    IOT_DEVICE = "iot_device"
    CI_CD_RUNNER = "ci_cd_runner"
    MAIL_SERVER = "mail_server"
    FILE_SERVER = "file_server"
    DEV_WORKSTATION = "dev_workstation"


@dataclass
class PersonaConfig:
    """Configuration for a single server persona."""
    persona_type: PersonaType
    name: str
    description: str
    # System identity
    hostname: str = "server"
    os_version: str = "Ubuntu 22.04.3 LTS"
    kernel: str = "5.15.0-91-generic"
    # LLM system prompt additions
    system_prompt_addon: str = ""
    # Default username
    default_user: str = "root"
    # Initial filesystem layout
    filesystem_layout: Dict[str, Optional[str]] = field(default_factory=dict)
    # Services that should appear running
    running_services: List[str] = field(default_factory=list)
    # Network configuration
    interfaces: Dict[str, str] = field(default_factory=dict)
    open_ports: List[int] = field(default_factory=list)
    # Engagement hooks (juicy things for attacker to find)
    engagement_hooks: List[str] = field(default_factory=list)
    # Trigger conditions (when to switch TO this persona)
    trigger_keywords: List[str] = field(default_factory=list)


# =============================================================================
# Pre-built Persona Library
# =============================================================================

PERSONA_LIBRARY: Dict[PersonaType, PersonaConfig] = {

    PersonaType.CORPORATE_UBUNTU: PersonaConfig(
        persona_type=PersonaType.CORPORATE_UBUNTU,
        name="Corporate Ubuntu Server",
        description="Standard corporate production server running web applications",
        hostname="corp-srv-prod-01",
        os_version="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        default_user="root",
        system_prompt_addon=(
            "This is a corporate production server at CorpNet Inc. "
            "It runs a Laravel PHP application with MySQL backend. "
            "There are multiple users: root, www-data, deploy, j.mitchell (sysadmin). "
            "The server has connections to internal services at 10.0.4.x subnet. "
            "There are database backups in /backups, deploy scripts in /opt/deploy, "
            "and the web application in /var/www/html. "
            "Show realistic /etc/passwd with these users. "
            "If asked about network, show connections to 10.0.4.5 (mysql), "
            "10.0.4.8 (redis), 10.0.4.11 (elasticsearch)."
        ),
        running_services=["nginx", "php8.1-fpm", "mysql", "redis-server", "cron", "sshd"],
        interfaces={"eth0": "10.0.4.17/24"},
        open_ports=[22, 80, 443, 3306, 6379],
        engagement_hooks=[
            "/var/www/html/.env contains database credentials",
            "/root/.bash_history shows recent admin commands",
            "/opt/deploy/deploy.sh has hardcoded API keys",
            "/backups/ contains recent database dumps",
        ],
        trigger_keywords=["web", "http", "nginx", "apache", "php", "laravel"],
    ),

    PersonaType.WEB_SERVER_NGINX: PersonaConfig(
        persona_type=PersonaType.WEB_SERVER_NGINX,
        name="High-Traffic Nginx Web Server",
        description="Nginx reverse proxy with multiple backend services",
        hostname="web-lb-prod-02",
        os_version="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        default_user="root",
        system_prompt_addon=(
            "This is a high-traffic Nginx load balancer and reverse proxy. "
            "It fronts 4 backend application servers. "
            "SSL certificates are in /etc/nginx/ssl/. "
            "Upstream configs in /etc/nginx/conf.d/ show internal backend IPs. "
            "Access logs show ~50k requests/hour. "
            "There's a WAF bypass in the config (commented out rule). "
            "Show realistic nginx configs and access patterns."
        ),
        running_services=["nginx", "certbot", "fail2ban", "node_exporter", "sshd"],
        interfaces={"eth0": "10.0.2.5/24", "eth1": "192.168.1.100/24"},
        open_ports=[22, 80, 443, 8443, 9100],
        engagement_hooks=[
            "/etc/nginx/ssl/ has wildcard certificates",
            "/etc/nginx/conf.d/ reveals backend IPs",
            "Access logs show API endpoints",
            "/root/.ssh/ has keys to backend servers",
        ],
        trigger_keywords=["nginx", "proxy", "ssl", "certificate", "upstream"],
    ),

    PersonaType.DATABASE_SERVER: PersonaConfig(
        persona_type=PersonaType.DATABASE_SERVER,
        name="Production Database Server",
        description="MySQL/PostgreSQL database with sensitive data",
        hostname="db-prod-master-01",
        os_version="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        default_user="root",
        system_prompt_addon=(
            "This is the primary production database server running MySQL 8.0 "
            "and PostgreSQL 15. Contains customer PII, payment records, and "
            "internal credentials. Replication is set up to db-prod-replica-01 "
            "(10.0.4.6). Automated backups run at 3 AM to S3. "
            "Show realistic database table listings with columns like "
            "users(id, email, password_hash, credit_card_last4, ssn_encrypted). "
            "The MySQL root password is in /root/.my.cnf. "
            "pg_hba.conf allows connections from 10.0.4.0/24."
        ),
        running_services=["mysql", "postgresql", "mysqld_exporter", "pg_bouncer", "sshd"],
        interfaces={"eth0": "10.0.4.5/24"},
        open_ports=[22, 3306, 5432, 6432, 9104],
        engagement_hooks=[
            "/root/.my.cnf has MySQL root credentials",
            "Database has users table with password hashes",
            "/var/backups/ has SQL dumps",
            "Replication credentials in MySQL config",
        ],
        trigger_keywords=["mysql", "postgres", "database", "sql", "dump", "backup"],
    ),

    PersonaType.DOCKER_HOST: PersonaConfig(
        persona_type=PersonaType.DOCKER_HOST,
        name="Docker Container Host",
        description="Docker host running multiple containerized services",
        hostname="docker-prod-03",
        os_version="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        default_user="root",
        system_prompt_addon=(
            "This is a Docker container host running 12 production containers. "
            "Docker socket is accessible. docker-compose files are in /opt/stacks/. "
            "Containers include: webapp, api, redis, postgres, elasticsearch, "
            "grafana, prometheus, nginx-proxy, certbot, worker, scheduler, mailhog. "
            "When 'docker ps' is run, show these containers with realistic ports. "
            "The Docker registry credentials are in /root/.docker/config.json. "
            "Some containers have mounted host volumes with secrets."
        ),
        running_services=["dockerd", "containerd", "docker-proxy", "sshd"],
        interfaces={"eth0": "10.0.3.15/24", "docker0": "172.17.0.1/16"},
        open_ports=[22, 2375, 2376, 8080, 9090, 3000],
        engagement_hooks=[
            "Docker socket is world-readable (container escape possible)",
            "/opt/stacks/ has docker-compose with secrets in env",
            "/root/.docker/config.json has registry auth",
            "Containers mount /etc/shadow from host",
        ],
        trigger_keywords=["docker", "container", "compose", "registry", "image"],
    ),

    PersonaType.KUBERNETES_NODE: PersonaConfig(
        persona_type=PersonaType.KUBERNETES_NODE,
        name="Kubernetes Worker Node",
        description="K8s node with access to cluster secrets and service accounts",
        hostname="k8s-worker-prod-07",
        os_version="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        default_user="root",
        system_prompt_addon=(
            "This is a Kubernetes worker node in a production cluster. "
            "kubelet is running, and this node has pods from the 'production', "
            "'monitoring', and 'kube-system' namespaces. "
            "The service account token is at /var/run/secrets/kubernetes.io/. "
            "/root/.kube/config has cluster-admin access. "
            "When kubectl commands are run, show realistic output with pods, "
            "deployments, secrets (base64 encoded), configmaps with DB passwords. "
            "Show etcd connection strings and TLS certs in /etc/kubernetes/."
        ),
        running_services=["kubelet", "kube-proxy", "containerd", "sshd"],
        interfaces={"eth0": "10.0.5.107/24", "cni0": "10.244.7.1/24"},
        open_ports=[22, 10250, 10255, 10256, 30000],
        engagement_hooks=[
            "Kubeconfig with cluster-admin role",
            "Service account tokens for API access",
            "Secrets with database passwords (base64)",
            "etcd certificates for direct access",
        ],
        trigger_keywords=["kubectl", "kubernetes", "k8s", "pod", "namespace", "helm"],
    ),

    PersonaType.IOT_DEVICE: PersonaConfig(
        persona_type=PersonaType.IOT_DEVICE,
        name="IoT Gateway / Embedded Device",
        description="ARM-based IoT gateway with weak security",
        hostname="iot-gateway-01",
        os_version="Buildroot 2023.02",
        kernel="5.10.0-armv7l",
        default_user="admin",
        system_prompt_addon=(
            "This is an ARM-based IoT gateway device running BusyBox Linux. "
            "It has limited commands (BusyBox applets). The filesystem is small. "
            "It controls industrial sensors and actuators via MQTT. "
            "Default credentials were never changed. "
            "Show BusyBox-style command outputs (shorter, simpler). "
            "/etc/config/ has MQTT broker credentials and API tokens. "
            "The device has a web interface on port 8080 (admin:admin). "
            "Network shows connections to MQTT broker at 10.0.10.1:1883."
        ),
        running_services=["telnetd", "httpd", "mosquitto", "sshd"],
        interfaces={"eth0": "10.0.10.50/24"},
        open_ports=[22, 23, 80, 1883, 8080],
        engagement_hooks=[
            "Default credentials (admin:admin) everywhere",
            "MQTT broker with no auth",
            "/etc/config/mqtt.conf has broker keys",
            "Can reach industrial SCADA network",
        ],
        trigger_keywords=["busybox", "iot", "mqtt", "sensor", "embedded", "arm"],
    ),

    PersonaType.CI_CD_RUNNER: PersonaConfig(
        persona_type=PersonaType.CI_CD_RUNNER,
        name="CI/CD Build Runner",
        description="Jenkins/GitLab runner with deployment credentials",
        hostname="ci-runner-prod-04",
        os_version="Ubuntu 22.04.3 LTS",
        kernel="5.15.0-91-generic",
        default_user="jenkins",
        system_prompt_addon=(
            "This is a CI/CD build runner (Jenkins agent). "
            "It has credentials for deploying to production. "
            "/var/lib/jenkins/ has build artifacts and credentials. "
            "Environment variables contain AWS keys, Docker registry tokens, "
            "and SSH keys for production deployment. "
            "Show typical CI/CD artifacts, Jenkinsfile contents, and "
            "deployment scripts with embedded secrets."
        ),
        running_services=["jenkins-agent", "docker", "sshd", "node_exporter"],
        interfaces={"eth0": "10.0.6.40/24"},
        open_ports=[22, 8080, 50000],
        engagement_hooks=[
            "Jenkins credentials.xml with encrypted secrets",
            "Deploy keys for production servers",
            "AWS credentials in environment",
            "Docker registry push access",
        ],
        trigger_keywords=["jenkins", "ci", "cd", "pipeline", "build", "deploy", "runner"],
    ),
}



# =============================================================================
# Adaptive Persona Engine
# =============================================================================

class AdaptivePersonaEngine:
    """
    Dynamically selects and adapts server personas based on
    attacker behavior, maximizing engagement and intelligence gathering.
    """

    def __init__(self, default_persona: PersonaType = PersonaType.CORPORATE_UBUNTU):
        self._default_persona = default_persona
        self._session_personas: Dict[str, PersonaType] = {}
        self._session_engagement_scores: Dict[str, float] = {}
        self._persona_switch_count: int = 0

    def get_persona(self, session_id: str) -> PersonaConfig:
        """Get the current persona for a session."""
        persona_type = self._session_personas.get(session_id, self._default_persona)
        return PERSONA_LIBRARY[persona_type]

    def assign_persona(
        self, session_id: str, service: str, initial_commands: List[str] = None
    ) -> PersonaConfig:
        """
        Assign an initial persona based on the service and any early commands.

        Args:
            session_id: The attacker's session ID.
            service: Which service they connected to (SSH, Telnet, HTTP, FTP).
            initial_commands: Any commands already received.

        Returns:
            The assigned PersonaConfig.
        """
        # Default assignment based on service
        if service == "HTTP":
            persona_type = PersonaType.WEB_SERVER_NGINX
        elif service == "FTP":
            persona_type = PersonaType.FILE_SERVER
        else:
            persona_type = self._default_persona

        # Refine based on initial commands if available
        if initial_commands:
            detected = self._detect_persona_from_commands(initial_commands)
            if detected:
                persona_type = detected

        self._session_personas[session_id] = persona_type
        self._session_engagement_scores[session_id] = 0.0

        persona = PERSONA_LIBRARY.get(persona_type, PERSONA_LIBRARY[self._default_persona])
        logger.info(
            f"[Persona] Assigned '{persona.name}' to session {session_id} "
            f"(service: {service})"
        )
        return persona

    def adapt_persona(
        self, session_id: str, recent_commands: List[str]
    ) -> Optional[PersonaConfig]:
        """
        Evaluate whether to switch persona based on recent attacker behavior.
        Returns new PersonaConfig if switched, None if no change.

        The engine switches personas when attacker behavior strongly indicates
        they're looking for a specific type of server.
        """
        current_type = self._session_personas.get(session_id, self._default_persona)
        detected = self._detect_persona_from_commands(recent_commands)

        if detected and detected != current_type:
            # Check if the switch makes sense (don't flip-flop)
            confidence = self._calculate_switch_confidence(recent_commands, detected)
            if confidence >= 0.7:
                self._session_personas[session_id] = detected
                self._persona_switch_count += 1
                new_persona = PERSONA_LIBRARY[detected]
                logger.info(
                    f"[Persona] Switched session {session_id} from "
                    f"{current_type.value} -> {detected.value} "
                    f"(confidence: {confidence:.2f})"
                )
                return new_persona

        return None

    def _detect_persona_from_commands(
        self, commands: List[str]
    ) -> Optional[PersonaType]:
        """Detect the best persona match from command patterns."""
        scores: Dict[PersonaType, int] = {}

        full_text = " ".join(commands).lower()

        for persona_type, config in PERSONA_LIBRARY.items():
            score = 0
            for keyword in config.trigger_keywords:
                if keyword.lower() in full_text:
                    score += 1
            if score > 0:
                scores[persona_type] = score

        if not scores:
            return None

        best_match = max(scores.items(), key=lambda x: x[1])
        if best_match[1] >= 2:  # Need at least 2 keyword matches
            return best_match[0]

        return None

    def _calculate_switch_confidence(
        self, commands: List[str], target_persona: PersonaType
    ) -> float:
        """Calculate confidence level for a persona switch."""
        config = PERSONA_LIBRARY.get(target_persona)
        if not config:
            return 0.0

        full_text = " ".join(commands).lower()
        matches = sum(
            1 for kw in config.trigger_keywords if kw.lower() in full_text
        )
        total_keywords = len(config.trigger_keywords)

        if total_keywords == 0:
            return 0.0

        return min(matches / max(total_keywords * 0.3, 1), 1.0)

    def build_system_prompt(self, session_id: str) -> str:
        """
        Build a complete system prompt for the LLM based on the current persona.
        This is injected into the Ollama API call for context.
        """
        persona = self.get_persona(session_id)

        prompt_parts = [
            f"You are an authentic {persona.os_version} server.",
            f"Hostname: {persona.hostname}",
            f"Kernel: {persona.kernel}",
            f"Description: {persona.description}",
            "",
            "BEHAVIORAL RULES:",
            "- Respond ONLY with raw terminal output",
            "- No markdown, no code fences, no explanations",
            "- Behave exactly like a real Linux terminal",
            "- Maintain consistency with previous responses",
            "",
            "SERVER-SPECIFIC CONTEXT:",
            persona.system_prompt_addon,
            "",
            f"Running services: {', '.join(persona.running_services)}",
            f"Network interfaces: {persona.interfaces}",
            "",
            "ENGAGEMENT STRATEGY:",
            "- If the attacker is exploring, reveal interesting file paths",
            "- Make responses realistic enough that the attacker stays engaged",
            "- Never reveal this is a honeypot",
            "- If they access sensitive files, show realistic fake content",
        ]

        return "\n".join(prompt_parts)

    def get_filesystem_overlay(self, session_id: str) -> Dict[str, Optional[str]]:
        """
        Get persona-specific filesystem entries to overlay on the
        virtual filesystem for consistent responses.
        """
        persona = self.get_persona(session_id)
        return persona.filesystem_layout.copy()

    def track_engagement(self, session_id: str, command: str) -> float:
        """
        Track engagement score for a session.
        Higher score = attacker is more deeply engaged.
        """
        score = self._session_engagement_scores.get(session_id, 0.0)

        # Commands that indicate deeper engagement
        deep_engagement = [
            "cat ", "nano ", "vim ", "vi ", "more ", "less ",
            "wget ", "curl ", "scp ", "ssh ", "mysql ", "psql ",
            "docker ", "kubectl ", "aws ", "find ", "grep -r",
        ]
        for pattern in deep_engagement:
            if pattern in command.lower():
                score += 2.0
                break
        else:
            score += 0.5  # Any command adds some engagement

        self._session_engagement_scores[session_id] = score
        return score

    def get_engagement_level(self, session_id: str) -> str:
        """Get a human-readable engagement level."""
        score = self._session_engagement_scores.get(session_id, 0.0)
        if score >= 20:
            return "deeply_engaged"
        elif score >= 10:
            return "engaged"
        elif score >= 5:
            return "exploring"
        else:
            return "initial"

    def end_session(self, session_id: str) -> None:
        """Clean up session persona data."""
        self._session_personas.pop(session_id, None)
        self._session_engagement_scores.pop(session_id, None)

    def get_stats(self) -> Dict:
        """Return persona engine statistics."""
        persona_distribution = {}
        for persona_type in self._session_personas.values():
            name = persona_type.value
            persona_distribution[name] = persona_distribution.get(name, 0) + 1

        return {
            "active_sessions": len(self._session_personas),
            "persona_switches": self._persona_switch_count,
            "persona_distribution": persona_distribution,
            "engagement_levels": {
                sid: self.get_engagement_level(sid)
                for sid in self._session_personas
            },
        }


# =============================================================================
# Module-level singleton
# =============================================================================
persona_engine = AdaptivePersonaEngine()
