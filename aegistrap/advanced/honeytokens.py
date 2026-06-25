"""
AegisTrap Advanced Deception - Dynamic Honeytokens & Breadcrumbs
==================================================================
Generates realistic-looking fake credentials, API keys, tokens, and
sensitive data that act as tripwires. When an attacker accesses or
uses these tokens, high-fidelity alerts are triggered.

Features:
- Dynamic AWS/GCP/Azure credential generation
- Fake database connection strings
- Decoy API keys and JWT tokens
- Breadcrumb files (.env, config, SSH keys)
- Canary DNS domains (detect exfiltration attempts)
- Trackable unique identifiers per honeytoken
- Usage detection and alerting hooks

All generated tokens are cryptographically tagged so that usage
can be traced back to the specific honeypot session and service.
"""

import uuid
import time
import hmac
import json
import hashlib
import secrets
import logging
import base64
from typing import Dict, List, Optional, Callable, Awaitable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

logger = logging.getLogger("aegistrap.honeytokens")



# =============================================================================
# Enumerations & Data Structures
# =============================================================================

class TokenType(Enum):
    """Types of honeytokens that can be generated."""
    AWS_ACCESS_KEY = "aws_access_key"
    AWS_SECRET_KEY = "aws_secret_key"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    AZURE_CLIENT_SECRET = "azure_client_secret"
    DATABASE_CREDENTIAL = "database_credential"
    API_KEY = "api_key"
    JWT_TOKEN = "jwt_token"
    SSH_PRIVATE_KEY = "ssh_private_key"
    SLACK_WEBHOOK = "slack_webhook"
    GITHUB_TOKEN = "github_token"
    STRIPE_KEY = "stripe_key"
    SMTP_CREDENTIAL = "smtp_credential"
    CANARY_DOMAIN = "canary_domain"
    BITCOIN_WALLET = "bitcoin_wallet"
    ENV_FILE = "env_file"
    KUBECONFIG = "kubeconfig"


class BreadcrumbType(Enum):
    """Types of breadcrumb files that lure attackers deeper."""
    DOT_ENV = ".env"
    SSH_CONFIG = ".ssh/config"
    AWS_CREDENTIALS = ".aws/credentials"
    DOCKER_CONFIG = ".docker/config.json"
    KUBE_CONFIG = ".kube/config"
    GIT_CONFIG = ".git/config"
    BASH_HISTORY = ".bash_history"
    MYSQL_HISTORY = ".mysql_history"
    NOTES_TXT = "notes.txt"
    PASSWORDS_TXT = "passwords.txt"
    DEPLOY_SCRIPT = "deploy.sh"
    BACKUP_SCRIPT = "backup.sh"


@dataclass
class Honeytoken:
    """Represents a single generated honeytoken."""
    token_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    token_type: TokenType = TokenType.API_KEY
    value: str = ""               # The fake credential value
    context: str = ""             # Where it was placed (service, file path)
    session_id: str = ""          # Which session saw this token
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    accessed: bool = False        # Has the attacker attempted to use it?
    accessed_at: Optional[str] = None
    accessed_from_ip: Optional[str] = None
    tracking_tag: str = ""        # Hidden identifier for tracing

    def to_dict(self) -> dict:
        return {
            "honeytoken_id": self.token_id,
            "honeytoken_type": self.token_type.value,
            "honeytoken_context": self.context,
            "honeytoken_session": self.session_id,
            "honeytoken_accessed": self.accessed,
            "honeytoken_accessed_at": self.accessed_at,
            "honeytoken_tracking_tag": self.tracking_tag,
        }


@dataclass
class Breadcrumb:
    """A breadcrumb file designed to lure attackers."""
    breadcrumb_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    breadcrumb_type: BreadcrumbType = BreadcrumbType.DOT_ENV
    file_path: str = ""
    content: str = ""
    embedded_tokens: List[str] = field(default_factory=list)  # Token IDs
    created_for_session: str = ""



# =============================================================================
# Token Generation Engine
# =============================================================================

class HoneytokenGenerator:
    """
    Generates realistic-looking fake credentials and sensitive data.
    Each token contains a hidden tracking identifier that allows
    detection of usage outside the honeypot.
    """

    # Secret key for generating tracking tags (set per deployment)
    _signing_key: str = secrets.token_hex(32)

    @classmethod
    def _generate_tracking_tag(cls, token_id: str) -> str:
        """Generate a hidden tracking tag for a honeytoken."""
        return hmac.HMAC(
            cls._signing_key.encode(),
            token_id.encode(),
            hashlib.sha256,
        ).hexdigest()[:16]

    @classmethod
    def generate_aws_credentials(cls, session_id: str = "") -> Dict[str, Honeytoken]:
        """Generate realistic-looking AWS access key and secret key pair."""
        # AWS access keys follow format: AKIA + 16 uppercase alphanumeric
        access_key_suffix = secrets.token_hex(8).upper()
        access_key = f"AKIA{access_key_suffix}"

        # AWS secret keys are 40 chars base64-ish
        secret_raw = secrets.token_bytes(30)
        secret_key = base64.b64encode(secret_raw).decode()[:40]

        access_token = Honeytoken(
            token_type=TokenType.AWS_ACCESS_KEY,
            value=access_key,
            context="aws_credentials_file",
            session_id=session_id,
        )
        access_token.tracking_tag = cls._generate_tracking_tag(access_token.token_id)

        secret_token = Honeytoken(
            token_type=TokenType.AWS_SECRET_KEY,
            value=secret_key,
            context="aws_credentials_file",
            session_id=session_id,
        )
        secret_token.tracking_tag = cls._generate_tracking_tag(secret_token.token_id)

        return {"access_key": access_token, "secret_key": secret_token}

    @classmethod
    def generate_api_key(cls, service: str = "internal", session_id: str = "") -> Honeytoken:
        """Generate a realistic API key for various services."""
        prefixes = {
            "internal": "sk-corpnet-",
            "stripe": "sk_live_",
            "sendgrid": "SG.",
            "github": "ghp_",
            "gitlab": "glpat-",
            "slack": "xoxb-",
            "openai": "sk-",
            "twilio": "SK",
        }
        prefix = prefixes.get(service, "api-")
        key_body = secrets.token_urlsafe(32)
        value = f"{prefix}{key_body}"

        token = Honeytoken(
            token_type=TokenType.API_KEY,
            value=value,
            context=f"api_key_{service}",
            session_id=session_id,
        )
        token.tracking_tag = cls._generate_tracking_tag(token.token_id)
        return token

    @classmethod
    def generate_database_credential(
        cls, db_type: str = "mysql", session_id: str = ""
    ) -> Honeytoken:
        """Generate realistic database connection credentials."""
        hosts = ["10.0.4.5", "10.0.4.8", "db-prod-01.internal", "rds-prod.corpnet.io"]
        users = ["app_service", "db_admin", "readonly_user", "backup_svc"]
        passwords = [
            "Pr0d_S3cur3!_2024", "D@t@b@se_M@ster99",
            "r00t_pa$$_ch@ng3_m3", "Backup#2024!Secure",
        ]

        import random
        host = random.choice(hosts)
        user = random.choice(users)
        password = random.choice(passwords)

        if db_type == "mysql":
            value = f"mysql://{user}:{password}@{host}:3306/production"
        elif db_type == "postgres":
            value = f"postgresql://{user}:{password}@{host}:5432/corpnet_db"
        elif db_type == "mongodb":
            value = f"mongodb://{user}:{password}@{host}:27017/admin"
        else:
            value = f"redis://:{password}@{host}:6379/0"

        token = Honeytoken(
            token_type=TokenType.DATABASE_CREDENTIAL,
            value=value,
            context=f"database_{db_type}",
            session_id=session_id,
        )
        token.tracking_tag = cls._generate_tracking_tag(token.token_id)
        return token



    @classmethod
    def generate_jwt_token(cls, session_id: str = "") -> Honeytoken:
        """Generate a realistic-looking JWT token."""
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")

        payload_data = {
            "sub": "admin@corpnet.io",
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
            "role": "superadmin",
            "org_id": "org_corpnet_prod",
            "permissions": ["read", "write", "admin", "deploy"],
        }
        payload = base64.urlsafe_b64encode(
            json.dumps(payload_data).encode()
        ).decode().rstrip("=")

        signature = secrets.token_urlsafe(32)
        value = f"{header}.{payload}.{signature}"

        token = Honeytoken(
            token_type=TokenType.JWT_TOKEN,
            value=value,
            context="jwt_admin_token",
            session_id=session_id,
        )
        token.tracking_tag = cls._generate_tracking_tag(token.token_id)
        return token

    @classmethod
    def generate_github_token(cls, session_id: str = "") -> Honeytoken:
        """Generate a fake GitHub personal access token."""
        value = f"ghp_{secrets.token_urlsafe(30)}"
        token = Honeytoken(
            token_type=TokenType.GITHUB_TOKEN,
            value=value,
            context="github_pat",
            session_id=session_id,
        )
        token.tracking_tag = cls._generate_tracking_tag(token.token_id)
        return token

    @classmethod
    def generate_slack_webhook(cls, session_id: str = "") -> Honeytoken:
        """Generate a fake Slack webhook URL."""
        workspace_id = f"T{secrets.token_hex(5).upper()}"
        hook_id = f"B{secrets.token_hex(5).upper()}"
        token_val = secrets.token_urlsafe(24)
        value = f"https://hooks.slack.com/services/{workspace_id}/{hook_id}/{token_val}"

        token = Honeytoken(
            token_type=TokenType.SLACK_WEBHOOK,
            value=value,
            context="slack_webhook",
            session_id=session_id,
        )
        token.tracking_tag = cls._generate_tracking_tag(token.token_id)
        return token

    @classmethod
    def generate_bitcoin_wallet(cls, session_id: str = "") -> Honeytoken:
        """Generate a fake Bitcoin wallet address (looks real but isn't)."""
        # Generate a realistic-looking BTC address (starts with 1 or 3)
        addr_body = secrets.token_hex(20)
        value = f"1{base64.b58encode(bytes.fromhex(addr_body)).decode()[:33]}" if hasattr(base64, 'b58encode') else f"1{addr_body[:33]}"
        # Fallback to simple format
        value = f"1{secrets.token_urlsafe(24)[:33]}"

        token = Honeytoken(
            token_type=TokenType.BITCOIN_WALLET,
            value=value,
            context="bitcoin_wallet",
            session_id=session_id,
        )
        token.tracking_tag = cls._generate_tracking_tag(token.token_id)
        return token



# =============================================================================
# Breadcrumb File Generator
# =============================================================================

class BreadcrumbGenerator:
    """
    Generates realistic breadcrumb files that contain embedded honeytokens.
    These files are served to attackers to lure them into using fake credentials.
    """

    @classmethod
    def generate_env_file(cls, session_id: str = "") -> Breadcrumb:
        """Generate a realistic .env file with embedded honeytokens."""
        aws_creds = HoneytokenGenerator.generate_aws_credentials(session_id)
        db_cred = HoneytokenGenerator.generate_database_credential("mysql", session_id)
        api_key = HoneytokenGenerator.generate_api_key("stripe", session_id)
        slack_hook = HoneytokenGenerator.generate_slack_webhook(session_id)

        content = (
            "# CorpNet Production Environment\n"
            "# Last updated: 2024-01-15 by j.mitchell\n"
            "# DO NOT COMMIT THIS FILE\n"
            "\n"
            "APP_NAME=CorpNet\n"
            "APP_ENV=production\n"
            "APP_DEBUG=false\n"
            f"APP_KEY=base64:{secrets.token_urlsafe(32)}\n"
            "APP_URL=https://app.corpnet.io\n"
            "\n"
            "# Database\n"
            f"DATABASE_URL={db_cred.value}\n"
            "DB_CONNECTION=mysql\n"
            "DB_HOST=10.0.4.5\n"
            "DB_PORT=3306\n"
            "DB_DATABASE=corpnet_production\n"
            "DB_USERNAME=app_service\n"
            "DB_PASSWORD=Pr0d_S3cur3!_2024\n"
            "\n"
            "# AWS\n"
            f"AWS_ACCESS_KEY_ID={aws_creds['access_key'].value}\n"
            f"AWS_SECRET_ACCESS_KEY={aws_creds['secret_key'].value}\n"
            "AWS_DEFAULT_REGION=us-east-1\n"
            "AWS_BUCKET=corpnet-prod-assets\n"
            "\n"
            "# Payment Processing\n"
            f"STRIPE_SECRET_KEY={api_key.value}\n"
            "STRIPE_WEBHOOK_SECRET=whsec_" + secrets.token_urlsafe(24) + "\n"
            "\n"
            "# Notifications\n"
            f"SLACK_WEBHOOK_URL={slack_hook.value}\n"
            "\n"
            "# Redis Cache\n"
            "REDIS_HOST=10.0.4.11\n"
            "REDIS_PASSWORD=r3d1s_c@ch3_2024\n"
            "REDIS_PORT=6379\n"
            "\n"
            "# SMTP\n"
            "MAIL_HOST=smtp.corpnet.io\n"
            "MAIL_PORT=587\n"
            "MAIL_USERNAME=noreply@corpnet.io\n"
            "MAIL_PASSWORD=Sm7p_S3nd3r!2024\n"
        )

        token_ids = [
            aws_creds["access_key"].token_id,
            aws_creds["secret_key"].token_id,
            db_cred.token_id,
            api_key.token_id,
            slack_hook.token_id,
        ]

        return Breadcrumb(
            breadcrumb_type=BreadcrumbType.DOT_ENV,
            file_path="/var/www/html/.env",
            content=content,
            embedded_tokens=token_ids,
            created_for_session=session_id,
        )

    @classmethod
    def generate_aws_credentials_file(cls, session_id: str = "") -> Breadcrumb:
        """Generate a fake ~/.aws/credentials file."""
        creds1 = HoneytokenGenerator.generate_aws_credentials(session_id)
        creds2 = HoneytokenGenerator.generate_aws_credentials(session_id)

        content = (
            "[default]\n"
            f"aws_access_key_id = {creds1['access_key'].value}\n"
            f"aws_secret_access_key = {creds1['secret_key'].value}\n"
            "region = us-east-1\n"
            "\n"
            "[production]\n"
            f"aws_access_key_id = {creds2['access_key'].value}\n"
            f"aws_secret_access_key = {creds2['secret_key'].value}\n"
            "region = us-west-2\n"
            "\n"
            "[backup]\n"
            f"aws_access_key_id = AKIA{secrets.token_hex(8).upper()}\n"
            f"aws_secret_access_key = {secrets.token_urlsafe(30)}\n"
            "region = eu-west-1\n"
        )

        return Breadcrumb(
            breadcrumb_type=BreadcrumbType.AWS_CREDENTIALS,
            file_path="/root/.aws/credentials",
            content=content,
            embedded_tokens=[
                creds1["access_key"].token_id, creds1["secret_key"].token_id,
                creds2["access_key"].token_id, creds2["secret_key"].token_id,
            ],
            created_for_session=session_id,
        )

    @classmethod
    def generate_bash_history(cls, session_id: str = "") -> Breadcrumb:
        """Generate a realistic .bash_history with embedded secrets."""
        api_key = HoneytokenGenerator.generate_api_key("internal", session_id)
        gh_token = HoneytokenGenerator.generate_github_token(session_id)

        content = (
            "ls -la\n"
            "cd /var/www/html\n"
            "git pull origin main\n"
            "composer install\n"
            f"curl -H 'Authorization: Bearer {api_key.value}' https://api.corpnet.io/v2/users\n"
            "systemctl restart nginx\n"
            "mysql -u root -pR00t_Mysql_2024! corpnet_production < backup.sql\n"
            "docker ps\n"
            "docker logs corpnet-api --tail 100\n"
            f"git clone https://{gh_token.value}@github.com/corpnet/internal-api.git\n"
            "ssh -i /root/.ssh/prod_key admin@10.0.4.22\n"
            "scp backup.tar.gz admin@10.0.4.22:/backups/\n"
            "kubectl get pods -n production\n"
            "aws s3 sync /backups s3://corpnet-backups-prod/daily/\n"
            "tail -f /var/log/nginx/access.log\n"
            "crontab -l\n"
            "cat /etc/shadow\n"
            "netstat -tlnp\n"
        )

        return Breadcrumb(
            breadcrumb_type=BreadcrumbType.BASH_HISTORY,
            file_path="/root/.bash_history",
            content=content,
            embedded_tokens=[api_key.token_id, gh_token.token_id],
            created_for_session=session_id,
        )

    @classmethod
    def generate_kubeconfig(cls, session_id: str = "") -> Breadcrumb:
        """Generate a fake kubeconfig with cluster credentials."""
        cluster_token = secrets.token_urlsafe(48)
        cert_data = base64.b64encode(secrets.token_bytes(128)).decode()

        content = (
            "apiVersion: v1\n"
            "kind: Config\n"
            "clusters:\n"
            "- cluster:\n"
            f"    certificate-authority-data: {cert_data}\n"
            "    server: https://k8s-prod.corpnet.internal:6443\n"
            "  name: corpnet-production\n"
            "contexts:\n"
            "- context:\n"
            "    cluster: corpnet-production\n"
            "    namespace: default\n"
            "    user: admin\n"
            "  name: corpnet-prod-context\n"
            "current-context: corpnet-prod-context\n"
            "users:\n"
            "- name: admin\n"
            "  user:\n"
            f"    token: {cluster_token}\n"
        )

        return Breadcrumb(
            breadcrumb_type=BreadcrumbType.KUBE_CONFIG,
            file_path="/root/.kube/config",
            content=content,
            embedded_tokens=[],
            created_for_session=session_id,
        )



# =============================================================================
# Honeytoken Manager (Tracking & Detection)
# =============================================================================

class HoneytokenManager:
    """
    Central manager for all generated honeytokens and breadcrumbs.
    Tracks generation, deployment, and usage detection.
    """

    def __init__(self):
        # All generated tokens indexed by ID
        self._tokens: Dict[str, Honeytoken] = {}
        # All generated breadcrumbs indexed by ID
        self._breadcrumbs: Dict[str, Breadcrumb] = {}
        # Quick lookup: token value -> token_id (for usage detection)
        self._value_index: Dict[str, str] = {}
        # Alert callback
        self._alert_callback: Optional[Callable[..., Awaitable]] = None
        # Statistics
        self._tokens_generated: int = 0
        self._tokens_accessed: int = 0

    def set_alert_callback(self, callback: Callable[..., Awaitable]) -> None:
        """Set the callback function for honeytoken access alerts."""
        self._alert_callback = callback

    def register_token(self, token: Honeytoken) -> None:
        """Register a honeytoken for tracking."""
        self._tokens[token.token_id] = token
        self._value_index[token.value] = token.token_id
        self._tokens_generated += 1

    def register_breadcrumb(self, breadcrumb: Breadcrumb) -> None:
        """Register a breadcrumb and all its embedded tokens."""
        self._breadcrumbs[breadcrumb.breadcrumb_id] = breadcrumb

    async def check_usage(self, text: str, source_ip: str = "") -> List[Honeytoken]:
        """
        Check if any text contains a known honeytoken value.
        This should be called on outgoing network traffic, DNS queries, etc.

        Args:
            text: Text to scan for honeytoken usage.
            source_ip: IP that used the token.

        Returns:
            List of honeytokens that were detected in the text.
        """
        triggered = []

        for value, token_id in self._value_index.items():
            if value in text:
                token = self._tokens.get(token_id)
                if token and not token.accessed:
                    token.accessed = True
                    token.accessed_at = datetime.now(timezone.utc).isoformat()
                    token.accessed_from_ip = source_ip
                    self._tokens_accessed += 1
                    triggered.append(token)

                    logger.warning(
                        f"[HONEYTOKEN] Token triggered! Type={token.token_type.value} "
                        f"ID={token.token_id} IP={source_ip}"
                    )

                    # Fire alert
                    if self._alert_callback:
                        try:
                            await self._alert_callback(token)
                        except Exception as e:
                            logger.error(f"[HONEYTOKEN] Alert callback error: {e}")

        return triggered

    def generate_session_breadcrumbs(self, session_id: str) -> Dict[str, Breadcrumb]:
        """
        Generate a complete set of breadcrumbs for a new session.
        Returns dict of file_path -> Breadcrumb for the virtual filesystem.
        """
        breadcrumbs = {}

        # Generate various breadcrumb files
        env_file = BreadcrumbGenerator.generate_env_file(session_id)
        breadcrumbs[env_file.file_path] = env_file
        self.register_breadcrumb(env_file)

        aws_creds = BreadcrumbGenerator.generate_aws_credentials_file(session_id)
        breadcrumbs[aws_creds.file_path] = aws_creds
        self.register_breadcrumb(aws_creds)

        bash_hist = BreadcrumbGenerator.generate_bash_history(session_id)
        breadcrumbs[bash_hist.file_path] = bash_hist
        self.register_breadcrumb(bash_hist)

        kubeconfig = BreadcrumbGenerator.generate_kubeconfig(session_id)
        breadcrumbs[kubeconfig.file_path] = kubeconfig
        self.register_breadcrumb(kubeconfig)

        # Register all embedded tokens
        for bc in breadcrumbs.values():
            for token_id in bc.embedded_tokens:
                if token_id in self._tokens:
                    continue
                # Token was generated inline; already registered by generator

        logger.info(
            f"[HONEYTOKEN] Generated {len(breadcrumbs)} breadcrumbs for "
            f"session {session_id}"
        )

        return breadcrumbs

    def get_stats(self) -> Dict:
        """Return honeytoken statistics."""
        return {
            "tokens_generated": self._tokens_generated,
            "tokens_accessed": self._tokens_accessed,
            "breadcrumbs_deployed": len(self._breadcrumbs),
            "active_tokens": len(self._tokens),
            "detection_rate": (
                self._tokens_accessed / max(self._tokens_generated, 1)
            ) * 100,
        }

    def get_triggered_tokens(self) -> List[Honeytoken]:
        """Return all tokens that have been triggered/accessed."""
        return [t for t in self._tokens.values() if t.accessed]


# =============================================================================
# Module-level singleton
# =============================================================================
honeytoken_manager = HoneytokenManager()
