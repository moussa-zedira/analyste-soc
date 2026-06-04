"""Configuration de l'application chargée depuis les variables d'environnement."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Paramètres d'exécution de l'API du tableau de bord de cyberdéfense.

    En production (ENV != "dev"), API_KEY est obligatoire.
    En développement (ENV == "dev"), API_KEY utilise "dev-insecure-key" par défaut.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ENV: str = "dev"
    DATABASE_URL: str = "postgresql+psycopg2://siem:siem@localhost:5432/siem"
    API_KEY: str = ""
    API_KEY_HEADER: str = "X-API-Key"
    WEBHOOK_URL: str = ""
    WEBHOOK_ENABLED: bool = False
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2"
    TRIAGE_ENABLED: bool = True
    MIN_SEVERITY: str = "medium"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT / Auth
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_EXPIRE_DAYS: int = 7

    # CORS — liste d'origines autorisees, separees par des virgules
    CORS_ALLOWED_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000,http://web:3000"

    @property
    def cors_allowed_origins(self) -> list[str]:
        """Liste deduiquee des origines CORS autorisees."""
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]

    # GeoIP
    GEOIP_DB_PATH: str = "/data/geoip/GeoLite2-City.mmdb"
    MAXMIND_LICENSE_KEY: str = ""

    # Observabilite — tracing OpenTelemetry (desactive si endpoint vide)
    OTEL_SERVICE_NAME: str = "cyberdef-api"
    OTEL_EXPORTER_OTLP_ENDPOINT: str = ""
    OTEL_EXPORTER_OTLP_INSECURE: bool = True
    OTEL_TRACES_SAMPLER_RATIO: float = 1.0

    # Alerting — SMTP
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "siem@example.com"

    # Alerting — Slack
    SLACK_WEBHOOK_URL: str = ""

    # Alerting — PagerDuty
    PAGERDUTY_ROUTING_KEY: str = ""

    # Alerting — Discord
    DISCORD_WEBHOOK_URL: str = ""

    # Alerting — Teams
    TEAMS_WEBHOOK_URL: str = ""

    # Alerting — Telegram
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""

    # Alerting — Syslog
    SYSLOG_HOST: str = ""
    SYSLOG_PORT: int = 514
    SYSLOG_PROTOCOL: str = "udp"

    # Threat Intelligence
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""
    VIRUSTOTAL_API_KEY: str = ""
    SHODAN_API_KEY: str = ""
    GREYNOISE_API_KEY: str = ""
    CIRCL_PDNS_USER: str = ""
    CIRCL_PDNS_PASSWORD: str = ""
    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = True

    # SSO OIDC
    SSO_REDIRECT_BASE_URL: str = "http://localhost:8000"
    SSO_STATE_TTL_SECONDS: int = 300

    # Red Team / Offensif — interrupteur global du module pentest.
    # Quand False, aucun router offensif (apps.api.pentest.* + routes red team)
    # n'est importé ni monté : démarrage plus léger, CI/surface réduite,
    # instance "blue team / SOC pur". Réversible instantanément.
    # Défaut True : la plateforme pentest reste le produit par défaut.
    ENABLE_OFFENSIVE: bool = True

    # Red Team — Sliver C2 (V4.3a)
    SLIVER_OPERATOR_CFG: str = ""
    SLIVER_DEFAULT_C2_URL: str = ""
    SLIVER_BUILD_OUTPUT_DIR: str = "/data/sliver/builds"

    # Red Team — Engagement audit log signing (V4.3b)
    AUDIT_SIGNING_KEY: str = ""

    # Red Team — GoPhish workflow (V4.6)
    GOPHISH_API_URL: str = ""
    GOPHISH_API_KEY: str = ""

    # Sentinelles refusees en production (anciens defaults compromis)
    _WEAK_API_KEYS = frozenset(
        {
            "elite-secret-key",
            "change-me",
            "dev-insecure-key",
            "",
        }
    )
    _WEAK_JWT_SECRETS = frozenset(
        {
            "change-me-in-production",
            "dev-jwt-secret-change-me",
            "",
        }
    )

    @property
    def effective_api_key(self) -> str:
        """Retourne la cle API utilisee pour la verification des requetes.

        Leve ``ValueError`` en production si la cle est faible/absente.
        """
        if self.ENV != "dev":
            if self.API_KEY in self._WEAK_API_KEYS:
                raise ValueError(
                    "API_KEY must be set to a strong random value in production. "
                    "Generate one: python -c 'import secrets; print(secrets.token_urlsafe(32))'"
                )
            return self.API_KEY
        return self.API_KEY or "dev-insecure-key"

    def validate_for_prod(self) -> list[str]:
        """Retourne la liste des problemes de configuration bloquants en prod."""
        problems: list[str] = []
        if self.ENV == "dev":
            return problems
        if self.API_KEY in self._WEAK_API_KEYS:
            problems.append("API_KEY is weak or unset")
        if self.JWT_SECRET_KEY in self._WEAK_JWT_SECRETS:
            problems.append("JWT_SECRET_KEY is weak or unset")
        if "siem:siem@" in self.DATABASE_URL:
            problems.append("DATABASE_URL still uses default credentials (siem:siem)")
        return problems


_FILE_BACKED_SECRETS: tuple[str, ...] = (
    "API_KEY",
    "JWT_SECRET_KEY",
    "POSTGRES_PASSWORD",
    "ABUSEIPDB_API_KEY",
    "OTX_API_KEY",
)


def _load_file_backed_secrets() -> None:
    """Convention Docker secrets : si VAR_FILE pointe sur un fichier, lit son contenu
    et l'expose comme VAR. Permet d'utiliser ``secrets:`` dans docker-compose
    sans coder en dur les valeurs dans .env.
    """
    import os
    from pathlib import Path

    for name in _FILE_BACKED_SECRETS:
        file_var = f"{name}_FILE"
        path = os.environ.get(file_var)
        if not path:
            continue
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            os.environ[name] = value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retourne une instance ``Settings`` mise en cache."""
    _load_file_backed_secrets()
    return Settings()
