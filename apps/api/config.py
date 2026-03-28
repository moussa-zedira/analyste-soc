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
    JWT_EXPIRE_MINUTES: int = 480

    # GeoIP
    GEOIP_DB_PATH: str = "/app/data/GeoLite2-City.mmdb"

    # Alerting — SMTP
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "siem@example.com"

    # Alerting — Slack
    SLACK_WEBHOOK_URL: str = ""

    # Threat Intelligence
    ABUSEIPDB_API_KEY: str = ""
    OTX_API_KEY: str = ""

    @property
    def effective_api_key(self) -> str:
        """Retourne la clé API utilisée pour la vérification des requêtes.

        Lève ``ValueError`` en production si aucune clé n'est configurée.
        """
        if self.API_KEY:
            return self.API_KEY
        if self.ENV == "dev":
            return "dev-insecure-key"
        raise ValueError(
            "API_KEY must be set in production environments (ENV != 'dev')"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retourne une instance ``Settings`` mise en cache."""
    return Settings()
