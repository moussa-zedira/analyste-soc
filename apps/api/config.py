"""Application configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for the Cyber Defense Dashboard API.

    In production (ENV != "dev"), API_KEY is required.
    In development (ENV == "dev"), API_KEY falls back to "dev-insecure-key".
    WARNING: The dev fallback is intentionally insecure and MUST NOT be used
    outside of local development.
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

    @property
    def effective_api_key(self) -> str:
        """Return the API key to use for request verification.

        Raises ``ValueError`` in production when no key is configured.
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
    """Return a cached ``Settings`` instance."""
    return Settings()
