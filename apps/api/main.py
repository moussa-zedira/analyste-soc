"""Point d'entrée de l'application FastAPI pour l'API du tableau de bord de cyberdéfense."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

import structlog
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text

from apps.api.config import get_settings
from apps.api.db.base import Base
from apps.api.db.session import engine, SessionLocal
from apps.api.logging_config import setup_logging, generate_request_id
from apps.api.middleware.rate_limit import limiter
from apps.api.routes import (
    admin,
    alerts,
    anomaly,
    auth,
    chat,
    events,
    export,
    incidents,
    ml,
    rules,
    scanner,
    stats,
    threat_scores,
    triage,
    ws,
)
from apps.api.security import require_api_key

# Import all models so Base.metadata knows about them.
import apps.api.models  # noqa: F401

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
settings = get_settings()
setup_logging(json_output=settings.ENV == "prod")

logger = structlog.get_logger("apps.api")

# ---------------------------------------------------------------------------
# Application startup timestamp
# ---------------------------------------------------------------------------
_start_time = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Exécute les migrations Alembic au démarrage, avec repli sur create_all."""
    try:
        from alembic.config import Config
        from alembic import command

        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL)
        command.upgrade(alembic_cfg, "head")
        logger.info("database_migrated", method="alembic")
    except Exception:
        Base.metadata.create_all(bind=engine)
        logger.info("database_initialised", method="create_all")

    # Create default admin account if no users exist
    _seed_default_admin()

    yield


def _seed_default_admin() -> None:
    """Cree un compte admin par defaut si la table users est vide."""
    import uuid
    from datetime import datetime, timezone
    from apps.api.auth import hash_password
    from apps.api.models.user import User

    db = SessionLocal()
    try:
        if db.query(User).first() is not None:
            return  # Users already exist, skip seeding
        admin = User(
            id=str(uuid.uuid4()),
            username="admin",
            email="admin@cyberdef.local",
            hashed_password=hash_password("CyberDef2024!"),
            role="admin",
            is_active=True,
            created_at=datetime.now(timezone.utc),
        )
        db.add(admin)
        db.commit()
        logger.info("default_admin_created", username="admin")
    except Exception as exc:
        db.rollback()
        logger.warning("seed_admin_failed", error=str(exc))
    finally:
        db.close()


def create_app() -> FastAPI:
    """Construit et retourne l'application FastAPI."""
    kwargs: dict = {}
    if settings.ENV == "prod":
        kwargs["docs_url"] = None
        kwargs["redoc_url"] = None

    app = FastAPI(
        title="Cyber Defense Dashboard API",
        version="1.0.0",
        lifespan=lifespan,
        **kwargs,
    )

    # -------------------------------------------------------------------
    # Rate limiter
    # -------------------------------------------------------------------
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # -------------------------------------------------------------------
    # Request ID middleware
    # -------------------------------------------------------------------
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        """Injecte un identifiant unique dans chaque requête HTTP."""
        request_id = generate_request_id()
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # -------------------------------------------------------------------
    # Health check (enhanced)
    # -------------------------------------------------------------------
    @app.get("/health")
    def health() -> dict:
        """Vérifie l'état de santé de l'API et de ses composants."""
        uptime = round(time.time() - _start_time, 1)
        result: dict = {
            "status": "ok",
            "version": "1.0.0",
            "uptime_seconds": uptime,
            "components": {},
        }

        # Check database
        try:
            db = SessionLocal()
            db.execute(text("SELECT 1"))
            db.close()
            result["components"]["database"] = "ok"
        except Exception:
            result["components"]["database"] = "error"
            result["status"] = "degraded"

        # Check Redis
        try:
            from apps.api.cache import get_redis_client

            r = get_redis_client()
            if r is not None:
                r.ping()
                result["components"]["redis"] = "ok"
            else:
                result["components"]["redis"] = "unavailable"
        except Exception:
            result["components"]["redis"] = "error"

        return result

    @app.get("/protected-check")
    def protected_check(
        _: None = Depends(require_api_key),
    ) -> dict[str, str]:
        """Vérifie que l'authentification par clé API fonctionne."""
        return {"status": "ok"}

    # -------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://web:3000",
        ],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -------------------------------------------------------------------
    # Prometheus metrics
    # -------------------------------------------------------------------
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/health", "/metrics"],
    ).instrument(app).expose(app, endpoint="/metrics")

    # -------------------------------------------------------------------
    # Routers
    # -------------------------------------------------------------------
    app.include_router(auth.router, prefix="/auth", tags=["auth"])
    app.include_router(events.router, prefix="/events", tags=["events"])
    app.include_router(rules.router, prefix="/rules", tags=["rules"])
    app.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
    app.include_router(stats.router, prefix="/stats", tags=["stats"])
    app.include_router(anomaly.router, prefix="/anomaly", tags=["anomaly"])
    app.include_router(ml.router)
    app.include_router(chat.router, prefix="/chat", tags=["chat"])
    app.include_router(
        threat_scores.router,
        prefix="/threat-scores",
        tags=["threat-scores"],
    )
    app.include_router(triage.router, prefix="/triage", tags=["triage"])
    app.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
    app.include_router(scanner.router, prefix="/scanner", tags=["scanner"])
    app.include_router(admin.router, prefix="/admin", tags=["admin"])
    app.include_router(export.router, prefix="/export", tags=["export"])
    app.include_router(ws.router, tags=["websocket"])

    return app


app = create_app()
