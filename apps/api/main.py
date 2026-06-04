"""Point d'entrée de l'application FastAPI pour l'API du tableau de bord de cyberdéfense."""

from __future__ import annotations

import asyncio
import os
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from datetime import UTC

import structlog
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy import text

# Import all models so Base.metadata knows about them.
import apps.api.models  # noqa: F401
from apps.api.ai.routes import router as ai_router
from apps.api.cases.routes import router as cases_router
from apps.api.compliance.routes import router as compliance_router
from apps.api.config import get_settings
from apps.api.db.base import Base
from apps.api.db.session import SessionLocal, engine
from apps.api.logging_config import generate_request_id, setup_logging
from apps.api.middleware.rate_limit import limiter

# Tout le wiring offensif (imports lourds + routers red team / pentest) est
# déporté dans apps.api.pentest.wiring et monté conditionnellement via le flag
# settings.ENABLE_OFFENSIVE (voir create_app). Les helpers défensifs qui
# importent apps.api.pentest.* continuent de fonctionner sans ce wiring.
from apps.api.routes import (
    admin,
    alerts,
    anomaly,
    auth,
    chat,
    correlation,
    cql,
    events,
    export,
    incidents,
    investigate,
    log_sources,
    mitre,
    ml,
    parsers,
    recon,
    rules,
    scan_history,
    scanner,
    sigma,
    soar,
    stats,
    threat_intel,
    threat_scores,
    triage,
    wordlists,
    ws,
)
from apps.api.security import require_api_key
from apps.api.uba.routes import router as uba_router

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
    config_problems = settings.validate_for_prod()
    if config_problems:
        for problem in config_problems:
            logger.error("config_invalid_for_prod", problem=problem)
        raise RuntimeError(
            "Refusing to start in production with weak configuration: " + "; ".join(config_problems)
        )

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

    # Audit signing key warning (V4.3b)
    if not settings.AUDIT_SIGNING_KEY:
        logger.error(
            "audit_signing_key_missing",
            note=(
                "AUDIT_SIGNING_KEY is empty: red team operator audit logs will "
                "use a deterministic fallback key with NO real cryptographic "
                "value. Set a strong random AUDIT_SIGNING_KEY in production."
            ),
        )

    # Create default admin account if no users exist
    _seed_default_admin()

    # Seed built-in SOAR playbooks
    _seed_soar_playbooks()

    # Seed built-in SIGMA rules pack
    _seed_builtin_sigma()

    # ── V4.4 Operator Console: Sliver poller + redteam notifier ──
    # Tolerant si Sliver non configure : le poller catche RuntimeError
    # et passe en mode "sleep long". Skippé entièrement si l'offensif est off.
    redteam_listener_task = None
    if settings.ENABLE_OFFENSIVE:
        try:
            from apps.api.pentest.c2_sliver.notifier import redteam_event_listener
            from apps.api.pentest.c2_sliver.poller import sliver_poller

            await sliver_poller.start()
            redteam_listener_task = asyncio.create_task(
                redteam_event_listener(), name="redteam_event_listener"
            )
            logger.info("v44_operator_console_background_started")
        except Exception:
            logger.exception("v44_operator_console_startup_failed")

    yield

    # Shutdown V4.4
    if settings.ENABLE_OFFENSIVE:
        try:
            from apps.api.pentest.c2_sliver.poller import sliver_poller as _poller

            await _poller.stop()
        except Exception:
            logger.warning("v44_poller_shutdown_failed", exc_info=True)
    if redteam_listener_task is not None:
        redteam_listener_task.cancel()


def _seed_default_admin() -> None:
    """Cree un compte admin uniquement si aucun utilisateur n'existe.

    Ne reset JAMAIS le mot de passe d'un admin existant (faille critique).
    En l'absence d'admin, genere un mot de passe aleatoire affiche une seule fois
    dans les logs au demarrage.
    """
    import os
    import secrets
    import uuid
    from datetime import datetime

    from apps.api.auth import hash_password
    from apps.api.models.user import User

    db = SessionLocal()
    try:
        any_user = db.query(User).first()
        if any_user is not None:
            return

        bootstrap_password = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD") or secrets.token_urlsafe(24)
        admin = User(
            id=str(uuid.uuid4()),
            username="admin",
            email="admin@cyberdef.local",
            hashed_password=hash_password(bootstrap_password),
            role="admin",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        db.add(admin)
        db.commit()
        logger.warning(
            "default_admin_created",
            username="admin",
            bootstrap_password=bootstrap_password,
            note="CHANGE THIS PASSWORD IMMEDIATELY via /auth or admin UI. This message is shown only once.",
        )
    except Exception as exc:
        db.rollback()
        logger.warning("seed_admin_failed", error=str(exc))
    finally:
        db.close()


def _seed_soar_playbooks() -> None:
    """Seed built-in SOAR playbooks on startup."""
    from apps.api.routes.soar import seed_builtin_playbooks

    db = SessionLocal()
    try:
        count = seed_builtin_playbooks(db)
        if count:
            logger.info("soar_playbooks_seeded", count=count)
    except Exception as exc:
        db.rollback()
        logger.warning("soar_seed_failed", error=str(exc))
    finally:
        db.close()


def _seed_builtin_sigma() -> None:
    """Seed le pack SIGMA built-in si non present."""
    from apps.api.detection.sigma_builtin import seed_builtin_sigma

    db = SessionLocal()
    try:
        count = seed_builtin_sigma(db)
        if count:
            logger.info("sigma_builtin_seeded", count=count)
    except Exception as exc:
        db.rollback()
        logger.warning("sigma_seed_failed", error=str(exc))
    finally:
        db.close()


def create_app() -> FastAPI:
    """Construit et retourne l'application FastAPI."""
    kwargs: dict = {}
    # Stealth mode hides the attack surface (Swagger, ReDoc, OpenAPI schema)
    stealth = os.getenv("STEALTH_MODE", "false").lower() in ("1", "true", "yes")
    if settings.ENV == "prod" or stealth:
        kwargs["docs_url"] = None
        kwargs["redoc_url"] = None
        kwargs["openapi_url"] = None

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
    # OpenTelemetry tracing (no-op si OTEL_EXPORTER_OTLP_ENDPOINT vide)
    # -------------------------------------------------------------------
    from apps.api.observability.tracing import setup_tracing

    setup_tracing(app)

    # -------------------------------------------------------------------
    # Request ID middleware (+ propagation trace_id si OTel actif)
    # -------------------------------------------------------------------
    @app.middleware("http")
    async def request_id_middleware(request: Request, call_next):
        """Injecte un identifiant unique + trace_id dans chaque requête HTTP."""
        request_id = generate_request_id()
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        # Si OTel est actif, accroche le trace_id au log context.
        try:
            from opentelemetry import trace as _otel_trace

            span = _otel_trace.get_current_span()
            ctx = span.get_span_context() if span else None
            if ctx and ctx.is_valid:
                structlog.contextvars.bind_contextvars(
                    trace_id=format(ctx.trace_id, "032x"),
                    span_id=format(ctx.span_id, "016x"),
                )
        except Exception:  # noqa: BLE001
            pass

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    # -------------------------------------------------------------------
    # Health checks — separes livez (process) / readyz (DB+Redis)
    # /health garde le format detaille pour compat retro.
    # -------------------------------------------------------------------
    @app.get("/livez")
    def livez() -> dict[str, str]:
        """Liveness : le process repond. Pas de check de dependance."""
        return {"status": "ok"}

    @app.get("/readyz")
    def readyz() -> JSONResponse:
        """Readiness : DB + Redis OK. 503 sinon (utile pour les LB / k8s)."""
        components: dict[str, str] = {}
        ok = True

        try:
            db = SessionLocal()
            db.execute(text("SELECT 1"))
            db.close()
            components["database"] = "ok"
        except Exception:
            components["database"] = "error"
            ok = False

        try:
            from apps.api.cache import get_redis_client

            r = get_redis_client()
            if r is not None:
                r.ping()
                components["redis"] = "ok"
            else:
                components["redis"] = "unavailable"
                ok = False
        except Exception:
            components["redis"] = "error"
            ok = False

        return JSONResponse(
            status_code=200 if ok else 503,
            content={"status": "ready" if ok else "not_ready", "components": components},
        )

    @app.get("/health")
    def health() -> dict:
        """Vue detaillee (compat retro). Renvoie toujours 200, status=degraded si KO."""
        uptime = round(time.time() - _start_time, 1)
        result: dict = {
            "status": "ok",
            "version": "1.0.0",
            "uptime_seconds": uptime,
            "components": {},
        }

        try:
            db = SessionLocal()
            db.execute(text("SELECT 1"))
            db.close()
            result["components"]["database"] = "ok"
        except Exception:
            result["components"]["database"] = "error"
            result["status"] = "degraded"

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
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Requested-With",
            "X-Request-Id",
        ],
        expose_headers=["X-Request-Id"],
        max_age=600,
    )

    # -------------------------------------------------------------------
    # Stealth headers — strip Server/X-Powered-By + security headers
    # -------------------------------------------------------------------
    @app.middleware("http")
    async def _stealth_headers(request, call_next):
        response = await call_next(request)
        for h in ("server", "x-powered-by"):
            if h in response.headers:
                del response.headers[h]
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

    # -------------------------------------------------------------------
    # Prometheus metrics
    # -------------------------------------------------------------------
    Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/health", "/livez", "/readyz", "/metrics"],
    ).instrument(app).expose(app, endpoint="/metrics")

    # Force l'import du module observability pour enregistrer les
    # compteurs metier dans le default registry (sinon /metrics n'expose
    # que les compteurs HTTP standard).
    import apps.api.observability  # noqa: F401

    # -------------------------------------------------------------------
    # Routers
    # -------------------------------------------------------------------
    app.include_router(auth.router, prefix="/auth", tags=["auth"])
    app.include_router(cql.router, tags=["CQL"])
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
    app.include_router(
        investigate.router,
        prefix="/investigate",
        tags=["investigate"],
    )
    app.include_router(
        log_sources.router,
        prefix="/log-sources",
        tags=["log-sources"],
    )
    app.include_router(recon.router, prefix="/recon", tags=["recon"])
    app.include_router(
        scan_history.router,
        prefix="/scans",
        tags=["Scan History"],
    )
    app.include_router(wordlists.router, prefix="/wordlists", tags=["wordlists"])
    app.include_router(sigma.router, prefix="/sigma", tags=["sigma"])
    app.include_router(mitre.router)
    app.include_router(
        parsers.router,
        prefix="/parsers",
        tags=["parsers"],
    )
    app.include_router(
        threat_intel.router,
        prefix="/threat-intel",
        tags=["threat-intel"],
    )
    app.include_router(
        correlation.router,
        tags=["correlation"],
    )
    app.include_router(soar.router, prefix="/soar", tags=["SOAR"])
    app.include_router(ws.router, tags=["websocket"])

    # ── Event Pipeline ──
    from apps.api.routes.pipeline import router as pipeline_router

    app.include_router(pipeline_router, tags=["Pipeline"])

    # ── IOC & Threat Feeds ──
    from apps.api.routes.feeds import router as feeds_router
    from apps.api.routes.ioc import router as ioc_router

    app.include_router(ioc_router, tags=["IOC Management"])
    app.include_router(feeds_router, tags=["Threat Feeds"])

    # ── TAXII 2.1 Server ──
    from apps.api.threat_intel.taxii import router as taxii_router

    app.include_router(taxii_router, tags=["TAXII 2.1"])

    # ── DevSecOps ──
    from apps.api.routes.devsecops import router as devsecops_router

    app.include_router(devsecops_router, tags=["DevSecOps"])

    # ── SOC Enterprise (Vague 12) ──
    app.include_router(uba_router, tags=["UEBA"])
    app.include_router(cases_router, tags=["Case Management"])
    app.include_router(compliance_router, tags=["Compliance"])

    # ── AI Native (Vague 14) ──
    app.include_router(ai_router, tags=["AI Native"])

    # ── SSO OIDC (V4.2) ──
    from apps.api.routes.sso import router as sso_router

    app.include_router(sso_router)

    # ── Outbound Integrations (V4.1) — Jira/ServiceNow/Linear/GitHub ──
    from apps.api.routes.integrations import router as integrations_router

    app.include_router(integrations_router, tags=["Outbound Integrations"])

    # ── Module offensif (red team / pentest) — monté conditionnellement ──
    # Tout le wiring offensif (≈110 routers) vit dans apps.api.pentest.wiring
    # et n'est importé QUE si le flag est actif. Voir config.ENABLE_OFFENSIVE.
    if settings.ENABLE_OFFENSIVE:
        from apps.api.pentest.wiring import register_offensive_routes

        register_offensive_routes(app)
        logger.info("offensive_module_enabled")
    else:
        logger.info("offensive_module_disabled", note="ENABLE_OFFENSIVE=false")

    return app


app = create_app()
