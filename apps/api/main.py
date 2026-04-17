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
    correlation,
    cql,
    events,
    export,
    incidents,
    investigate,
    log_sources,
    mitre,
    parsers,
    pentest,
    recon,
    ml,
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
from apps.api.pentest.recon.nvd import router as pentest_nvd_router
from apps.api.pentest.automation.pipeline import router as pentest_pipeline_router
from apps.api.pentest.tools.sessions import router as pentest_sessions_router
from apps.api.pentest.reporting.stream import router as pentest_stream_router
from apps.api.pentest.evasion.stealth import router as pentest_stealth_router
from apps.api.pentest.evasion.network_evasion import router as pentest_network_evasion_router
from apps.api.pentest.reporting.templates import router as pentest_templates_router
from apps.api.pentest.tools.hash_cracker import router as pentest_hash_cracker_router
from apps.api.pentest.reporting.report import router as pentest_report_router
from apps.api.pentest.tools.wordlist_gen import router as pentest_wordgen_router
from apps.api.pentest.recon.deep_scan import router as pentest_deep_scan_router
from apps.api.pentest.exploitation.blind_extract import router as pentest_blind_router
from apps.api.pentest.tools.oob_server import router as pentest_oob_router
from apps.api.pentest.tools.oob_server import callback_router as oob_callback_router
from apps.api.pentest.exploitation.ssrf_advanced import router as pentest_ssrf_router
from apps.api.pentest.recon.subdomain_discovery import router as pentest_subdomain_router
from apps.api.pentest.evasion.waf_bypass import router as pentest_waf_bypass_router
from apps.api.pentest.post_exploit.exfiltration import router as pentest_exfil_router
from apps.api.pentest.post_exploit.persistence import router as pentest_persist_router
from apps.api.pentest.post_exploit.antiforensics import router as pentest_antiforensics_router
from apps.api.pentest.automation.killchain import router as pentest_killchain_router
from apps.api.pentest.post_exploit.shell_handler import router as pentest_shell_router
from apps.api.pentest.post_exploit.shell_handler import ws_router as shell_ws_router
from apps.api.pentest.automation.chain_engine import router as pentest_chain_router
from apps.api.pentest.exploitation.sqli_engine import router as pentest_sqli_router
from apps.api.pentest.tools.session_manager import router as pentest_sessmgr_router
from apps.api.pentest.post_exploit.privesc import router as pentest_privesc_router
from apps.api.pentest.post_exploit.cred_harvester import router as pentest_creds_router
from apps.api.pentest.post_exploit.lateral import router as pentest_lateral_router
from apps.api.pentest.exploitation.xss_engine import router as pentest_xss_engine_router
from apps.api.pentest.exploitation.lfi_rce import router as pentest_lfi_rce_router
from apps.api.pentest.exploitation.protocol_exploit import router as pentest_protocols_router
from apps.api.pentest.post_exploit.shell_bridge import router as pentest_bridge_router
from apps.api.pentest.post_exploit.c2_server import router as pentest_c2_router
from apps.api.pentest.post_exploit.c2_server import beacon_router as c2_beacon_router
from apps.api.pentest.tools.http_proxy import router as pentest_proxy_router
from apps.api.pentest.tools.http_proxy import ws_router as proxy_ws_router
from apps.api.pentest.evasion.evasion import router as pentest_evasion_router
from apps.api.pentest.tools.fuzzer import router as pentest_fuzzer_router
from apps.api.pentest.recon.net_scanner import router as pentest_netscan_router
from apps.api.pentest.automation.exploit_dev import router as pentest_exploitdev_router
from apps.api.pentest.automation.ai_assistant import router as pentest_ai_router
from apps.api.pentest.automation.workflows import router as pentest_workflows_router
from apps.api.pentest.reporting.live_dashboard import router as pentest_live_router
from apps.api.pentest.recon.headless_scanner import router as pentest_headless_router
from apps.api.pentest.automation.auto_exploit import router as pentest_autoexploit_router
from apps.api.pentest.automation.autochain import router as pentest_autochain_router
from apps.api.pentest.tools.curl_client import router as pentest_curl_router
from apps.api.pentest.tools.http_history import router as pentest_http_history_router
from apps.api.pentest.evasion.payload_obfuscation import router as pentest_obfuscation_router
from apps.api.pentest.evasion.traffic_shaping import router as pentest_traffic_router
from apps.api.routes.findings import router as findings_router
from apps.api.pentest.recon.vuln_correlator import router as pentest_correlator_router
from apps.api.pentest.automation.exploit_dispatcher import router as pentest_dispatcher_router
from apps.api.pentest.exploitation.race_condition import router as pentest_race_router
from apps.api.pentest.exploitation.websocket import router as pentest_ws_security_router
from apps.api.pentest.exploitation.api_fuzzer import router as pentest_api_fuzzer_router
from apps.api.pentest.exploitation.jwt_attack import router as pentest_jwt_router
from apps.api.pentest.exploitation.ssti_engine import router as pentest_ssti_router
from apps.api.pentest.exploitation.deserialization import router as pentest_deser_router
from apps.api.pentest.recon.cloud_scanner import router as pentest_cloud_router
from apps.api.pentest.post_exploit.ad_attack import router as pentest_ad_router
from apps.api.pentest.automation.ai_vuln_analyzer import router as pentest_ai_vuln_router
from apps.api.pentest.exploitation.smart_payload import router as pentest_smart_payload_router
from apps.api.pentest.recon.iot_analyzer import router as pentest_iot_router
from apps.api.pentest.recon.mobile_tester import router as pentest_mobile_router
from apps.api.pentest.post_exploit.adversary_emulation import router as pentest_adversary_router
from apps.api.pentest.post_exploit.phishing import router as pentest_phishing_router
from apps.api.pentest.post_exploit.social_engineering import router as pentest_social_router
from apps.api.pentest.recon.network_mapper import router as pentest_netmap_router
from apps.api.pentest.automation.compliance import router as pentest_compliance_router
from apps.api.pentest.automation.threat_model import router as pentest_threat_model_router
from apps.api.pentest.post_exploit.executor import router as pentest_executor_router
from apps.api.pentest.post_exploit.executor import ws_router as executor_ws_router
from apps.api.pentest.recon.network_exec import router as pentest_network_exec_router
from apps.api.pentest.recon.web_crawler import router as pentest_web_crawler_router
from apps.api.pentest.recon.auth_scanner import router as pentest_auth_scanner_router
from apps.api.pentest.tools.interceptor import router as pentest_interceptor_router
from apps.api.pentest.tools.interceptor import ws_router as interceptor_ws_router
from apps.api.pentest.implants.payload_engine import router as pentest_payload_engine_router
from apps.api.pentest.recon.vuln_scanner import router as pentest_vuln_scanner_router
from apps.api.pentest.tools.brute import router as pentest_brute_router
from apps.api.routes.orchestrator import router as orchestrator_router
from apps.api.routes.orchestrator import ws_router as orchestrator_ws_router
from apps.api.pentest.campaign.routes import router as campaign_router
from apps.api.pentest.campaign.routes import ws_router as campaign_ws_router
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
    config_problems = settings.validate_for_prod()
    if config_problems:
        for problem in config_problems:
            logger.error("config_invalid_for_prod", problem=problem)
        raise RuntimeError(
            "Refusing to start in production with weak configuration: "
            + "; ".join(config_problems)
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

    # Create default admin account if no users exist
    _seed_default_admin()

    # Seed built-in SOAR playbooks
    _seed_soar_playbooks()

    # Seed built-in SIGMA rules pack
    _seed_builtin_sigma()

    yield


def _seed_default_admin() -> None:
    """Cree un compte admin uniquement si aucun utilisateur n'existe.

    Ne reset JAMAIS le mot de passe d'un admin existant (faille critique).
    En l'absence d'admin, genere un mot de passe aleatoire affiche une seule fois
    dans les logs au demarrage.
    """
    import os
    import secrets
    import uuid
    from datetime import datetime, timezone
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
            created_at=datetime.now(timezone.utc),
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
    app.include_router(pentest.router, prefix="/pentest", tags=["pentest"])
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
    app.include_router(pentest_stream_router, tags=["Pentest Stream"])
    app.include_router(pentest_pipeline_router, tags=["Pentest Pipeline"])
    app.include_router(pentest_sessions_router, tags=["Pentest Sessions"])
    app.include_router(pentest_nvd_router, tags=["NVD CVE"])
    app.include_router(pentest_stealth_router, tags=["Pentest Stealth"])
    app.include_router(pentest_templates_router, tags=["Pentest Templates"])
    app.include_router(pentest_network_evasion_router, tags=["Network Evasion"])
    app.include_router(pentest_hash_cracker_router, tags=["Hash Cracker"])
    app.include_router(pentest_report_router, tags=["Pentest Report"])
    app.include_router(pentest_wordgen_router, tags=["Wordlist Generator"])
    app.include_router(pentest_deep_scan_router, tags=["Deep Scan"])
    app.include_router(pentest_blind_router, tags=["Blind Extraction"])
    app.include_router(pentest_oob_router, tags=["OOB Callback"])
    app.include_router(oob_callback_router, tags=["OOB Receiver"])
    app.include_router(pentest_ssrf_router, tags=["SSRF Advanced"])
    app.include_router(pentest_subdomain_router, tags=["Subdomain Discovery"])
    app.include_router(pentest_waf_bypass_router, tags=["WAF Bypass"])
    app.include_router(pentest_exfil_router, tags=["Exfiltration"])
    app.include_router(pentest_persist_router, tags=["Persistence"])
    app.include_router(pentest_antiforensics_router, tags=["Anti-Forensics"])
    app.include_router(pentest_killchain_router, tags=["Kill Chain"])
    app.include_router(pentest_shell_router, tags=["Shell Handler"])
    app.include_router(shell_ws_router, tags=["Shell Handler WS"])
    app.include_router(pentest_chain_router, tags=["Attack Chain"])
    app.include_router(pentest_sqli_router, tags=["SQLi Engine"])
    app.include_router(pentest_sessmgr_router, tags=["Session Manager"])
    app.include_router(pentest_privesc_router, tags=["Privilege Escalation"])
    app.include_router(pentest_creds_router, tags=["Credential Auditor"])
    app.include_router(pentest_lateral_router, tags=["Lateral Movement"])
    app.include_router(pentest_xss_engine_router, tags=["XSS Engine"])
    app.include_router(pentest_lfi_rce_router, tags=["LFI to RCE"])
    app.include_router(pentest_protocols_router, tags=["Protocol Exploiter"])
    app.include_router(pentest_bridge_router, tags=["Execution Bridge"])
    app.include_router(pentest_c2_router, tags=["C2 Server"])
    app.include_router(c2_beacon_router, tags=["C2 Beacon"])
    app.include_router(pentest_proxy_router, tags=["HTTP Proxy"])
    app.include_router(proxy_ws_router, tags=["HTTP Proxy WS"])
    app.include_router(pentest_evasion_router, tags=["AV/EDR Evasion"])
    app.include_router(pentest_fuzzer_router, tags=["Fuzzer"])
    app.include_router(pentest_netscan_router, tags=["Network Scanner"])
    app.include_router(pentest_exploitdev_router, tags=["Exploit Dev"])
    app.include_router(pentest_ai_router, tags=["AI Assistant"])
    app.include_router(pentest_workflows_router, tags=["Workflows"])
    app.include_router(pentest_live_router, tags=["Live Dashboard"])
    app.include_router(pentest_headless_router, tags=["Headless Scanner"])
    app.include_router(pentest_autoexploit_router, tags=["Auto-Exploit"])
    app.include_router(pentest_autochain_router, tags=["Auto-Chain"])
    app.include_router(pentest_curl_router, tags=["Curl Client"])
    app.include_router(pentest_http_history_router, tags=["HTTP History"])
    app.include_router(pentest_obfuscation_router, tags=["Payload Obfuscation"])
    app.include_router(pentest_traffic_router, tags=["Traffic Shaping"])
    app.include_router(findings_router, prefix="/findings", tags=["Findings"])
    app.include_router(pentest_correlator_router, tags=["Vuln Correlator"])
    app.include_router(pentest_dispatcher_router, tags=["Exploit Dispatcher"])
    app.include_router(pentest_race_router, tags=["Race Condition"])
    app.include_router(pentest_ws_security_router, tags=["WebSocket Security"])
    app.include_router(pentest_api_fuzzer_router, tags=["API Fuzzer"])
    app.include_router(pentest_jwt_router, tags=["JWT Attack"])
    app.include_router(pentest_ssti_router, tags=["SSTI Engine"])
    app.include_router(pentest_deser_router, tags=["Deserialization"])
    app.include_router(pentest_cloud_router, tags=["Cloud Scanner"])
    app.include_router(pentest_ad_router, tags=["AD Attack"])
    app.include_router(pentest_ai_vuln_router, tags=["AI Vuln Analyzer"])
    app.include_router(pentest_smart_payload_router, tags=["Smart Payload"])
    app.include_router(pentest_iot_router, tags=["IoT Analyzer"])
    app.include_router(pentest_mobile_router, tags=["Mobile Tester"])
    app.include_router(pentest_adversary_router, tags=["Adversary Emulation"])
    app.include_router(pentest_phishing_router, tags=["Phishing Campaigns"])
    app.include_router(pentest_social_router, tags=["Social Engineering"])
    app.include_router(pentest_netmap_router, tags=["Network Mapper"])
    app.include_router(pentest_compliance_router, tags=["Compliance Scanner"])
    app.include_router(pentest_threat_model_router, tags=["Threat Modeling"])

    # ── Real Execution Modules ──
    app.include_router(pentest_executor_router, tags=["Execution Engine"])
    app.include_router(executor_ws_router, tags=["Execution Engine WS"])
    app.include_router(pentest_network_exec_router, tags=["Network Exec"])
    app.include_router(pentest_web_crawler_router, tags=["Web Crawler"])
    app.include_router(pentest_auth_scanner_router, tags=["Auth Scanner"])
    app.include_router(pentest_interceptor_router, tags=["HTTP Interceptor"])
    app.include_router(interceptor_ws_router, tags=["HTTP Interceptor WS"])
    app.include_router(pentest_payload_engine_router, tags=["Payload Engine"])
    app.include_router(pentest_vuln_scanner_router, tags=["Vulnerability Scanner"])
    app.include_router(pentest_brute_router, tags=["Brute Force"])

    # ── Event Pipeline ──
    from apps.api.routes.pipeline import router as pipeline_router
    app.include_router(pipeline_router, tags=["Pipeline"])

    # ── IOC & Threat Feeds ──
    from apps.api.routes.ioc import router as ioc_router
    from apps.api.routes.feeds import router as feeds_router
    app.include_router(ioc_router, tags=["IOC Management"])
    app.include_router(feeds_router, tags=["Threat Feeds"])

    # ── TAXII 2.1 Server ──
    from apps.api.threat_intel.taxii import router as taxii_router
    app.include_router(taxii_router, tags=["TAXII 2.1"])

    # ── DevSecOps ──
    from apps.api.routes.devsecops import router as devsecops_router
    app.include_router(devsecops_router, tags=["DevSecOps"])

    # ── Implant Builder ──
    from apps.api.routes.implants import router as implants_router
    app.include_router(implants_router, tags=["Implant Builder"])

    # ── Pentest Orchestrator ──
    app.include_router(orchestrator_router, tags=["Pentest Orchestrator"])
    app.include_router(orchestrator_ws_router, tags=["Orchestrator WebSocket"])

    # ── Red Team Campaign Engine (Vague 11) ──
    app.include_router(campaign_router, tags=["Red Team Campaign"])
    app.include_router(campaign_ws_router, tags=["Red Team Campaign"])

    return app


app = create_app()
