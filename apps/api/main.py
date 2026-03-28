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
    investigate,
    log_sources,
    pentest,
    recon,
    ml,
    rules,
    scan_history,
    scanner,
    sigma,
    stats,
    threat_intel,
    threat_scores,
    triage,
    wordlists,
    ws,
)
from apps.api.pentest_nvd import router as pentest_nvd_router
from apps.api.pentest_pipeline import router as pentest_pipeline_router
from apps.api.pentest_sessions import router as pentest_sessions_router
from apps.api.pentest_stream import router as pentest_stream_router
from apps.api.pentest_stealth import router as pentest_stealth_router
from apps.api.pentest_network_evasion import router as pentest_network_evasion_router
from apps.api.pentest_templates import router as pentest_templates_router
from apps.api.pentest_hash_cracker import router as pentest_hash_cracker_router
from apps.api.pentest_report import router as pentest_report_router
from apps.api.pentest_wordlist_gen import router as pentest_wordgen_router
from apps.api.pentest_deep_scan import router as pentest_deep_scan_router
from apps.api.pentest_blind_extract import router as pentest_blind_router
from apps.api.pentest_oob_server import router as pentest_oob_router
from apps.api.pentest_oob_server import callback_router as oob_callback_router
from apps.api.pentest_ssrf_advanced import router as pentest_ssrf_router
from apps.api.pentest_subdomain_discovery import router as pentest_subdomain_router
from apps.api.pentest_waf_bypass import router as pentest_waf_bypass_router
from apps.api.pentest_exfiltration import router as pentest_exfil_router
from apps.api.pentest_persistence import router as pentest_persist_router
from apps.api.pentest_antiforensics import router as pentest_antiforensics_router
from apps.api.pentest_killchain import router as pentest_killchain_router
from apps.api.pentest_shell_handler import router as pentest_shell_router
from apps.api.pentest_shell_handler import ws_router as shell_ws_router
from apps.api.pentest_chain_engine import router as pentest_chain_router
from apps.api.pentest_sqli_engine import router as pentest_sqli_router
from apps.api.pentest_session_manager import router as pentest_sessmgr_router
from apps.api.pentest_privesc import router as pentest_privesc_router
from apps.api.pentest_cred_harvester import router as pentest_creds_router
from apps.api.pentest_lateral import router as pentest_lateral_router
from apps.api.pentest_xss_engine import router as pentest_xss_engine_router
from apps.api.pentest_lfi_rce import router as pentest_lfi_rce_router
from apps.api.pentest_protocol_exploit import router as pentest_protocols_router
from apps.api.pentest_shell_bridge import router as pentest_bridge_router
from apps.api.pentest_c2_server import router as pentest_c2_router
from apps.api.pentest_c2_server import beacon_router as c2_beacon_router
from apps.api.pentest_http_proxy import router as pentest_proxy_router
from apps.api.pentest_http_proxy import ws_router as proxy_ws_router
from apps.api.pentest_evasion import router as pentest_evasion_router
from apps.api.pentest_fuzzer import router as pentest_fuzzer_router
from apps.api.pentest_net_scanner import router as pentest_netscan_router
from apps.api.pentest_exploit_dev import router as pentest_exploitdev_router
from apps.api.pentest_ai_assistant import router as pentest_ai_router
from apps.api.pentest_workflows import router as pentest_workflows_router
from apps.api.pentest_live_dashboard import router as pentest_live_router
from apps.api.pentest_headless_scanner import router as pentest_headless_router
from apps.api.pentest_auto_exploit import router as pentest_autoexploit_router
from apps.api.pentest_autochain import router as pentest_autochain_router
from apps.api.pentest_curl_client import router as pentest_curl_router
from apps.api.pentest_http_history import router as pentest_http_history_router
from apps.api.pentest_payload_obfuscation import router as pentest_obfuscation_router
from apps.api.pentest_traffic_shaping import router as pentest_traffic_router
from apps.api.routes.findings import router as findings_router
from apps.api.pentest_vuln_correlator import router as pentest_correlator_router
from apps.api.pentest_exploit_dispatcher import router as pentest_dispatcher_router
from apps.api.pentest_race_condition import router as pentest_race_router
from apps.api.pentest_websocket import router as pentest_ws_security_router
from apps.api.pentest_api_fuzzer import router as pentest_api_fuzzer_router
from apps.api.pentest_jwt_attack import router as pentest_jwt_router
from apps.api.pentest_ssti_engine import router as pentest_ssti_router
from apps.api.pentest_deserialization import router as pentest_deser_router
from apps.api.pentest_cloud_scanner import router as pentest_cloud_router
from apps.api.pentest_ad_attack import router as pentest_ad_router
from apps.api.pentest_ai_vuln_analyzer import router as pentest_ai_vuln_router
from apps.api.pentest_smart_payload import router as pentest_smart_payload_router
from apps.api.pentest_iot_analyzer import router as pentest_iot_router
from apps.api.pentest_mobile_tester import router as pentest_mobile_router
from apps.api.pentest_adversary_emulation import router as pentest_adversary_router
from apps.api.pentest_phishing import router as pentest_phishing_router
from apps.api.pentest_social_engineering import router as pentest_social_router
from apps.api.pentest_network_mapper import router as pentest_netmap_router
from apps.api.pentest_compliance import router as pentest_compliance_router
from apps.api.pentest_threat_model import router as pentest_threat_model_router
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
    """Cree ou met a jour le compte admin par defaut."""
    import uuid
    from datetime import datetime, timezone
    from apps.api.auth import hash_password
    from apps.api.models.user import User

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == "admin").first()
        if existing:
            # Reset password to ensure it works
            existing.hashed_password = hash_password("admin")
            existing.is_active = True
            db.commit()
            logger.info("default_admin_password_reset", username="admin")
            return

        admin = User(
            id=str(uuid.uuid4()),
            username="admin",
            email="admin@cyberdef.local",
            hashed_password=hash_password("admin"),
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
    app.include_router(
        threat_intel.router,
        prefix="/threat-intel",
        tags=["threat-intel"],
    )
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

    return app


app = create_app()
