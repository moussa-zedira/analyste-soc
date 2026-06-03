"""Tâches Celery pour le traitement en arrière-plan."""

from __future__ import annotations

import logging
from datetime import UTC

from sqlalchemy.exc import DBAPIError, OperationalError

from apps.api.celery_app import celery
from apps.api.db.session import SessionLocal
from apps.api.middleware.metrics import celery_tasks_total

logger = logging.getLogger(__name__)

# Erreurs transitoires sur lesquelles on retente automatiquement.
# Erreurs metier (ValueError, KeyError) ne sont PAS retentees pour eviter
# les boucles infinies sur donnees corrompues.
_TRANSIENT_ERRORS = (OperationalError, DBAPIError, ConnectionError, TimeoutError)
_RETRY_KW = {
    "autoretry_for": _TRANSIENT_ERRORS,
    "retry_backoff": True,
    "retry_backoff_max": 300,
    "retry_jitter": True,
    "max_retries": 3,
}


@celery.task(name="apps.api.tasks.task_run_detection", **_RETRY_KW)
def task_run_detection() -> dict:
    """Exécute le moteur de détection dans un worker en arrière-plan."""
    from apps.api.detection.engine import run_detection

    db = SessionLocal()
    try:
        result = run_detection(db)
        celery_tasks_total.labels(task_name="run_detection", status="success").inc()
        logger.info("Detection task completed: %s", result)
        return result
    except Exception:
        db.rollback()
        celery_tasks_total.labels(task_name="run_detection", status="failure").inc()
        logger.exception("Detection task failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_compute_threat_scores", **_RETRY_KW)
def task_compute_threat_scores(lookback_hours: int = 24) -> dict:
    """Recalcule les scores de menace en arrière-plan."""
    from apps.api.detection.threat_score import compute_threat_scores

    db = SessionLocal()
    try:
        count = compute_threat_scores(db, lookback_hours=lookback_hours)
        celery_tasks_total.labels(task_name="compute_threat_scores", status="success").inc()
        logger.info("Threat score task completed: %d IPs scored", count)
        return {"ips_scored": count}
    except Exception:
        db.rollback()
        celery_tasks_total.labels(task_name="compute_threat_scores", status="failure").inc()
        logger.exception("Threat score task failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_run_anomaly", **_RETRY_KW)
def task_run_anomaly() -> dict:
    """Exécute la détection d'anomalies en arrière-plan."""
    from apps.api.detection.anomaly import run_anomaly_detection

    db = SessionLocal()
    try:
        result = run_anomaly_detection(db)
        celery_tasks_total.labels(task_name="run_anomaly", status="success").inc()
        logger.info("Anomaly task completed: %s", result)
        return result
    except Exception:
        db.rollback()
        celery_tasks_total.labels(task_name="run_anomaly", status="failure").inc()
        logger.exception("Anomaly task failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_run_ml_detect", **_RETRY_KW)
def task_run_ml_detect() -> dict:
    """Entraîne Isolation Forest et détecte les anomalies en arrière-plan."""
    from apps.api.detection.ml_anomaly import train_and_detect as run_ml_detection

    db = SessionLocal()
    try:
        result = run_ml_detection(db)
        celery_tasks_total.labels(task_name="run_ml_detect", status="success").inc()
        return result
    except Exception:
        db.rollback()
        celery_tasks_total.labels(task_name="run_ml_detect", status="failure").inc()
        logger.exception("ML detection task failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_enrich_event", **_RETRY_KW)
def task_enrich_event(event_id: str) -> dict:
    """Enrichit un event avec les donnees de Threat Intelligence."""
    from apps.api.threat_intel.enrichment import enrich_event_sync

    db = SessionLocal()
    try:
        enrich_event_sync(event_id, db)
        celery_tasks_total.labels(task_name="enrich_event", status="success").inc()
        return {"event_id": event_id, "status": "enriched"}
    except Exception:
        db.rollback()
        celery_tasks_total.labels(task_name="enrich_event", status="failure").inc()
        logger.exception("TI enrichment failed for event %s", event_id)
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_refresh_ti_cache", **_RETRY_KW)
def task_refresh_ti_cache() -> dict:
    """Rafraichit le cache TI expire."""
    from datetime import datetime

    from apps.api.models.ti_cache import TICache

    db = SessionLocal()
    try:
        now = datetime.now(UTC)
        expired = db.query(TICache).filter(TICache.expires_at < now).count()
        db.query(TICache).filter(TICache.expires_at < now).delete()
        db.commit()
        celery_tasks_total.labels(task_name="refresh_ti_cache", status="success").inc()
        logger.info("Cleaned %d expired TI cache entries", expired)
        return {"expired_cleaned": expired}
    except Exception:
        db.rollback()
        celery_tasks_total.labels(task_name="refresh_ti_cache", status="failure").inc()
        logger.exception("TI cache refresh failed")
        raise
    finally:
        db.close()


@celery.task(
    name="apps.api.tasks.task_send_alert",
    autoretry_for=(ConnectionError, TimeoutError),
    retry_backoff=True,
    retry_backoff_max=300,
    retry_jitter=True,
    max_retries=5,
)
def task_send_alert(incident_data: dict) -> dict:
    """Envoie les notifications d'alerte pour un incident."""
    from apps.api.alerting import dispatch_alert

    try:
        dispatch_alert(incident_data)
        celery_tasks_total.labels(task_name="send_alert", status="success").inc()
        return {"status": "sent", "incident_id": incident_data.get("id")}
    except Exception:
        celery_tasks_total.labels(task_name="send_alert", status="failure").inc()
        logger.exception("Alert dispatch failed")
        raise


# ---------------------------------------------------------------------------
# Pipeline tasks
# ---------------------------------------------------------------------------


@celery.task(name="apps.api.tasks.task_process_event")
def task_process_event(raw_event) -> dict:
    """Process a single event through the full pipeline."""
    import asyncio

    from apps.api.pipeline.engine import get_pipeline_engine

    try:
        engine = get_pipeline_engine()
        loop = asyncio.new_event_loop()
        try:
            ctx = loop.run_until_complete(engine.process_event(raw_event))
        finally:
            loop.close()
        celery_tasks_total.labels(task_name="process_event", status="success").inc()
        return {
            "context_id": ctx.context_id,
            "score": ctx.score,
            "detections": len(ctx.detections),
            "ioc_matches": len(ctx.ioc_matches),
            "success": ctx.metadata.get("success", False),
            "total_ms": ctx.metadata.get("total_ms", 0),
        }
    except Exception:
        celery_tasks_total.labels(task_name="process_event", status="failure").inc()
        logger.exception("Pipeline process_event failed")
        raise


@celery.task(name="apps.api.tasks.task_process_batch")
def task_process_batch(events: list) -> dict:
    """Process a batch of events through the pipeline."""
    import asyncio

    from apps.api.pipeline.engine import get_pipeline_engine

    try:
        engine = get_pipeline_engine()
        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(engine.process_batch(events))
        finally:
            loop.close()

        successes = sum(1 for r in results if r.metadata.get("success", False))
        celery_tasks_total.labels(task_name="process_batch", status="success").inc()
        return {
            "total": len(results),
            "success": successes,
            "errors": len(results) - successes,
        }
    except Exception:
        celery_tasks_total.labels(task_name="process_batch", status="failure").inc()
        logger.exception("Pipeline process_batch failed")
        raise


@celery.task(name="apps.api.tasks.task_pipeline_replay")
def task_pipeline_replay(
    query: dict | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
) -> dict:
    """Replay historical events through the pipeline."""
    import asyncio
    from datetime import datetime

    from apps.api.pipeline.engine import get_pipeline_engine

    try:
        engine = get_pipeline_engine()
        time_range = None
        if start_time and end_time:
            s = datetime.fromisoformat(start_time.replace("Z", "+00:00"))
            e = datetime.fromisoformat(end_time.replace("Z", "+00:00"))
            time_range = (s, e)

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(engine.replay(query=query, time_range=time_range))
        finally:
            loop.close()

        celery_tasks_total.labels(task_name="pipeline_replay", status="success").inc()
        return result
    except Exception:
        celery_tasks_total.labels(task_name="pipeline_replay", status="failure").inc()
        logger.exception("Pipeline replay failed")
        raise
