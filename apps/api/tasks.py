"""Tâches Celery pour le traitement en arrière-plan."""

from __future__ import annotations

import logging

from apps.api.celery_app import celery
from apps.api.db.session import SessionLocal
from apps.api.middleware.metrics import celery_tasks_total

logger = logging.getLogger(__name__)


@celery.task(name="apps.api.tasks.task_run_detection")
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
        celery_tasks_total.labels(task_name="run_detection", status="failure").inc()
        logger.exception("Detection task failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_compute_threat_scores")
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
        celery_tasks_total.labels(task_name="compute_threat_scores", status="failure").inc()
        logger.exception("Threat score task failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_run_anomaly")
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
        celery_tasks_total.labels(task_name="run_anomaly", status="failure").inc()
        logger.exception("Anomaly task failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_run_ml_detect")
def task_run_ml_detect() -> dict:
    """Entraîne Isolation Forest et détecte les anomalies en arrière-plan."""
    from apps.api.detection.ml_anomaly import train_and_detect as run_ml_detection

    db = SessionLocal()
    try:
        result = run_ml_detection(db)
        celery_tasks_total.labels(task_name="run_ml_detect", status="success").inc()
        return result
    except Exception:
        celery_tasks_total.labels(task_name="run_ml_detect", status="failure").inc()
        logger.exception("ML detection task failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.tasks.task_send_alert")
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
