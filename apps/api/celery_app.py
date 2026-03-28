"""Configuration de l'application Celery avec le broker Redis."""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from apps.api.config import get_settings

settings = get_settings()

celery = Celery(
    "siem",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["apps.api.tasks"],
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
)

# Periodic tasks (Celery Beat)
celery.conf.beat_schedule = {
    "run-detection-every-2-min": {
        "task": "apps.api.tasks.task_run_detection",
        "schedule": 120.0,  # every 2 minutes
    },
    "compute-threat-scores-every-5-min": {
        "task": "apps.api.tasks.task_compute_threat_scores",
        "schedule": 300.0,  # every 5 minutes
    },
    "run-anomaly-every-3-min": {
        "task": "apps.api.tasks.task_run_anomaly",
        "schedule": 180.0,  # every 3 minutes
    },
    "refresh-ti-cache-every-hour": {
        "task": "apps.api.tasks.task_refresh_ti_cache",
        "schedule": 3600.0,  # every 1 hour
    },
}
