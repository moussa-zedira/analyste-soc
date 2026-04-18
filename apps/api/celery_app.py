"""Configuration de l'application Celery avec le broker Redis."""

from __future__ import annotations

import time

from celery import Celery
from celery.schedules import crontab
from celery.signals import task_postrun, task_prerun, worker_process_init

from apps.api.config import get_settings

settings = get_settings()

celery = Celery(
    "siem",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "apps.api.tasks",
        "apps.api.soar.tasks",
        "apps.api.uba.tasks",
        "apps.api.integrations.tasks",
        "apps.api.pentest.phishing.tasks",
    ],
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    # Retry policy par defaut — surchargeable par tache
    task_default_retry_delay=30,
    task_default_rate_limit="60/m",
    # Visibilite des taches longues
    task_time_limit=600,
    task_soft_time_limit=540,
    # Resultats: TTL court pour ne pas saturer Redis
    result_expires=3600,
    # Eviter qu'une tache plante perde le broker quand Redis blip
    broker_connection_retry_on_startup=True,
)

# ─────────────────────────────────────────────────────────────────────
# Observabilite : tracing OTel + histogramme de duree par tache
# ─────────────────────────────────────────────────────────────────────
_task_start_times: dict[str, float] = {}


@worker_process_init.connect
def _init_observability(**_kwargs) -> None:
    """Initialise OTel cote worker (no-op si endpoint non configure)."""
    try:
        from apps.api.observability.tracing import setup_celery_tracing

        setup_celery_tracing()
    except Exception:  # noqa: BLE001
        pass


@task_prerun.connect
def _task_started(task_id: str | None = None, **_kwargs) -> None:
    if task_id:
        _task_start_times[task_id] = time.monotonic()


@task_postrun.connect
def _task_finished(
    task_id: str | None = None,
    task=None,
    state: str | None = None,
    **_kwargs,
) -> None:
    started = _task_start_times.pop(task_id or "", None)
    if started is None or task is None:
        return
    duration = time.monotonic() - started
    try:
        from apps.api.observability.metrics import celery_task_duration_seconds

        celery_task_duration_seconds.labels(
            task=task.name,
            result=(state or "UNKNOWN").lower(),
        ).observe(duration)
    except Exception:  # noqa: BLE001
        pass


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
    "sync-outbound-tickets-every-hour": {
        "task": "apps.api.integrations.tasks.sync_all_outbound_tickets_task",
        "schedule": 3600.0,
    },
    "sync-phishing-every-5-minutes": {
        "task": "apps.api.pentest.phishing.tasks.sync_all_phishing_task",
        "schedule": 300.0,
    },
}
