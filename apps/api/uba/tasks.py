"""Taches Celery UEBA — recompute global asynchrone des baselines."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import DBAPIError, OperationalError

from apps.api.celery_app import celery
from apps.api.db.session import SessionLocal
from apps.api.middleware.metrics import celery_tasks_total
from apps.api.uba.engine import update_baselines
from apps.api.uba.peer_groups import assign_peer_groups, compute_peer_stats

logger = logging.getLogger(__name__)

_TRANSIENT_ERRORS = (OperationalError, DBAPIError, ConnectionError, TimeoutError)
_RETRY_KW = {
    "autoretry_for": _TRANSIENT_ERRORS,
    "retry_backoff": True,
    "retry_backoff_max": 600,
    "retry_jitter": True,
    "max_retries": 3,
}


@celery.task(name="apps.api.uba.tasks.recompute_all_baselines_task", **_RETRY_KW)
def recompute_all_baselines_task(lookback_hours: int = 24) -> dict:
    """Rescore global UEBA sur une fenetre etendue (defaut 24h).

    Parcourt tous les events des `lookback_hours` dernieres heures, met a
    jour chaque baseline puis recalcule les peer-groups (z-score). Conçu
    pour tourner en offline (Beat ou trigger manuel via /uba/recompute-all).
    """
    db = SessionLocal()
    try:
        since = datetime.now(UTC) - timedelta(hours=lookback_hours)
        result = update_baselines(db, since=since)
        stats = compute_peer_stats(db)
        peers = assign_peer_groups(db, stats=stats)
        celery_tasks_total.labels(
            task_name="recompute_all_baselines", status="success"
        ).inc()
        result["peer_groups_persisted"] = peers
        result["lookback_hours"] = lookback_hours
        logger.info("UBA recompute_all completed: %s", result)
        return result
    except Exception:
        db.rollback()
        celery_tasks_total.labels(
            task_name="recompute_all_baselines", status="failure"
        ).inc()
        logger.exception("UBA recompute_all failed")
        raise
    finally:
        db.close()
