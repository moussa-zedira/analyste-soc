"""Celery tasks for outbound integrations."""

from __future__ import annotations

import asyncio
import logging

from apps.api.celery_app import celery
from apps.api.db.session import SessionLocal

logger = logging.getLogger(__name__)


@celery.task(name="apps.api.integrations.tasks.sync_all_outbound_tickets_task")
def sync_all_outbound_tickets_task(max_age_minutes: int = 60) -> dict:
    """Periodic sync of all open outbound tickets."""
    from apps.api.integrations.outbound import sync_all_open_tickets

    db = SessionLocal()
    try:
        result = asyncio.run(sync_all_open_tickets(db, max_age_minutes=max_age_minutes))
        logger.info("outbound_tickets_synced %s", result)
        return result
    except Exception:
        db.rollback()
        logger.exception("sync_all_outbound_tickets_task_failed")
        raise
    finally:
        db.close()


@celery.task(name="apps.api.integrations.tasks.dispatch_incident_outbound_task")
def dispatch_incident_outbound_task(incident_payload: dict) -> list[dict]:
    """Async dispatch of one incident to all eligible outbound integrations."""
    from apps.api.integrations.outbound import dispatch_to_integrations

    db = SessionLocal()
    try:
        return asyncio.run(dispatch_to_integrations(db, incident_payload))
    except Exception:
        db.rollback()
        logger.exception("dispatch_incident_outbound_task_failed")
        raise
    finally:
        db.close()
