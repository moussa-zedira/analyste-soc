"""Celery tasks for SOAR playbook execution."""

from __future__ import annotations

import asyncio
import logging

from apps.api.celery_app import celery
from apps.api.db.session import SessionLocal

logger = logging.getLogger(__name__)


@celery.task(
    name="apps.api.soar.tasks.task_execute_playbook",
    bind=True,
    max_retries=0,
    soft_time_limit=1800,
    time_limit=2000,
)
def task_execute_playbook(
    self,
    execution_id: str,
    playbook_id: str,
    input_data: dict | None = None,
    trigger: str = "manual",
    incident_id: str | None = None,
) -> dict:
    """Execute a SOAR playbook in a Celery worker."""
    from apps.api.models.soar import Playbook, PlaybookExecution
    from apps.api.soar.engine import PlaybookEngine

    db = SessionLocal()
    try:
        playbook = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not playbook:
            logger.error("Playbook %s not found", playbook_id)
            return {"status": "error", "error": "Playbook not found"}

        execution = db.query(PlaybookExecution).filter(
            PlaybookExecution.id == execution_id,
        ).first()
        if not execution:
            logger.error("Execution %s not found", execution_id)
            return {"status": "error", "error": "Execution not found"}

        engine = PlaybookEngine(db, dry_run=False)

        # Run the async engine in a new event loop
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                engine.execute(
                    playbook,
                    input_data=input_data,
                    trigger=trigger,
                    created_by=execution.created_by,
                    incident_id=incident_id,
                )
            )
        finally:
            loop.close()

        # The engine already updates the execution record, but we need to
        # handle the case where a *separate* execution record was created
        # by the route. Merge the results into the original record.
        if result.id != execution_id:
            execution.status = result.status
            execution.result = result.result
            execution.error = result.error
            execution.variables = result.variables
            execution.started_at = result.started_at
            execution.finished_at = result.finished_at
            execution.duration_ms = result.duration_ms
            db.commit()
            # Clean up the engine-created duplicate
            db.query(PlaybookExecution).filter(PlaybookExecution.id == result.id).delete()
            db.commit()

        logger.info(
            "SOAR playbook executed: %s (status=%s, duration=%.0fms)",
            playbook.name,
            execution.status,
            execution.duration_ms or 0,
        )
        return {
            "execution_id": execution_id,
            "status": execution.status,
            "duration_ms": execution.duration_ms,
        }

    except Exception as exc:
        logger.exception("SOAR task failed for execution %s", execution_id)
        # Mark execution as failed
        try:
            execution = db.query(PlaybookExecution).filter(
                PlaybookExecution.id == execution_id,
            ).first()
            if execution and execution.status in ("pending", "running"):
                from datetime import datetime, timezone
                execution.status = "failed"
                execution.error = str(exc)
                execution.finished_at = datetime.now(timezone.utc)
                db.commit()
        except Exception:
            db.rollback()
        raise
    finally:
        db.close()


@celery.task(name="apps.api.soar.tasks.task_fire_triggers")
def task_fire_triggers(trigger_type: str, context: dict) -> dict:
    """Check and fire SOAR triggers (called from detection engine, alert system, etc.)."""
    from apps.api.soar.engine import fire_triggers

    db = SessionLocal()
    try:
        loop = asyncio.new_event_loop()
        try:
            executions = loop.run_until_complete(
                fire_triggers(db, trigger_type, context)
            )
        finally:
            loop.close()

        result = {
            "trigger_type": trigger_type,
            "playbooks_triggered": len(executions),
            "executions": [
                {"id": e.id, "playbook": e.playbook_name, "status": e.status}
                for e in executions
            ],
        }
        logger.info("SOAR triggers fired: %s", result)
        return result
    except Exception:
        logger.exception("SOAR trigger task failed")
        raise
    finally:
        db.close()
