"""API SOAR — orchestration, automatisation et reponse a incident."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.soar import Playbook, PlaybookExecution, PlaybookStepResult
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class PlaybookCreate(BaseModel):
    name: str
    description: str = ""
    category: str = "custom"
    trigger_type: str = "manual"
    trigger_config: dict | None = None
    definition: dict
    tags: list[str] | None = None
    enabled: bool = True


class PlaybookRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str
    category: str
    trigger_type: str
    trigger_config: dict | None
    definition: dict
    enabled: bool
    builtin: bool
    version: int
    tags: list | None
    created_at: datetime
    updated_at: datetime
    created_by: str


class PlaybookSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str
    category: str
    trigger_type: str
    enabled: bool
    builtin: bool
    version: int
    tags: list | None
    created_at: datetime


class ExecutionRequest(BaseModel):
    input_data: dict = Field(default_factory=dict)
    trigger: str = "manual"
    incident_id: str | None = None


class ExecutionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    playbook_id: str
    playbook_name: str
    status: str
    trigger: str
    input_data: dict | None
    result: dict | None
    error: str | None
    dry_run: bool
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: float | None
    created_at: datetime
    created_by: str
    incident_id: str | None


class StepResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    execution_id: str
    step_name: str
    step_index: int
    action: str
    status: str
    input_params: dict | None
    output: dict | None
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: float | None
    skipped: bool
    skip_reason: str | None


class ExecutionDetail(ExecutionRead):
    steps: list[StepResultRead] = []
    variables: dict | None = None


class ActionInfo(BaseModel):
    name: str
    category: str
    description: str
    params_schema: dict


class SoarMetrics(BaseModel):
    total_playbooks: int
    enabled_playbooks: int
    total_executions: int
    completed: int
    failed: int
    cancelled: int
    running: int
    avg_duration_ms: float | None
    success_rate: float
    playbook_usage: list[dict]
    recent_executions: list[dict]


# ---------------------------------------------------------------------------
# Startup: seed built-in playbooks
# ---------------------------------------------------------------------------

def seed_builtin_playbooks(db: Session) -> int:
    """Insert or update built-in playbooks. Returns count of seeded playbooks."""
    from apps.api.soar.playbooks_builtin import BUILTIN_PLAYBOOKS

    count = 0
    for pb_def in BUILTIN_PLAYBOOKS:
        name = pb_def["name"]
        existing = db.query(Playbook).filter(
            Playbook.name == name, Playbook.builtin.is_(True),
        ).first()

        now = datetime.now(timezone.utc)
        if existing:
            existing.definition = pb_def["definition"]
            existing.description = pb_def.get("description", "")
            existing.category = pb_def.get("category", "general")
            existing.trigger_type = pb_def.get("trigger_type", "manual")
            existing.trigger_config = pb_def.get("trigger_config")
            existing.tags = pb_def.get("tags")
            existing.updated_at = now
            existing.version = existing.version + 1
        else:
            playbook = Playbook(
                id=str(uuid.uuid4()),
                name=name,
                description=pb_def.get("description", ""),
                category=pb_def.get("category", "general"),
                trigger_type=pb_def.get("trigger_type", "manual"),
                trigger_config=pb_def.get("trigger_config"),
                definition=pb_def["definition"],
                enabled=True,
                builtin=True,
                version=1,
                tags=pb_def.get("tags"),
                created_at=now,
                updated_at=now,
                created_by="system",
            )
            db.add(playbook)
            count += 1

    db.commit()
    return count


# ---------------------------------------------------------------------------
# Endpoints: Playbooks
# ---------------------------------------------------------------------------

@router.get("/playbooks", response_model=list[PlaybookSummary])
def list_playbooks(
    category: str | None = Query(None),
    trigger_type: str | None = Query(None),
    enabled_only: bool = Query(False),
    db: Session = Depends(get_db),
):
    """List all SOAR playbooks with optional filters."""
    q = db.query(Playbook)
    if category:
        q = q.filter(Playbook.category == category)
    if trigger_type:
        q = q.filter(Playbook.trigger_type == trigger_type)
    if enabled_only:
        q = q.filter(Playbook.enabled.is_(True))
    return q.order_by(Playbook.name).all()


@router.post("/playbooks", response_model=PlaybookRead, status_code=status.HTTP_201_CREATED)
def create_playbook(body: PlaybookCreate, db: Session = Depends(get_db)):
    """Create a custom SOAR playbook."""
    from apps.api.soar.engine import validate_playbook_definition

    errors = validate_playbook_definition(body.definition)
    if errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"validation_errors": errors},
        )

    now = datetime.now(timezone.utc)
    playbook = Playbook(
        id=str(uuid.uuid4()),
        name=body.name,
        description=body.description,
        category=body.category,
        trigger_type=body.trigger_type,
        trigger_config=body.trigger_config,
        definition=body.definition,
        enabled=body.enabled,
        builtin=False,
        version=1,
        tags=body.tags,
        created_at=now,
        updated_at=now,
        created_by="api",
    )
    db.add(playbook)
    db.commit()
    db.refresh(playbook)
    return playbook


@router.get("/playbooks/{playbook_id}", response_model=PlaybookRead)
def get_playbook(playbook_id: str, db: Session = Depends(get_db)):
    """Get playbook details including full definition."""
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return pb


@router.post("/playbooks/{playbook_id}/execute", response_model=ExecutionRead)
async def execute_playbook(
    playbook_id: str,
    body: ExecutionRequest,
    db: Session = Depends(get_db),
):
    """Execute a playbook (async). Returns execution record immediately."""
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    if not pb.enabled:
        raise HTTPException(status_code=400, detail="Playbook is disabled")

    # Launch via Celery for long-running execution
    from apps.api.soar.tasks import task_execute_playbook
    now = datetime.now(timezone.utc)
    execution_id = str(uuid.uuid4())

    execution = PlaybookExecution(
        id=execution_id,
        playbook_id=pb.id,
        playbook_name=pb.name,
        status="pending",
        trigger=body.trigger,
        input_data=body.input_data,
        dry_run=False,
        created_at=now,
        created_by="api",
        incident_id=body.incident_id,
    )
    db.add(execution)
    db.commit()

    # Dispatch to Celery
    celery_result = task_execute_playbook.delay(
        execution_id=execution_id,
        playbook_id=playbook_id,
        input_data=body.input_data,
        trigger=body.trigger,
        incident_id=body.incident_id,
    )
    execution.celery_task_id = celery_result.id
    db.commit()
    db.refresh(execution)

    return execution


@router.get("/playbooks/{playbook_id}/history", response_model=list[ExecutionRead])
def get_playbook_history(
    playbook_id: str,
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
):
    """Get execution history for a playbook."""
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")
    return (
        db.query(PlaybookExecution)
        .filter(PlaybookExecution.playbook_id == playbook_id)
        .order_by(PlaybookExecution.created_at.desc())
        .limit(limit)
        .all()
    )


@router.post("/playbooks/{playbook_id}/simulate", response_model=ExecutionRead)
async def simulate_playbook(
    playbook_id: str,
    body: ExecutionRequest,
    db: Session = Depends(get_db),
):
    """Dry-run simulation of a playbook — no real actions executed."""
    pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook not found")

    from apps.api.soar.engine import PlaybookEngine

    engine = PlaybookEngine(db, dry_run=True)
    execution = await engine.execute(
        pb,
        input_data=body.input_data,
        trigger="simulation",
        created_by="api",
        incident_id=body.incident_id,
    )
    return execution


# ---------------------------------------------------------------------------
# Endpoints: Actions
# ---------------------------------------------------------------------------

@router.get("/actions", response_model=list[ActionInfo])
def list_available_actions():
    """List all registered SOAR actions."""
    from apps.api.soar.actions import list_actions
    return list_actions()


# ---------------------------------------------------------------------------
# Endpoints: Executions
# ---------------------------------------------------------------------------

@router.get("/executions", response_model=list[ExecutionRead])
def list_executions(
    status_filter: str | None = Query(None, alias="status"),
    playbook_id: str | None = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
):
    """List all SOAR executions."""
    q = db.query(PlaybookExecution)
    if status_filter:
        q = q.filter(PlaybookExecution.status == status_filter)
    if playbook_id:
        q = q.filter(PlaybookExecution.playbook_id == playbook_id)
    return q.order_by(PlaybookExecution.created_at.desc()).limit(limit).all()


@router.get("/executions/{execution_id}", response_model=ExecutionDetail)
def get_execution_detail(execution_id: str, db: Session = Depends(get_db)):
    """Get execution detail with all step results."""
    execution = db.query(PlaybookExecution).filter(
        PlaybookExecution.id == execution_id,
    ).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")

    steps = (
        db.query(PlaybookStepResult)
        .filter(PlaybookStepResult.execution_id == execution_id)
        .order_by(PlaybookStepResult.step_index)
        .all()
    )

    result = ExecutionDetail.model_validate(execution)
    result.steps = [StepResultRead.model_validate(s) for s in steps]
    result.variables = execution.variables
    return result


@router.post("/executions/{execution_id}/cancel")
def cancel_execution(execution_id: str, db: Session = Depends(get_db)):
    """Cancel a running execution."""
    execution = db.query(PlaybookExecution).filter(
        PlaybookExecution.id == execution_id,
    ).first()
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    if execution.status not in ("pending", "running"):
        raise HTTPException(status_code=400, detail=f"Cannot cancel execution in state: {execution.status}")

    # Try to revoke the Celery task
    if execution.celery_task_id:
        try:
            from apps.api.celery_app import celery
            celery.control.revoke(execution.celery_task_id, terminate=True)
        except Exception:
            pass

    execution.status = "cancelled"
    execution.finished_at = datetime.now(timezone.utc)
    db.commit()

    # Publish cancel status
    try:
        from apps.api.soar.engine import _publish_status
        _publish_status(execution_id, "cancelled")
    except Exception:
        pass

    return {"id": execution_id, "status": "cancelled"}


# ---------------------------------------------------------------------------
# Endpoints: Metrics
# ---------------------------------------------------------------------------

@router.get("/metrics", response_model=SoarMetrics)
def get_soar_metrics(db: Session = Depends(get_db)):
    """SOAR operational metrics — MTTD, MTTR, playbook usage, success rates."""
    from sqlalchemy import func

    total_pb = db.query(Playbook).count()
    enabled_pb = db.query(Playbook).filter(Playbook.enabled.is_(True)).count()

    total_exec = db.query(PlaybookExecution).count()
    completed = db.query(PlaybookExecution).filter(PlaybookExecution.status == "completed").count()
    failed = db.query(PlaybookExecution).filter(PlaybookExecution.status == "failed").count()
    cancelled = db.query(PlaybookExecution).filter(PlaybookExecution.status == "cancelled").count()
    running = db.query(PlaybookExecution).filter(PlaybookExecution.status.in_(("running", "pending"))).count()

    avg_dur = db.query(func.avg(PlaybookExecution.duration_ms)).filter(
        PlaybookExecution.duration_ms.isnot(None),
    ).scalar()

    success_rate = round(completed / total_exec * 100, 1) if total_exec > 0 else 0.0

    # Playbook usage stats
    usage_rows = (
        db.query(
            PlaybookExecution.playbook_name,
            func.count(PlaybookExecution.id).label("count"),
        )
        .group_by(PlaybookExecution.playbook_name)
        .order_by(func.count(PlaybookExecution.id).desc())
        .limit(15)
        .all()
    )
    playbook_usage = [{"name": r[0], "count": r[1]} for r in usage_rows]

    # Recent executions
    recent = (
        db.query(PlaybookExecution)
        .order_by(PlaybookExecution.created_at.desc())
        .limit(10)
        .all()
    )
    recent_list = [
        {
            "id": e.id,
            "playbook_name": e.playbook_name,
            "status": e.status,
            "trigger": e.trigger,
            "created_at": e.created_at.isoformat(),
            "duration_ms": e.duration_ms,
        }
        for e in recent
    ]

    return SoarMetrics(
        total_playbooks=total_pb,
        enabled_playbooks=enabled_pb,
        total_executions=total_exec,
        completed=completed,
        failed=failed,
        cancelled=cancelled,
        running=running,
        avg_duration_ms=round(avg_dur, 2) if avg_dur else None,
        success_rate=success_rate,
        playbook_usage=playbook_usage,
        recent_executions=recent_list,
    )
