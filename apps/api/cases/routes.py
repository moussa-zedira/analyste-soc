"""Routes Case Management."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.cases.service import (
    add_evidence,
    append_custody,
    assign_case,
    case_to_dict,
    close_case,
    compute_sla_status,
    create_case,
    scan_sla_breaches,
    transition_case,
)
from apps.api.db.session import get_db
from apps.api.models.case import Case, CaseEvidence, CaseTimelineEntry

router = APIRouter(prefix="/cases", tags=["Case Management"])


# ── Schemas ─────────────────────────────────────────────────────────────


class CreateCaseRequest(BaseModel):
    title: str
    description: str = ""
    priority: str = "medium"
    severity: str = "medium"
    incident_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    sla_response_minutes: int = 60
    sla_resolution_minutes: int = 480


class TransitionRequest(BaseModel):
    status: str
    note: str = ""


class AssignRequest(BaseModel):
    assignee_id: str | None = None
    assignee_username: str | None = None


class CloseRequest(BaseModel):
    resolution: str
    summary: str = ""


class EvidenceRequest(BaseModel):
    kind: str
    title: str
    content: str
    extra: dict[str, Any] = Field(default_factory=dict)


class CustodyAppendRequest(BaseModel):
    action: str


# ── Routes ──────────────────────────────────────────────────────────────


@router.post("/", status_code=201)
def post_case(
    body: CreateCaseRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        case = create_case(
            db,
            title=body.title,
            description=body.description,
            priority=body.priority,
            severity=body.severity,
            incident_ids=body.incident_ids,
            tags=body.tags,
            sla_response_minutes=body.sla_response_minutes,
            sla_resolution_minutes=body.sla_resolution_minutes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return case_to_dict(case)


@router.get("/")
def list_cases(
    status: str | None = None,
    priority: str | None = None,
    assignee_id: str | None = None,
    sla_breached: bool | None = None,
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    q = db.query(Case)
    if status:
        q = q.filter(Case.status == status)
    if priority:
        q = q.filter(Case.priority == priority)
    if assignee_id:
        q = q.filter(Case.assignee_id == assignee_id)
    if sla_breached is not None:
        q = q.filter(Case.sla_breached.is_(sla_breached))
    items = q.order_by(Case.created_at.desc()).limit(limit).all()
    return {"cases": [case_to_dict(c) for c in items], "count": len(items)}


@router.get("/stats")
def case_stats(db: Session = Depends(get_db)) -> dict[str, Any]:
    total = db.query(Case).count()
    open_count = db.query(Case).filter(Case.status != "closed").count()
    breached = db.query(Case).filter(Case.sla_breached.is_(True)).count()
    by_status: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    for c in db.query(Case).all():
        by_status[c.status] = by_status.get(c.status, 0) + 1
        by_priority[c.priority] = by_priority.get(c.priority, 0) + 1
    return {
        "total": total,
        "open": open_count,
        "sla_breached": breached,
        "by_status": by_status,
        "by_priority": by_priority,
    }


@router.get("/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    return case_to_dict(case)


@router.post("/{case_id}/transition")
def post_transition(
    case_id: str,
    body: TransitionRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        case = transition_case(db, case_id, body.status, note=body.note)
    except LookupError:
        raise HTTPException(status_code=404, detail="case not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return case_to_dict(case)


@router.post("/{case_id}/assign")
def post_assign(
    case_id: str,
    body: AssignRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        case = assign_case(db, case_id, body.assignee_id, body.assignee_username)
    except LookupError:
        raise HTTPException(status_code=404, detail="case not found")
    return case_to_dict(case)


@router.post("/{case_id}/close")
def post_close(
    case_id: str,
    body: CloseRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        case = close_case(db, case_id, body.resolution, summary=body.summary)
    except LookupError:
        raise HTTPException(status_code=404, detail="case not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return case_to_dict(case)


# ── Evidence ────────────────────────────────────────────────────────────


@router.post("/{case_id}/evidence", status_code=201)
def post_evidence(
    case_id: str,
    body: EvidenceRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        ev = add_evidence(
            db, case_id,
            kind=body.kind, title=body.title, content=body.content, extra=body.extra,
        )
    except LookupError:
        raise HTTPException(status_code=404, detail="case not found")
    return _evidence_to_dict(ev)


@router.get("/{case_id}/evidence")
def list_evidence(case_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    items = db.query(CaseEvidence).filter(CaseEvidence.case_id == case_id).all()
    return {"evidence": [_evidence_to_dict(e) for e in items], "count": len(items)}


@router.post("/{case_id}/evidence/{evidence_id}/custody")
def post_custody(
    case_id: str,
    evidence_id: str,
    body: CustodyAppendRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        ev = append_custody(db, evidence_id, body.action)
    except LookupError:
        raise HTTPException(status_code=404, detail="evidence not found")
    return _evidence_to_dict(ev)


# ── Timeline ────────────────────────────────────────────────────────────


@router.get("/{case_id}/timeline")
def get_timeline(case_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    items = (
        db.query(CaseTimelineEntry)
        .filter(CaseTimelineEntry.case_id == case_id)
        .order_by(CaseTimelineEntry.ts.asc())
        .all()
    )
    return {
        "case_id": case_id,
        "timeline": [
            {
                "id": e.id,
                "ts": e.ts.isoformat() if e.ts else None,
                "kind": e.kind,
                "actor_username": e.actor_username,
                "message": e.message,
                "data": e.data,
            }
            for e in items
        ],
        "count": len(items),
    }


# ── SLA ─────────────────────────────────────────────────────────────────


@router.get("/{case_id}/sla")
def get_sla(case_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    return compute_sla_status(case)


@router.post("/sla/scan")
def post_sla_scan(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Detecte les SLA breaches sur l'ensemble des cases ouverts (cron-friendly)."""
    breached = scan_sla_breaches(db)
    return {"newly_breached": breached, "count": len(breached)}


# ── Helpers ─────────────────────────────────────────────────────────────


def _evidence_to_dict(ev: CaseEvidence) -> dict[str, Any]:
    return {
        "id": ev.id,
        "case_id": ev.case_id,
        "kind": ev.kind,
        "title": ev.title,
        "sha256": ev.sha256,
        "extra": ev.extra,
        "collected_by": ev.collected_by,
        "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
        "custody_chain": ev.custody_chain,
        "content_size": len(ev.content or ""),
    }
