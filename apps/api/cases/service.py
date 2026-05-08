"""Service Case Management : creation, transitions, evidence, SLA monitor."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from apps.api.models.case import Case, CaseEvidence, CaseTimelineEntry

# Workflow valide
VALID_STATUSES = ("open", "triaging", "investigating", "containment", "recovery", "closed")
VALID_PRIORITIES = ("critical", "high", "medium", "low")
VALID_RESOLUTIONS = (
    "true_positive",
    "false_positive",
    "benign",
    "duplicate",
    "mitigated",
)

ALLOWED_TRANSITIONS = {
    "open": {"triaging", "closed"},
    "triaging": {"investigating", "closed"},
    "investigating": {"containment", "closed"},
    "containment": {"recovery", "closed"},
    "recovery": {"closed"},
    "closed": set(),  # immutable une fois ferme (sauf reopen explicite)
}


# ---------------------------------------------------------------------------
# Timeline helper
# ---------------------------------------------------------------------------


def _add_timeline(
    db: Session,
    case_id: str,
    kind: str,
    message: str,
    actor_id: str | None,
    actor_username: str | None,
    data: dict[str, Any] | None = None,
) -> CaseTimelineEntry:
    entry = CaseTimelineEntry(
        id=str(uuid.uuid4()),
        case_id=case_id,
        ts=datetime.now(UTC),
        actor_id=actor_id,
        actor_username=actor_username,
        kind=kind,
        message=message,
        data=data or {},
    )
    db.add(entry)
    return entry


# ---------------------------------------------------------------------------
# CRUD Case
# ---------------------------------------------------------------------------


def create_case(
    db: Session,
    *,
    title: str,
    description: str = "",
    priority: str = "medium",
    severity: str = "medium",
    incident_ids: list[str] | None = None,
    tags: list[str] | None = None,
    sla_response_minutes: int = 60,
    sla_resolution_minutes: int = 480,
    actor_id: str | None = None,
    actor_username: str | None = None,
) -> Case:
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"invalid priority: {priority}")
    now = datetime.now(UTC)
    case = Case(
        id=str(uuid.uuid4()),
        title=title,
        description=description,
        priority=priority,
        severity=severity,
        status="open",
        incident_ids=incident_ids or [],
        tags=tags or [],
        sla_response_minutes=sla_response_minutes,
        sla_resolution_minutes=sla_resolution_minutes,
        created_by=actor_username,
        created_at=now,
        updated_at=now,
    )
    db.add(case)
    _add_timeline(
        db, case.id, "created", f"Case '{title}' created (priority={priority})",
        actor_id, actor_username,
    )
    db.commit()
    return case


def transition_case(
    db: Session,
    case_id: str,
    new_status: str,
    *,
    actor_id: str | None = None,
    actor_username: str | None = None,
    note: str = "",
) -> Case:
    case = db.get(Case, case_id)
    if not case:
        raise LookupError("case not found")
    if new_status not in VALID_STATUSES:
        raise ValueError(f"invalid status: {new_status}")
    allowed = ALLOWED_TRANSITIONS.get(case.status, set())
    if new_status != case.status and new_status not in allowed:
        raise ValueError(f"transition {case.status} -> {new_status} not allowed")
    old = case.status
    case.status = new_status
    case.updated_at = datetime.now(UTC)
    if new_status == "closed":
        case.closed_at = case.updated_at
    if old in ("open",) and new_status != "open" and not case.sla_responded_at:
        case.sla_responded_at = case.updated_at
    _add_timeline(
        db, case_id, "status_change",
        f"{old} -> {new_status}" + (f": {note}" if note else ""),
        actor_id, actor_username, data={"from": old, "to": new_status, "note": note},
    )
    db.commit()
    return case


def assign_case(
    db: Session,
    case_id: str,
    assignee_id: str | None,
    assignee_username: str | None,
    *,
    actor_id: str | None = None,
    actor_username: str | None = None,
) -> Case:
    case = db.get(Case, case_id)
    if not case:
        raise LookupError("case not found")
    case.assignee_id = assignee_id
    case.assignee_username = assignee_username
    case.updated_at = datetime.now(UTC)
    _add_timeline(
        db, case_id, "assignment",
        f"assigned to {assignee_username or assignee_id or '(unassigned)'}",
        actor_id, actor_username,
        data={"assignee_id": assignee_id, "assignee_username": assignee_username},
    )
    db.commit()
    return case


def close_case(
    db: Session,
    case_id: str,
    resolution: str,
    *,
    actor_id: str | None = None,
    actor_username: str | None = None,
    summary: str = "",
) -> Case:
    if resolution not in VALID_RESOLUTIONS:
        raise ValueError(f"invalid resolution: {resolution}")
    case = transition_case(
        db, case_id, "closed",
        actor_id=actor_id, actor_username=actor_username, note=summary,
    )
    case.resolution = resolution
    db.commit()
    return case


# ---------------------------------------------------------------------------
# Evidence + chain of custody
# ---------------------------------------------------------------------------


def _custody_link(prev_hash: str, actor: str, action: str, ts: datetime) -> dict:
    payload = json.dumps(
        {"prev": prev_hash, "actor": actor, "action": action, "ts": ts.isoformat()},
        sort_keys=True,
    ).encode()
    h = hashlib.sha256(payload).hexdigest()
    return {"actor": actor, "action": action, "ts": ts.isoformat(), "prev_hash": prev_hash, "hash": h}


def add_evidence(
    db: Session,
    case_id: str,
    *,
    kind: str,
    title: str,
    content: str,
    extra: dict[str, Any] | None = None,
    actor_id: str | None = None,
    actor_username: str | None = None,
) -> CaseEvidence:
    case = db.get(Case, case_id)
    if not case:
        raise LookupError("case not found")
    now = datetime.now(UTC)
    sha = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
    custody = [_custody_link(prev_hash="", actor=actor_username or "system",
                             action="collected", ts=now)]
    ev = CaseEvidence(
        id=str(uuid.uuid4()),
        case_id=case_id,
        kind=kind,
        title=title,
        content=content,
        sha256=sha,
        extra=extra or {},
        collected_by=actor_username,
        collected_at=now,
        custody_chain=custody,
    )
    db.add(ev)
    _add_timeline(
        db, case_id, "evidence_added",
        f"+ evidence [{kind}] {title} (sha256={sha[:12]}…)",
        actor_id, actor_username,
        data={"evidence_id": ev.id, "sha256": sha},
    )
    db.commit()
    return ev


def append_custody(
    db: Session,
    evidence_id: str,
    action: str,
    *,
    actor_id: str | None = None,
    actor_username: str | None = None,
) -> CaseEvidence:
    """Ajoute un lien de custody (acces, copie, transfert)."""
    ev = db.get(CaseEvidence, evidence_id)
    if not ev:
        raise LookupError("evidence not found")
    chain = list(ev.custody_chain or [])
    prev = chain[-1]["hash"] if chain else ""
    link = _custody_link(prev, actor_username or "system", action, datetime.now(UTC))
    chain.append(link)
    ev.custody_chain = chain
    db.commit()
    return ev


# ---------------------------------------------------------------------------
# SLA
# ---------------------------------------------------------------------------


def compute_sla_status(case: Case) -> dict[str, Any]:
    now = datetime.now(UTC)
    response_deadline = case.created_at + timedelta(minutes=case.sla_response_minutes)
    resolution_deadline = case.created_at + timedelta(minutes=case.sla_resolution_minutes)
    response_breached = (
        case.sla_responded_at is None and now > response_deadline
    )
    resolution_breached = (
        case.status != "closed" and now > resolution_deadline
    )
    return {
        "response_deadline": response_deadline.isoformat(),
        "resolution_deadline": resolution_deadline.isoformat(),
        "response_breached": response_breached,
        "resolution_breached": resolution_breached,
        "any_breach": response_breached or resolution_breached,
        "minutes_to_resolution": (resolution_deadline - now).total_seconds() / 60,
    }


def scan_sla_breaches(db: Session) -> list[str]:
    """Marque sla_breached=True sur les cases en breach et retourne leurs IDs."""
    breached: list[str] = []
    for case in db.query(Case).filter(Case.status != "closed", Case.sla_breached.is_(False)):
        s = compute_sla_status(case)
        if s["any_breach"]:
            case.sla_breached = True
            breached.append(case.id)
            _add_timeline(
                db, case.id, "sla_breach",
                "SLA breached: " + (
                    "response" if s["response_breached"] else "resolution"
                ),
                None, "system", data=s,
            )
    if breached:
        db.commit()
    return breached


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------


def case_to_dict(case: Case, *, include_sla: bool = True) -> dict[str, Any]:
    out = {
        "id": case.id,
        "title": case.title,
        "description": case.description,
        "status": case.status,
        "priority": case.priority,
        "severity": case.severity,
        "assignee_id": case.assignee_id,
        "assignee_username": case.assignee_username,
        "incident_ids": case.incident_ids,
        "tags": case.tags,
        "resolution": case.resolution,
        "sla_breached": case.sla_breached,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "updated_at": case.updated_at.isoformat() if case.updated_at else None,
        "closed_at": case.closed_at.isoformat() if case.closed_at else None,
    }
    if include_sla:
        out["sla"] = compute_sla_status(case)
    return out
