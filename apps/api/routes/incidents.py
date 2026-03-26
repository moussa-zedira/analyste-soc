"""Incidents API — list and retrieve security incidents."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from apps.api.auth import RoleChecker
from apps.api.db.session import get_db
from apps.api.models.incident import Incident
from apps.api.routes.events import EventRead
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

MAX_LINKED_EVENTS = 50


VALID_TRANSITIONS: dict[str, set[str]] = {
    "open": {"ack", "closed"},
    "ack": {"closed", "open"},
    "closed": {"open"},
}


class IncidentStatusUpdate(BaseModel):
    """Payload for PATCH /incidents/{id}."""

    status: str


class IncidentRead(BaseModel):
    """List-view schema for incidents (no linked events)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    updated_at: datetime
    status: str
    severity: str
    title: str
    description: str
    rule_id: str
    entity_key: str
    start_ts: datetime
    end_ts: datetime
    dedup_hash: str
    suggested_severity: str | None = None


class IncidentDetail(IncidentRead):
    """Detail-view schema including linked events (up to 50)."""

    events: list[EventRead] = []


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=list[IncidentRead])
def list_incidents(
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    status_filter: str | None = None,
    rule_id: str | None = None,
    db: Session = Depends(get_db),
) -> list[Incident]:
    """Return a paginated, filterable list of incidents."""
    query = db.query(Incident)

    if severity is not None:
        query = query.filter(Incident.severity == severity)
    if status_filter is not None:
        query = query.filter(Incident.status == status_filter)
    if rule_id is not None:
        query = query.filter(Incident.rule_id == rule_id)

    return (
        query
        .order_by(Incident.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: str, db: Session = Depends(get_db)) -> dict:
    """Return a single incident with its linked events (up to 50)."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    # Eager-load the relationship; limit to MAX_LINKED_EVENTS.
    linked_events = incident.events[:MAX_LINKED_EVENTS]

    return {
        "id": incident.id,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "status": incident.status,
        "severity": incident.severity,
        "title": incident.title,
        "description": incident.description,
        "rule_id": incident.rule_id,
        "entity_key": incident.entity_key,
        "start_ts": incident.start_ts,
        "end_ts": incident.end_ts,
        "dedup_hash": incident.dedup_hash,
        "suggested_severity": incident.suggested_severity,
        "events": linked_events,
    }


@router.patch(
    "/{incident_id}",
    response_model=IncidentRead,
    dependencies=[Depends(RoleChecker("lead"))],
)
def update_incident_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
) -> Incident:
    """Update an incident's status with transition validation."""
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    new_status = payload.status.lower()
    allowed = VALID_TRANSITIONS.get(incident.status, set())
    if new_status not in allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Cannot transition from '{incident.status}' to '{new_status}'. "
                   f"Allowed: {sorted(allowed)}",
        )

    incident.status = new_status
    incident.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(incident)
    return incident
