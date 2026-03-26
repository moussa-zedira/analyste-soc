"""Events API — CRUD endpoints for security events."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from apps.api.broadcast import broadcaster
from apps.api.cache import invalidate
from apps.api.db.session import get_db
from apps.api.models.event import Event
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])

# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class EventCreate(BaseModel):
    """Payload accepted by POST /events."""

    source: str
    event_type: str
    severity: Literal["low", "medium", "high"]
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    message: str | None = None
    raw: dict | list | str | None = None


class EventRead(BaseModel):
    """Response schema returned for every event."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    ts: datetime
    source: str
    event_type: str
    severity: str
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    message: str | None = None
    raw: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=EventRead,
    status_code=status.HTTP_201_CREATED,
)
def create_event(payload: EventCreate, db: Session = Depends(get_db)) -> Event:
    """Ingest a single security event."""
    raw_value: str | None = None
    if payload.raw is not None:
        raw_value = (
            payload.raw
            if isinstance(payload.raw, str)
            else json.dumps(payload.raw)
        )

    event = Event(
        id=str(uuid.uuid4()),
        ts=datetime.now(timezone.utc),
        source=payload.source,
        event_type=payload.event_type,
        severity=payload.severity,
        src_ip=payload.src_ip,
        dst_ip=payload.dst_ip,
        username=payload.username,
        message=payload.message,
        raw=raw_value,
    )
    db.add(event)
    db.commit()
    db.refresh(event)

    invalidate("stats:*")

    broadcaster.publish({
        "type": "new_event",
        "payload": {
            "id": event.id,
            "ts": event.ts.isoformat(),
            "source": event.source,
            "event_type": event.event_type,
            "severity": event.severity,
            "src_ip": event.src_ip,
            "dst_ip": event.dst_ip,
            "username": event.username,
            "message": event.message,
        },
    })

    return event


@router.get("", response_model=list[EventRead])
def list_events(
    limit: int = 50,
    offset: int = 0,
    severity: str | None = None,
    event_type: str | None = None,
    src_ip: str | None = None,
    db: Session = Depends(get_db),
) -> list[Event]:
    """Return a paginated, filterable list of events, newest first."""
    query = db.query(Event)

    if severity is not None:
        query = query.filter(Event.severity == severity)
    if event_type is not None:
        query = query.filter(Event.event_type == event_type)
    if src_ip is not None:
        query = query.filter(Event.src_ip == src_ip)

    return (
        query
        .order_by(Event.ts.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/{event_id}", response_model=EventRead)
def get_event(event_id: str, db: Session = Depends(get_db)) -> Event:
    """Return a single event by ID."""
    event = db.get(Event, event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Event not found",
        )
    return event
