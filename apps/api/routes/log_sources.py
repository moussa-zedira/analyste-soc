"""API Log Sources — statut des sources de collecte."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.event import Event
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


class LogSourceStatus(BaseModel):
    """Statut d'une source de logs."""

    source: str
    event_count: int
    last_seen: str | None
    events_per_minute: float


@router.get("", response_model=list[LogSourceStatus])
def list_log_sources(
    db: Session = Depends(get_db),
) -> list[dict]:
    """Liste les sources de logs actives avec leurs statistiques."""
    cutoff_1h = datetime.now(UTC) - timedelta(hours=1)

    rows = (
        db.query(
            Event.source,
            func.count(Event.id).label("event_count"),
            func.max(Event.ts).label("last_seen"),
        )
        .group_by(Event.source)
        .order_by(func.count(Event.id).desc())
        .all()
    )

    # Count events in last hour per source for rate
    rate_rows = (
        db.query(Event.source, func.count(Event.id).label("recent_count"))
        .filter(Event.ts >= cutoff_1h)
        .group_by(Event.source)
        .all()
    )
    rate_map = {r.source: r.recent_count for r in rate_rows}

    results = []
    for row in rows:
        recent = rate_map.get(row.source, 0)
        epm = round(recent / 60, 2)

        results.append({
            "source": row.source,
            "event_count": row.event_count,
            "last_seen": row.last_seen.isoformat() if row.last_seen else None,
            "events_per_minute": epm,
        })

    return results
