"""Impossible-travel detection rule (impossible-travel.v1).

Detects a single username authenticating successfully from multiple distinct
source IPs within a short time window, which may indicate credential compromise.

Algorithm:
- Considers events with event_type == "auth.success", non-null src_ip and username.
- Groups by username, sorts by ts ascending.
- Sliding window of 10 minutes.
- When the window contains >= MIN_DISTINCT_IPS distinct src_ip values, an
  incident is created.

Dedup strategy:
- dedup_hash = sha256(rule_id | entity_key | bucket)
- bucket = end_ts truncated to the minute.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from apps.api.broadcast import broadcaster
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.notifications.webhook import notify_incident_created

logger = logging.getLogger(__name__)

RULE_ID = "impossible-travel.v1"
WINDOW = timedelta(minutes=10)
MIN_DISTINCT_IPS = 2
SEVERITY = "critical"


def _compute_dedup_hash(entity_key: str, end_ts: datetime) -> str:
    bucket = end_ts.strftime("%Y-%m-%dT%H:%M")
    raw = f"{RULE_ID}|{entity_key}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


def run_impossible_travel(db: Session, events: list[Event]) -> int:
    """Run impossible-travel detection against pre-fetched events.

    Returns the number of incidents created.
    """
    # Filter to successful auths with both username and src_ip
    candidates = [
        e
        for e in events
        if e.event_type == "auth.success" and e.username and e.src_ip
    ]
    if not candidates:
        return 0

    # Group by username
    by_user: dict[str, list[Event]] = defaultdict(list)
    for ev in candidates:
        by_user[ev.username].append(ev)  # type: ignore[arg-type]

    created = 0
    for username, user_events in by_user.items():
        user_events.sort(key=lambda e: e.ts)
        created += _detect_for_user(db, username, user_events)

    return created


def _detect_for_user(db: Session, username: str, events: list[Event]) -> int:
    """Sliding-window detection for a single username. Returns incident count."""
    created = 0
    entity_key = f"user:{username}"
    left = 0

    for right in range(len(events)):
        # Shrink window from the left
        while events[right].ts - events[left].ts > WINDOW:
            left += 1

        window_events = events[left : right + 1]
        distinct_ips = {e.src_ip for e in window_events}

        if len(distinct_ips) < MIN_DISTINCT_IPS:
            continue

        start_ts = window_events[0].ts
        end_ts = window_events[-1].ts
        dedup_hash = _compute_dedup_hash(entity_key, end_ts)

        existing = (
            db.query(Incident.id)
            .filter(Incident.dedup_hash == dedup_hash)
            .first()
        )
        if existing is not None:
            continue

        ip_list = ", ".join(sorted(distinct_ips))
        now = datetime.now(timezone.utc)
        incident_id = str(uuid.uuid4())

        incident = Incident(
            id=incident_id,
            created_at=now,
            updated_at=now,
            status="open",
            severity=SEVERITY,
            title=f"Impossible travel detected for {username}",
            description=(
                f"User '{username}' authenticated from {len(distinct_ips)} "
                f"distinct IPs ({ip_list}) within a 10-minute window."
            ),
            rule_id=RULE_ID,
            entity_key=entity_key,
            start_ts=start_ts,
            end_ts=end_ts,
            dedup_hash=dedup_hash,
        )
        db.add(incident)
        db.flush()

        for ev in window_events:
            db.add(IncidentEvent(incident_id=incident_id, event_id=ev.id))

        notify_incident_created(
            incident_id=incident_id,
            title=incident.title,
            severity=incident.severity,
            description=incident.description,
            rule_id=RULE_ID,
            entity_key=entity_key,
            status="open",
            created_at=now.isoformat(),
        )

        broadcaster.publish({
            "type": "new_incident",
            "payload": {
                "id": incident_id,
                "title": incident.title,
                "severity": incident.severity,
                "rule_id": RULE_ID,
                "entity_key": entity_key,
                "status": "open",
                "created_at": now.isoformat(),
            },
        })

        created += 1
        # Advance past this window
        left = right + 1

    return created
