"""Brute-force detection rule (bruteforce.v1).

Sliding-window algorithm:
- Considers events with event_type == "auth.fail" and a non-null src_ip.
- Groups by src_ip, sorts by ts ascending.
- Two-pointer sliding window of 2 minutes.
- When window contains >= THRESHOLD events, an incident is created.

Dedup strategy:
- dedup_hash = sha256(rule_id | entity_key | bucket)
- bucket = end_ts truncated to the minute (ISO-8601 minute string).
- If an incident with the same dedup_hash already exists, skip creation.

Checkpointing:
- Reads events from (last_ts - WINDOW) to allow overlap.
- Updates last_ts to the max processed ts.
- Dedup hash prevents duplicates caused by the overlap.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_
from sqlalchemy.orm import Session

from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.models.rule_checkpoint import RuleCheckpoint

logger = logging.getLogger(__name__)

RULE_ID = "bruteforce.v1"
WINDOW = timedelta(minutes=2)
THRESHOLD = 10


def _compute_dedup_hash(rule_id: str, entity_key: str, end_ts: datetime) -> str:
    """Deterministic dedup hash: bucket is end_ts truncated to the minute."""
    bucket = end_ts.strftime("%Y-%m-%dT%H:%M")
    raw = f"{rule_id}|{entity_key}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


def run(db: Session) -> dict:
    """Execute the bruteforce.v1 rule. Returns a summary dict."""

    now = datetime.now(timezone.utc)

    # ---- checkpoint ----
    checkpoint = db.get(RuleCheckpoint, RULE_ID)
    if checkpoint is not None:
        query_start = checkpoint.last_ts - WINDOW
    else:
        query_start = datetime(2000, 1, 1, tzinfo=timezone.utc)

    query_end = now

    # ---- fetch candidate events ----
    candidates = (
        db.query(Event)
        .filter(
            and_(
                Event.event_type == "auth.fail",
                Event.src_ip.is_not(None),
                Event.ts >= query_start,
                Event.ts <= query_end,
            )
        )
        .order_by(Event.ts.asc())
        .all()
    )

    processed_events = len(candidates)

    if not candidates:
        return {
            "processed_events": 0,
            "created_incidents": 0,
            "updated_checkpoints": [RULE_ID] if checkpoint else [],
        }

    # ---- group by src_ip ----
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in candidates:
        by_ip[ev.src_ip].append(ev)  # type: ignore[arg-type]

    created_incidents = 0
    max_ts = candidates[-1].ts

    for ip, events_for_ip in by_ip.items():
        created_incidents += _detect_for_ip(db, ip, events_for_ip)

    # ---- update checkpoint ----
    if checkpoint is None:
        checkpoint = RuleCheckpoint(
            rule_id=RULE_ID, last_ts=max_ts, updated_at=now
        )
        db.add(checkpoint)
    else:
        checkpoint.last_ts = max_ts
        checkpoint.updated_at = now

    db.commit()

    return {
        "processed_events": processed_events,
        "created_incidents": created_incidents,
        "updated_checkpoints": [RULE_ID],
    }


def _detect_for_ip(db: Session, ip: str, events: list[Event]) -> int:
    """Sliding-window detection for a single src_ip. Returns incident count."""
    created = 0
    entity_key = f"ip:{ip}"
    left = 0

    for right in range(len(events)):
        # shrink window from the left while it exceeds 2 minutes
        while events[right].ts - events[left].ts > WINDOW:
            left += 1

        window_size = right - left + 1
        if window_size < THRESHOLD:
            continue

        # We have a triggering window [left..right]
        window_events = events[left : right + 1]
        start_ts = window_events[0].ts
        end_ts = window_events[-1].ts

        dedup_hash = _compute_dedup_hash(RULE_ID, entity_key, end_ts)

        # Check dedup
        existing = (
            db.query(Incident.id)
            .filter(Incident.dedup_hash == dedup_hash)
            .first()
        )
        if existing is not None:
            continue

        # Distinct usernames
        usernames = sorted(
            {e.username for e in window_events if e.username}
        )
        username_info = (
            f"Usernames targeted: {', '.join(usernames)}"
            if usernames
            else "No username information available"
        )

        incident_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)

        incident = Incident(
            id=incident_id,
            created_at=now,
            updated_at=now,
            status="open",
            severity="high",
            title=f"Brute force suspected from {ip}",
            description=(
                f"{window_size} failed authentication attempts detected "
                f"within a 2-minute window. {username_info}"
            ),
            rule_id=RULE_ID,
            entity_key=entity_key,
            start_ts=start_ts,
            end_ts=end_ts,
            dedup_hash=dedup_hash,
        )
        db.add(incident)
        db.flush()

        # Link events to incident
        for ev in window_events:
            db.add(IncidentEvent(incident_id=incident_id, event_id=ev.id))

        created += 1

        # Advance left pointer past this window to avoid overlapping triggers
        # for the same IP in the same minute bucket.
        left = right + 1

    return created
