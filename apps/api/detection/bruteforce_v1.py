"""Regle de detection de force brute (bruteforce.v1).

Algorithme a fenetre glissante :
- Considere les evenements event_type == "auth.fail" avec src_ip non nul.
- Regroupe par src_ip, trie par ts croissant.
- Fenetre glissante a deux pointeurs de 2 minutes.
- Un incident est cree lorsque la fenetre contient >= THRESHOLD evenements.

Strategie de deduplication :
- dedup_hash = sha256(rule_id | entity_key | bucket)
- bucket = end_ts tronque a la minute (chaine ISO-8601).
- Si un incident avec le meme dedup_hash existe deja, la creation est ignoree.

Point de reprise :
- Lit les evenements depuis (last_ts - WINDOW) pour permettre le chevauchement.
- Met a jour last_ts au ts maximum traite.
- Le hash de deduplication empeche les doublons dus au chevauchement.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

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
    """Hash de deduplication deterministe : bucket = end_ts tronque a la minute."""
    bucket = end_ts.strftime("%Y-%m-%dT%H:%M")
    raw = f"{rule_id}|{entity_key}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


def run(db: Session) -> dict:
    """Execute la regle bruteforce.v1. Retourne un dictionnaire de resume."""

    now = datetime.now(UTC)

    # ---- checkpoint ----
    checkpoint = db.get(RuleCheckpoint, RULE_ID)
    if checkpoint is not None:
        query_start = checkpoint.last_ts - WINDOW
    else:
        query_start = datetime(2000, 1, 1, tzinfo=UTC)

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
    """Detection par fenetre glissante pour une seule src_ip. Retourne le nombre d'incidents."""
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
        now = datetime.now(UTC)

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
