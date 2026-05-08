"""Deduplication d'alertes par fingerprint avec TTL.

Empeche le re-envoi d'alertes identiques dans une fenetre de temps.
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from apps.api.models.alert_dedup import AlertFingerprint

logger = logging.getLogger(__name__)

DEFAULT_DEDUP_TTL_MINUTES = int(os.environ.get("ALERT_DEDUP_TTL_MIN", "30"))


def compute_fingerprint(incident: dict) -> str:
    """sha256(rule_id|entity_key|severity)."""
    raw = "|".join([
        str(incident.get("rule_id") or ""),
        str(incident.get("entity_key") or incident.get("user") or ""),
        str(incident.get("severity") or ""),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def check_and_record(
    db: Session,
    incident: dict,
    *,
    ttl_minutes: int | None = None,
) -> tuple[bool, AlertFingerprint]:
    """Verifie si l'incident doit etre supprime (deja vu recemment).

    Retourne (suppress, row). Si suppress=True, l'appelant n'envoie pas l'alerte.
    Met a jour count + last_seen + suppressed_until dans tous les cas.
    """
    ttl = ttl_minutes if ttl_minutes is not None else DEFAULT_DEDUP_TTL_MINUTES
    fp = compute_fingerprint(incident)
    now = datetime.now(UTC)

    row = db.query(AlertFingerprint).filter(AlertFingerprint.fingerprint == fp).first()
    suppress = False

    if row is None:
        row = AlertFingerprint(
            fingerprint=fp,
            rule_id=incident.get("rule_id"),
            entity_key=incident.get("entity_key") or incident.get("user"),
            severity=incident.get("severity"),
            first_seen=now,
            last_seen=now,
            count=1,
            suppressed_until=now + timedelta(minutes=ttl),
            last_incident_id=str(incident.get("id") or ""),
        )
        db.add(row)
    else:
        row.count = (row.count or 0) + 1
        row.last_seen = now
        row.last_incident_id = str(incident.get("id") or row.last_incident_id or "")
        if row.suppressed_until and row.suppressed_until > now:
            suppress = True
        else:
            row.suppressed_until = now + timedelta(minutes=ttl)

    db.commit()
    return suppress, row


def list_recent(db: Session, *, limit: int = 100) -> list[AlertFingerprint]:
    return (
        db.query(AlertFingerprint)
        .order_by(AlertFingerprint.last_seen.desc())
        .limit(limit)
        .all()
    )


def reset_fingerprint(db: Session, fingerprint: str) -> bool:
    row = db.query(AlertFingerprint).filter(AlertFingerprint.fingerprint == fingerprint).first()
    if not row:
        return False
    row.suppressed_until = None
    db.commit()
    return True
