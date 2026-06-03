"""Moteur de score de menace — calcule un score de risque 0-100 par IP source."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.models.event import Event
from apps.api.models.incident_event import IncidentEvent
from apps.api.models.threat_score import ThreatScore

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {"low": 1, "medium": 2, "high": 4, "critical": 8}

# Factor weights (must sum to 1.0)
W_EVENTS = 0.15
W_INCIDENTS = 0.25
W_SEVERITY = 0.20
W_ATTACK_TYPES = 0.10
W_RECENCY = 0.15
W_TI = 0.15


def _severity_score(severity: str) -> int:
    """Retourne le poids numerique associe a un niveau de severite."""
    return SEVERITY_WEIGHTS.get(severity, 1)


def compute_threat_scores(db: Session, lookback_hours: int = 24) -> int:
    """Calcule les scores de menace pour toutes les IP sources actives.

    Retourne le nombre d'IP evaluees.
    """
    now = datetime.now(UTC)
    cutoff = now - timedelta(hours=lookback_hours)

    # --- Gather per-IP stats from events ---
    ip_rows = (
        db.query(
            Event.src_ip,
            func.count(Event.id).label("event_count"),
            func.count(func.distinct(Event.event_type)).label("distinct_types"),
            func.max(Event.ts).label("last_seen"),
        )
        .filter(Event.ts >= cutoff, Event.src_ip.isnot(None))
        .group_by(Event.src_ip)
        .all()
    )

    if not ip_rows:
        return 0

    # --- Gather per-IP TI scores ---
    ti_by_ip: dict[str, int] = {}
    try:
        ti_rows = (
            db.query(Event.src_ip, func.max(Event.ti_score))
            .filter(Event.ts >= cutoff, Event.src_ip.isnot(None), Event.ti_score.isnot(None))
            .group_by(Event.src_ip)
            .all()
        )
        ti_by_ip = {ip: score for ip, score in ti_rows if score}
    except Exception:
        logger.debug("threat_score: ignored exception", exc_info=True)

    # --- Gather per-IP severity sums ---
    severity_rows = (
        db.query(Event.src_ip, Event.severity, func.count(Event.id))
        .filter(Event.ts >= cutoff, Event.src_ip.isnot(None))
        .group_by(Event.src_ip, Event.severity)
        .all()
    )
    severity_by_ip: dict[str, float] = {}
    for src_ip, sev, cnt in severity_rows:
        severity_by_ip[src_ip] = severity_by_ip.get(src_ip, 0) + _severity_score(sev) * cnt

    # --- Gather per-IP incident counts ---
    incident_rows = (
        db.query(Event.src_ip, func.count(func.distinct(IncidentEvent.incident_id)))
        .join(IncidentEvent, IncidentEvent.event_id == Event.id)
        .filter(Event.ts >= cutoff, Event.src_ip.isnot(None))
        .group_by(Event.src_ip)
        .all()
    )
    incidents_by_ip: dict[str, int] = dict(incident_rows)

    # --- Normalization bounds ---
    max_events = max(r.event_count for r in ip_rows)
    max_incidents = max(incidents_by_ip.values()) if incidents_by_ip else 1
    max_severity = max(severity_by_ip.values()) if severity_by_ip else 1
    max_types = max(r.distinct_types for r in ip_rows)

    # Avoid division by zero
    max_events = max(max_events, 1)
    max_incidents = max(max_incidents, 1)
    max_severity = max(max_severity, 1)
    max_types = max(max_types, 1)

    scored = 0
    for row in ip_rows:
        ip = row.src_ip
        event_count = row.event_count
        distinct_types = row.distinct_types
        last_seen: datetime = row.last_seen

        incident_count = incidents_by_ip.get(ip, 0)
        sev_total = severity_by_ip.get(ip, 0)

        # Recency: hours since last event, inverse (more recent = higher)
        hours_ago = max((now - last_seen).total_seconds() / 3600, 0.01)
        recency = max(1.0 - (hours_ago / lookback_hours), 0.0)

        # TI score (already 0-100, normalize to 0-1)
        ti_score_val = ti_by_ip.get(ip, 0)
        f_ti = ti_score_val / 100.0

        # Normalize each factor to 0-1
        f_events = event_count / max_events
        f_incidents = incident_count / max_incidents
        f_severity = sev_total / max_severity
        f_types = distinct_types / max_types
        f_recency = recency

        # Weighted sum → 0-100
        raw_score = (
            W_EVENTS * f_events
            + W_INCIDENTS * f_incidents
            + W_SEVERITY * f_severity
            + W_ATTACK_TYPES * f_types
            + W_RECENCY * f_recency
            + W_TI * f_ti
        )
        score = round(min(raw_score * 100, 100.0), 1)

        factors = {
            "event_count": event_count,
            "incident_count": incident_count,
            "severity_total": round(sev_total, 1),
            "distinct_attack_types": distinct_types,
            "recency": round(f_recency, 3),
            "ti_score": ti_score_val,
            "score_breakdown": {
                "events": round(f_events * W_EVENTS * 100, 1),
                "incidents": round(f_incidents * W_INCIDENTS * 100, 1),
                "severity": round(f_severity * W_SEVERITY * 100, 1),
                "attack_types": round(f_types * W_ATTACK_TYPES * 100, 1),
                "recency": round(f_recency * W_RECENCY * 100, 1),
                "threat_intel": round(f_ti * W_TI * 100, 1),
            },
        }

        existing = db.get(ThreatScore, ip)
        if existing:
            existing.score = score
            existing.factors_json = json.dumps(factors)
            existing.updated_at = now
        else:
            db.add(
                ThreatScore(
                    ip=ip,
                    score=score,
                    factors_json=json.dumps(factors),
                    updated_at=now,
                )
            )
        scored += 1

    db.commit()
    logger.info("Threat scores computed for %d IPs", scored)
    return scored
