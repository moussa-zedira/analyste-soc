"""Detection d'anomalies statistiques par z-scores avec l'algorithme en ligne de Welford."""

from __future__ import annotations

import hashlib
import logging
import math
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.broadcast import broadcaster
from apps.api.config import get_settings
from apps.api.detection.triage import _load_whitelist
from apps.api.models.anomaly_baseline import AnomalyBaseline
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.notifications.webhook import notify_incident_created

logger = logging.getLogger(__name__)

Z_SCORE_THRESHOLD = 3.0
MIN_SAMPLES = 5
LOOKBACK_MINUTES = 5


def _welford_update(
    count: int,
    mean: float,
    variance: float,
    new_value: float,
) -> tuple[int, float, float]:
    """Met a jour les statistiques en ligne avec l'algorithme de Welford."""
    count += 1
    delta = new_value - mean
    mean += delta / count
    delta2 = new_value - mean
    variance += delta * delta2
    return count, mean, variance


def _stddev(variance: float, count: int) -> float:
    """Calcule l'ecart-type a partir de la variance et du nombre d'echantillons."""
    if count < 2:
        return 0.0
    return math.sqrt(variance / (count - 1))


def _z_score(value: float, mean: float, stddev: float) -> float:
    """Calcule le z-score d'une valeur par rapport a la moyenne et l'ecart-type."""
    if stddev == 0:
        return 0.0
    return (value - mean) / stddev


def _create_anomaly_incident(
    db: Session,
    rule_id: str,
    title: str,
    description: str,
    severity: str,
    entity_key: str,
    event_ids: list[str],
    start_ts: datetime,
    end_ts: datetime,
) -> bool:
    """Cree un incident d'anomalie avec deduplication. Retourne True si cree."""
    bucket = end_ts.strftime("%Y-%m-%dT%H:%M")
    dedup_hash = hashlib.sha256(f"{rule_id}|{entity_key}|{bucket}".encode()).hexdigest()

    if db.query(Incident.id).filter(Incident.dedup_hash == dedup_hash).first():
        return False

    now = datetime.now(UTC)
    incident_id = str(uuid.uuid4())

    incident = Incident(
        id=incident_id,
        created_at=now,
        updated_at=now,
        status="open",
        severity=severity,
        title=title,
        description=description,
        rule_id=rule_id,
        entity_key=entity_key,
        start_ts=start_ts,
        end_ts=end_ts,
        dedup_hash=dedup_hash,
    )
    db.add(incident)
    db.flush()

    for eid in event_ids[:100]:
        db.add(IncidentEvent(incident_id=incident_id, event_id=eid))
    db.flush()

    notify_incident_created(
        incident_id=incident_id,
        title=title,
        severity=severity,
        description=description,
        rule_id=rule_id,
        entity_key=entity_key,
        status="open",
        created_at=now.isoformat(),
    )

    broadcaster.publish(
        {
            "type": "new_incident",
            "payload": {
                "id": incident_id,
                "title": title,
                "severity": severity,
                "rule_id": rule_id,
                "entity_key": entity_key,
                "status": "open",
                "created_at": now.isoformat(),
            },
        }
    )

    logger.info("Created anomaly incident %s: %s", incident_id, rule_id)
    return True


def _get_or_create_baseline(
    db: Session,
    metric_key: str,
    metric_type: str,
    now: datetime,
) -> AnomalyBaseline:
    """Recupere ou cree une ligne de base d'anomalie pour la metrique donnee."""
    baseline = db.get(AnomalyBaseline, metric_key)
    if baseline is None:
        baseline = AnomalyBaseline(
            id=metric_key,
            metric_type=metric_type,
            metric_key=metric_key.split(":", 1)[1],
            count=0,
            mean=0.0,
            variance=0.0,
            last_value=0.0,
            updated_at=now,
        )
        db.add(baseline)
    return baseline


def run_anomaly_detection(db: Session) -> dict:
    """Execute la detection d'anomalies statistiques. Retourne un resume."""
    now = datetime.now(UTC)
    window_start = now - timedelta(minutes=LOOKBACK_MINUTES)
    incidents_created = 0

    # Triage: filter out benign and whitelisted events from anomaly detection
    settings = get_settings()
    benign_types: set[str] = set()
    if settings.TRIAGE_ENABLED:
        from apps.api.detection.triage import EVENT_CLASSIFICATION

        benign_types = {k for k, v in EVENT_CLASSIFICATION.items() if v == "benign"}
        _load_whitelist(db)
    else:
        pass

    # --- Volume anomaly: events per event_type ---
    volume_rows = (
        db.query(Event.event_type, func.count(Event.id))
        .filter(Event.ts >= window_start)
        .group_by(Event.event_type)
        .all()
    )

    for event_type, count in volume_rows:
        # Skip benign event types in anomaly detection
        if event_type in benign_types:
            continue

        key = f"volume:{event_type}"
        baseline = _get_or_create_baseline(db, key, "volume", now)

        sd = _stddev(baseline.variance, baseline.count)
        z = _z_score(float(count), baseline.mean, sd)

        if baseline.count >= MIN_SAMPLES and abs(z) > Z_SCORE_THRESHOLD:
            event_ids = [
                eid
                for (eid,) in db.query(Event.id)
                .filter(Event.event_type == event_type, Event.ts >= window_start)
                .limit(100)
                .all()
            ]
            if _create_anomaly_incident(
                db,
                rule_id="anomaly.volume.v1",
                title=f"Volume anomaly: {event_type} ({count} events in {LOOKBACK_MINUTES}min)",
                description=f"Detected {count} '{event_type}' events in {LOOKBACK_MINUTES} min. "
                f"Baseline mean: {baseline.mean:.1f}, z-score: {z:.2f}.",
                severity="high",
                entity_key=f"event_type:{event_type}",
                event_ids=event_ids,
                start_ts=window_start,
                end_ts=now,
            ):
                incidents_created += 1

        new_count, new_mean, new_var = _welford_update(
            baseline.count,
            baseline.mean,
            baseline.variance,
            float(count),
        )
        baseline.count = new_count
        baseline.mean = new_mean
        baseline.variance = new_var
        baseline.last_value = float(count)
        baseline.updated_at = now

    # --- IP behavior anomaly: events per src_ip ---
    ip_rows = (
        db.query(Event.src_ip, func.count(Event.id))
        .filter(Event.ts >= window_start, Event.src_ip.isnot(None))
        .group_by(Event.src_ip)
        .all()
    )

    for src_ip, count in ip_rows:
        key = f"ip:{src_ip}"
        baseline = _get_or_create_baseline(db, key, "ip", now)

        sd = _stddev(baseline.variance, baseline.count)
        z = _z_score(float(count), baseline.mean, sd)

        if baseline.count >= MIN_SAMPLES and abs(z) > Z_SCORE_THRESHOLD:
            event_ids = [
                eid
                for (eid,) in db.query(Event.id)
                .filter(Event.src_ip == src_ip, Event.ts >= window_start)
                .limit(100)
                .all()
            ]
            if _create_anomaly_incident(
                db,
                rule_id="anomaly.ip.v1",
                title=f"IP behavior anomaly: {src_ip} ({count} events in {LOOKBACK_MINUTES}min)",
                description=f"Detected {count} events from {src_ip} in {LOOKBACK_MINUTES} min. "
                f"Baseline mean: {baseline.mean:.1f}, z-score: {z:.2f}.",
                severity="medium",
                entity_key=f"src_ip:{src_ip}",
                event_ids=event_ids,
                start_ts=window_start,
                end_ts=now,
            ):
                incidents_created += 1

        new_count, new_mean, new_var = _welford_update(
            baseline.count,
            baseline.mean,
            baseline.variance,
            float(count),
        )
        baseline.count = new_count
        baseline.mean = new_mean
        baseline.variance = new_var
        baseline.last_value = float(count)
        baseline.updated_at = now

    db.commit()

    summary = {
        "volume_metrics_evaluated": len(volume_rows),
        "ip_metrics_evaluated": len(ip_rows),
        "incidents_created": incidents_created,
    }
    logger.info("Anomaly detection finished: %s", summary)
    return summary
