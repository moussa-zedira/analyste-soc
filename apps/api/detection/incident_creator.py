"""Createur d'incidents — persiste les correspondances de regles en incidents avec deduplication."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from apps.api.detection.evaluator import RuleMatch
from apps.api.detection.rules import Rule
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.broadcast import broadcaster
from apps.api.middleware.metrics import incidents_created_total
from apps.api.notifications.webhook import notify_incident_created
from apps.api.observability import record_incident_created

try:
    from apps.api.detection.ml_classifier import predict_severity
except ImportError:
    predict_severity = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def _compute_dedup_hash(rule_id: str, entity_key: str, end_ts: datetime) -> str:
    """Hash de deduplication deterministe : bucket = end_ts tronque a la minute."""
    bucket = end_ts.strftime("%Y-%m-%dT%H:%M")
    raw = f"{rule_id}|{entity_key}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _format_title(rule: Rule, match: RuleMatch) -> str:
    """Genere le titre de la regle a partir du modele et des valeurs de correspondance."""
    template_vars: dict[str, str] = {**match.group_values}
    template_vars["count"] = str(match.count)
    try:
        return rule.title_template.format(**template_vars)
    except KeyError:
        return f"{rule.id} triggered on {match.group_key}"


def _format_description(rule: Rule, match: RuleMatch) -> str:
    """Genere la description de la regle a partir du modele et des valeurs de correspondance."""
    if not rule.description_template:
        return f"Rule {rule.id} matched {match.count} events."
    template_vars: dict[str, str] = {**match.group_values}
    template_vars["count"] = str(match.count)
    template_vars["window"] = str(int(rule.time_window.total_seconds()))
    template_vars["extra"] = ""
    try:
        return rule.description_template.format(**template_vars)
    except KeyError:
        return f"Rule {rule.id} matched {match.count} events."


def create_incident(db: Session, rule: Rule, match: RuleMatch) -> bool:
    """Cree un incident a partir d'une correspondance de regle si non duplique.

    Retourne True si un incident a ete cree, False si deduplique.
    """
    entity_key = match.group_key
    dedup_hash = _compute_dedup_hash(rule.id, entity_key, match.end_ts)

    existing = (
        db.query(Incident.id)
        .filter(Incident.dedup_hash == dedup_hash)
        .first()
    )
    if existing is not None:
        logger.debug(
            "Skipped duplicate incident: rule=%s key=%s hash=%s",
            rule.id,
            entity_key,
            dedup_hash[:12],
        )
        return False

    now = datetime.now(timezone.utc)
    incident_id = str(uuid.uuid4())

    incident = Incident(
        id=incident_id,
        created_at=now,
        updated_at=now,
        status="open",
        severity=rule.severity.value,
        title=_format_title(rule, match),
        description=_format_description(rule, match),
        rule_id=rule.id,
        entity_key=entity_key,
        start_ts=match.start_ts,
        end_ts=match.end_ts,
        dedup_hash=dedup_hash,
    )

    try:
        db.add(incident)
        db.flush()

        for event_id in match.event_ids:
            db.add(IncidentEvent(incident_id=incident_id, event_id=event_id))

        db.flush()

        # ML severity suggestion
        if predict_severity is not None:
            try:
                event_msgs = [
                    e.message for e in incident.events[:50] if e.message
                ]
                suggested = predict_severity(
                    incident.title, incident.description, event_msgs,
                )
                if suggested:
                    incident.suggested_severity = suggested
                    db.flush()
            except Exception:
                logger.debug("ML prediction skipped (model not trained)")

        notify_incident_created(
            incident_id=incident_id,
            title=incident.title,
            severity=incident.severity,
            description=incident.description,
            rule_id=rule.id,
            entity_key=entity_key,
            status="open",
            created_at=now.isoformat(),
        )

        incidents_created_total.labels(severity=incident.severity).inc()
        record_incident_created(incident.severity, rule.id)

        broadcaster.publish({
            "type": "new_incident",
            "payload": {
                "id": incident_id,
                "title": incident.title,
                "severity": incident.severity,
                "rule_id": rule.id,
                "entity_key": entity_key,
                "status": "open",
                "created_at": now.isoformat(),
            },
        })

        # Dispatch alerts via Celery (non-blocking)
        try:
            from apps.api.tasks import task_send_alert

            task_send_alert.delay({
                "id": incident_id,
                "title": incident.title,
                "severity": incident.severity,
                "description": incident.description,
                "rule_id": rule.id,
                "entity_key": entity_key,
                "status": "open",
                "created_at": now.isoformat(),
            })
        except Exception:
            logger.debug("Celery alert dispatch skipped (worker not available)")
    except Exception:
        logger.exception(
            "Failed to create incident: rule=%s key=%s",
            rule.id,
            entity_key,
        )
        db.rollback()
        return False

    logger.info(
        "Created incident %s: rule=%s key=%s events=%d",
        incident_id,
        rule.id,
        entity_key,
        len(match.event_ids),
    )
    return True
