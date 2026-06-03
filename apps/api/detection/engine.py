"""Moteur de detection — orchestre l'evaluation des regles et la creation d'incidents."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from apps.api.detection.evaluator import evaluate_rule
from apps.api.detection.impossible_travel import run_impossible_travel
from apps.api.detection.incident_creator import create_incident
from apps.api.detection.rules import Rule, get_rules
from apps.api.detection.triage import filter_events
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.observability import record_rule_match

logger = logging.getLogger(__name__)

LOOKBACK = timedelta(hours=1)

_SIGMA_SEVERITY_MAP = {"high": "high", "medium": "medium", "low": "low"}


def _create_sigma_incident(
    db: Session,
    sigma_rule: object,
    compiled: dict,
    event: Event,
    now: datetime,
) -> bool:
    """Cree un incident pour une correspondance SIGMA avec deduplication."""
    rule_id = f"sigma:{sigma_rule.id}"  # type: ignore[attr-defined]
    entity_key = event.src_ip or event.username or event.id
    bucket = now.strftime("%Y-%m-%dT%H:%M")
    dedup = hashlib.sha256(f"{rule_id}|{entity_key}|{bucket}".encode()).hexdigest()

    existing = db.query(Incident).filter(Incident.dedup_hash == dedup).first()
    if existing:
        return False

    severity = _SIGMA_SEVERITY_MAP.get(compiled.get("level", "medium"), "medium")
    title = f"[SIGMA] {sigma_rule.name}: {entity_key}"  # type: ignore[attr-defined]

    incident = Incident(
        id=str(uuid.uuid4()),
        title=title,
        description=compiled.get("description", ""),
        severity=severity,
        status="open",
        rule_id=rule_id,
        entity_key=entity_key,
        start_ts=event.ts,
        end_ts=event.ts,
        dedup_hash=dedup,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.add(IncidentEvent(incident_id=incident.id, event_id=event.id))
    logger.info("SIGMA incident created: %s", title)
    return True


def _fetch_recent_events(db: Session, since: datetime) -> list[Event]:
    """Recupere les evenements de la derniere heure, tries par horodatage croissant."""
    return db.query(Event).filter(Event.ts >= since).order_by(Event.ts.asc()).all()


def run_detection(db: Session) -> dict:
    """Execute toutes les regles de detection actives sur les evenements recents.

    Retourne un dictionnaire avec rules_evaluated et incidents_created.
    """
    now = datetime.now(UTC)
    since = now - LOOKBACK

    rules: list[Rule] = get_rules(enabled_only=True)
    logger.info("Detection engine started: %d rules loaded", len(rules))

    events = _fetch_recent_events(db, since)
    logger.info("Fetched %d events since %s", len(events), since.isoformat())

    events = filter_events(events, db)
    logger.info("After triage: %d events remain", len(events))

    total_incidents = 0

    for rule in rules:
        try:
            matches = evaluate_rule(rule, events)
            logger.info("Rule %s produced %d matches", rule.id, len(matches))

            for match in matches:
                created = create_incident(db, rule, match)
                if created:
                    total_incidents += 1
                    record_rule_match("builtin", rule.id, rule.severity)
        except Exception:
            logger.exception("Rule %s failed", rule.id)

    # Custom rules that need special logic beyond the declarative framework
    try:
        total_incidents += run_impossible_travel(db, events)
    except Exception:
        logger.exception("Impossible-travel rule failed")

    # SIGMA rules evaluation
    sigma_evaluated = 0
    try:
        from apps.api.detection.sigma_engine import (
            evaluate_sigma_rule,
            get_enabled_sigma_rules,
        )

        sigma_rules = get_enabled_sigma_rules(db)
        for sigma_rule, compiled in sigma_rules:
            sigma_evaluated += 1
            for event in events:
                if evaluate_sigma_rule(compiled, event):
                    created = _create_sigma_incident(
                        db,
                        sigma_rule,
                        compiled,
                        event,
                        now,
                    )
                    if created:
                        total_incidents += 1
                        record_rule_match(
                            "sigma",
                            f"sigma:{sigma_rule.id}",  # type: ignore[attr-defined]
                            _SIGMA_SEVERITY_MAP.get(compiled.get("level", "medium"), "medium"),
                        )
    except Exception:
        logger.exception("SIGMA rules evaluation failed")

    # Multi-event correlation engine
    correlation_incidents = 0
    correlation_rules_count = 0
    try:
        from apps.api.detection.correlation import (
            get_correlation_engine,
            run_correlation,
        )

        corr_engine = get_correlation_engine()
        correlation_rules_count = len(corr_engine.get_rules(enabled_only=True))
        correlation_incidents = run_correlation(db, events)
        total_incidents += correlation_incidents
    except Exception:
        logger.exception("Correlation engine evaluation failed")

    # State machine engine — process events for stateful detection
    fsm_completions = 0
    try:
        from apps.api.detection.state_machine import get_state_machine_engine

        sm_engine = get_state_machine_engine()
        completions = sm_engine.process_events(events)
        fsm_completions = len(completions)

        # Create incidents from completed state machines
        for completion in completions:
            try:
                entity_key = completion["group_key"]
                bucket = now.strftime("%Y-%m-%dT%H:%M")
                dedup = hashlib.sha256(
                    f"fsm:{completion['machine_id']}|{entity_key}|{bucket}".encode()
                ).hexdigest()

                existing = db.query(Incident).filter(Incident.dedup_hash == dedup).first()
                if existing:
                    continue

                incident = Incident(
                    id=str(uuid.uuid4()),
                    title=f"[FSM] {completion['machine_name']}: {entity_key}",
                    description=(
                        f"State machine '{completion['machine_name']}' completed "
                        f"full attack chain for {entity_key}. "
                        f"MITRE: {', '.join(completion.get('mitre_tactics', []))}"
                    ),
                    severity=completion.get("severity", "critical"),
                    status="open",
                    rule_id=f"fsm:{completion['machine_id']}",
                    entity_key=entity_key,
                    start_ts=now - LOOKBACK,
                    end_ts=now,
                    dedup_hash=dedup,
                    created_at=now,
                    updated_at=now,
                )
                db.add(incident)
                total_incidents += 1
            except Exception:
                logger.exception(
                    "FSM incident creation failed for %s", completion.get("machine_id")
                )

        # Cleanup expired states periodically
        sm_engine.cleanup()
    except Exception:
        logger.exception("State machine engine evaluation failed")

    db.commit()

    summary = {
        "rules_evaluated": len(rules) + 1 + sigma_evaluated + correlation_rules_count,
        "incidents_created": total_incidents,
        "correlation_rules": correlation_rules_count,
        "correlation_incidents": correlation_incidents,
        "fsm_completions": fsm_completions,
    }
    logger.info("Detection engine finished: %s", summary)
    return summary
