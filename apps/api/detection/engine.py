"""Moteur de detection — orchestre l'evaluation des regles et la creation d'incidents."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from apps.api.detection.evaluator import evaluate_rule
from apps.api.detection.impossible_travel import run_impossible_travel
from apps.api.detection.incident_creator import create_incident
from apps.api.detection.rules import Rule, get_rules
from apps.api.detection.triage import filter_events
from apps.api.models.event import Event

logger = logging.getLogger(__name__)

LOOKBACK = timedelta(hours=1)


def _fetch_recent_events(db: Session, since: datetime) -> list[Event]:
    """Recupere les evenements de la derniere heure, tries par horodatage croissant."""
    return (
        db.query(Event)
        .filter(Event.ts >= since)
        .order_by(Event.ts.asc())
        .all()
    )


def run_detection(db: Session) -> dict:
    """Execute toutes les regles de detection actives sur les evenements recents.

    Retourne un dictionnaire avec rules_evaluated et incidents_created.
    """
    now = datetime.now(timezone.utc)
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
            logger.info(
                "Rule %s produced %d matches", rule.id, len(matches)
            )

            for match in matches:
                created = create_incident(db, rule, match)
                if created:
                    total_incidents += 1
        except Exception:
            logger.exception("Rule %s failed", rule.id)

    # Custom rules that need special logic beyond the declarative framework
    try:
        total_incidents += run_impossible_travel(db, events)
    except Exception:
        logger.exception("Impossible-travel rule failed")

    db.commit()

    summary = {
        "rules_evaluated": len(rules) + 1,  # +1 for impossible-travel
        "incidents_created": total_incidents,
    }
    logger.info("Detection engine finished: %s", summary)
    return summary
