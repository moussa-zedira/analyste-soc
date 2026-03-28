"""Moteur SIGMA — parse, compile et evalue les regles SIGMA."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import yaml
from sqlalchemy.orm import Session

from apps.api.models.event import Event
from apps.api.models.sigma_rule import SigmaRule

logger = logging.getLogger(__name__)

# Mapping logsource SIGMA → event_types SIEM
LOGSOURCE_MAP: dict[str, list[str]] = {
    "authentication": ["auth.fail", "auth.success", "auth.explicit"],
    "windows": [
        "winlog", "auth.fail", "auth.success", "priv.escalation",
        "account.created", "account.deleted", "service.installed",
    ],
    "linux": ["auth.fail", "auth.success", "priv.escalation", "priv.sudo"],
    "firewall": ["network.blocked", "network.allowed"],
    "webserver": ["web.access", "web.forbidden", "web.server_error"],
    "ids": ["ids.alert"],
    "process_creation": ["process.created"],
}


def compile_sigma(yaml_content: str) -> dict:
    """Parse et compile une regle SIGMA YAML en format interne."""
    try:
        rule = yaml.safe_load(yaml_content)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {e}") from e

    if not isinstance(rule, dict):
        raise ValueError("SIGMA rule must be a YAML mapping")

    title = rule.get("title", "Unnamed Rule")
    description = rule.get("description", "")
    level = rule.get("level", "medium")
    author = rule.get("author", "")

    # Extract logsource
    logsource = rule.get("logsource", {})
    category = logsource.get("category", "")
    product = logsource.get("product", "")

    # Map to event types
    matched_types: list[str] = []
    for key in [category, product]:
        if key in LOGSOURCE_MAP:
            matched_types.extend(LOGSOURCE_MAP[key])

    # Extract detection
    detection = rule.get("detection", {})
    compiled = {
        "title": title,
        "description": description,
        "level": _normalize_level(level),
        "author": author,
        "event_types": list(set(matched_types)),
        "conditions": _compile_detection(detection),
    }

    return compiled


def _normalize_level(level: str) -> str:
    level = level.lower()
    if level in ("critical", "high"):
        return "high"
    if level in ("medium", "moderate"):
        return "medium"
    return "low"


def _compile_detection(detection: dict) -> list[dict]:
    """Compile les conditions de detection SIGMA en filtres internes."""
    conditions = []

    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict):
            conditions.append({"type": "match", "name": key, "fields": value})
        elif isinstance(value, list):
            conditions.append({"type": "any_of", "name": key, "values": value})

    return conditions


def _match_field(event_value: str | None, pattern: Any) -> bool:
    """Verifie si une valeur d'event correspond a un pattern SIGMA."""
    if event_value is None:
        return False

    if isinstance(pattern, str):
        # Wildcards
        if "*" in pattern or "?" in pattern:
            regex = pattern.replace(".", r"\.").replace("*", ".*").replace("?", ".")
            return bool(re.search(regex, event_value, re.IGNORECASE))
        return pattern.lower() in event_value.lower()
    elif isinstance(pattern, list):
        return any(_match_field(event_value, p) for p in pattern)
    elif isinstance(pattern, (int, float)):
        return str(pattern) in event_value

    return False


def evaluate_sigma_rule(compiled: dict, event: Event) -> bool:
    """Evalue une regle SIGMA compilee contre un event."""
    # Check event type filter
    allowed_types = compiled.get("event_types", [])
    if allowed_types and not any(
        event.event_type.startswith(t) or t.startswith(event.event_type)
        for t in allowed_types
    ):
        return False

    conditions = compiled.get("conditions", [])
    if not conditions:
        return False

    # All conditions must match (AND logic by default)
    for cond in conditions:
        if cond["type"] == "match":
            fields = cond["fields"]
            matched = True
            for field_name, pattern in fields.items():
                event_value = _get_event_field(event, field_name)
                if not _match_field(event_value, pattern):
                    matched = False
                    break
            if not matched:
                return False
        elif cond["type"] == "any_of":
            values = cond["values"]
            event_raw = event.raw or ""
            event_msg = event.message or ""
            combined = f"{event_raw} {event_msg}".lower()
            if not any(str(v).lower() in combined for v in values):
                return False

    return True


def _get_event_field(event: Event, field_name: str) -> str | None:
    """Mappe un nom de champ SIGMA vers un champ de l'event."""
    field_map = {
        "SourceIp": event.src_ip,
        "IpAddress": event.src_ip,
        "src_ip": event.src_ip,
        "DestinationIp": event.dst_ip,
        "dst_ip": event.dst_ip,
        "TargetUserName": event.username,
        "User": event.username,
        "username": event.username,
        "EventType": event.event_type,
        "event_type": event.event_type,
        "Message": event.message,
        "message": event.message,
        "Source": event.source,
        "source": event.source,
    }
    return field_map.get(field_name) or getattr(event, field_name, None)


def import_sigma_rule(yaml_content: str, db: Session) -> SigmaRule:
    """Importe une regle SIGMA dans la base de donnees."""
    compiled = compile_sigma(yaml_content)

    rule = SigmaRule(
        name=compiled["title"],
        description=compiled.get("description", ""),
        level=compiled["level"],
        yaml_content=yaml_content,
        compiled_json=json.dumps(compiled),
        enabled=True,
        author=compiled.get("author", ""),
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def get_enabled_sigma_rules(db: Session) -> list[tuple[SigmaRule, dict]]:
    """Retourne les regles SIGMA actives avec leur version compilee."""
    rules = db.query(SigmaRule).filter(SigmaRule.enabled.is_(True)).all()
    result = []
    for rule in rules:
        if rule.compiled_json:
            try:
                compiled = json.loads(rule.compiled_json)
                result.append((rule, compiled))
            except json.JSONDecodeError:
                logger.warning("Invalid compiled JSON for SIGMA rule %d", rule.id)
    return result
