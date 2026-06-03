"""PagerDuty Events API v2 — trigger, acknowledge, resolve incidents."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

EVENTS_API_URL = "https://events.pagerduty.com/v2/enqueue"

_SEVERITY_MAP = {
    "critical": "critical",
    "high": "error",
    "medium": "warning",
    "low": "info",
}

_PRIORITY_MAP = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
}


def _dedup_key(incident: dict[str, Any]) -> str:
    """Generate a stable deduplication key for an incident."""
    raw = f"{incident.get('rule_id', '')}-{incident.get('entity_key', '')}-{incident.get('id', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _build_payload(
    config: dict[str, Any],
    incident: dict[str, Any],
    action: str = "trigger",
) -> dict:
    """Build a PagerDuty Events API v2 payload."""
    routing_key = config.get("routing_key", "")
    severity = incident.get("severity", "medium")
    pd_severity = _SEVERITY_MAP.get(severity, "warning")
    dedup = incident.get("dedup_key") or _dedup_key(incident)

    payload: dict[str, Any] = {
        "routing_key": routing_key,
        "event_action": action,
        "dedup_key": dedup,
    }

    if action == "trigger":
        custom_details = {
            "incident_id": incident.get("id", "N/A"),
            "rule_id": incident.get("rule_id", "N/A"),
            "entity_key": incident.get("entity_key", "N/A"),
            "threat_score": incident.get("threat_score", "N/A"),
            "description": incident.get("description", ""),
            "priority": _PRIORITY_MAP.get(severity, "P3"),
        }
        actions_list = incident.get("recommended_actions", [])
        if actions_list:
            custom_details["recommended_actions"] = actions_list

        payload["payload"] = {
            "summary": f"[{severity.upper()}] {incident.get('title', 'Security Incident')}",
            "source": config.get("source", "cyberdef-siem"),
            "severity": pd_severity,
            "component": incident.get("rule_id", "detection-engine"),
            "group": config.get("service_group", "security"),
            "class": incident.get("alert_type", "incident"),
            "custom_details": custom_details,
            "timestamp": incident.get("timestamp"),
        }

    return payload


async def send_alert(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Send a PagerDuty event.

    Config keys:
        routing_key: str — PagerDuty integration routing key (required)
        source: str — source identifier (default: cyberdef-siem)
        service_group: str — PD service group (default: security)
        action: str — trigger|acknowledge|resolve (default: trigger)
    """
    routing_key = config.get("routing_key", "")
    if not routing_key:
        raise ValueError("No PagerDuty routing_key configured")

    action = config.get("action", "trigger")
    payload = _build_payload(config, incident, action)

    async with httpx.AsyncClient(timeout=15.0) as client:
        for attempt in range(3):
            try:
                resp = await client.post(EVENTS_API_URL, json=payload)
                if resp.status_code == 429:
                    import asyncio

                    await asyncio.sleep(2**attempt)
                    continue
                resp.raise_for_status()
                logger.info("PagerDuty event %s sent (dedup=%s)", action, payload.get("dedup_key"))
                return
            except httpx.TransportError:
                if attempt == 2:
                    raise


async def acknowledge(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Acknowledge an existing PagerDuty incident."""
    config = {**config, "action": "acknowledge"}
    await send_alert(config, incident)


async def resolve(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Resolve an existing PagerDuty incident."""
    config = {**config, "action": "resolve"}
    await send_alert(config, incident)
