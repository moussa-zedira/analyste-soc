"""Discord webhook integration — embed messages with severity color coding."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_SEVERITY_INT_COLORS = {
    "critical": 0xEF4444,
    "high": 0xF97316,
    "medium": 0xEAB308,
    "low": 0x3B82F6,
}


def _build_embed(incident: dict[str, Any]) -> dict:
    """Build a Discord embed for an incident alert."""
    severity = incident.get("severity", "medium")
    color = _SEVERITY_INT_COLORS.get(severity, 0x808080)

    fields = [
        {"name": "Severity", "value": severity.upper(), "inline": True},
        {"name": "Threat Score", "value": str(incident.get("threat_score", "N/A")), "inline": True},
        {"name": "Rule", "value": incident.get("rule_id", "N/A"), "inline": True},
        {"name": "Entity", "value": incident.get("entity_key", "N/A"), "inline": True},
        {"name": "Incident ID", "value": f"`{incident.get('id', 'N/A')}`", "inline": True},
    ]

    description = incident.get("description", "No description")
    if len(description) > 2048:
        description = description[:2045] + "..."

    actions = incident.get("recommended_actions", [])
    if actions:
        actions_text = "\n".join(f"- {a}" for a in actions[:5])
        fields.append({"name": "Recommended Actions", "value": actions_text, "inline": False})

    return {
        "title": f"{'🔴' if severity == 'critical' else '🟡'} {incident.get('title', 'Security Alert')}",
        "description": description,
        "color": color,
        "fields": fields,
        "footer": {"text": "CyberDef SIEM"},
        "timestamp": incident.get("timestamp", ""),
    }


async def send_alert(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Send a Discord alert via webhook.

    Config keys:
        webhook_url: str — Discord webhook URL
        username: str — Bot display name (default: CyberDef SIEM)
        avatar_url: str — Bot avatar URL
    """
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        raise ValueError("No Discord webhook_url configured")

    embed = _build_embed(incident)
    payload: dict[str, Any] = {
        "username": config.get("username", "CyberDef SIEM"),
        "embeds": [embed],
    }
    avatar = config.get("avatar_url")
    if avatar:
        payload["avatar_url"] = avatar

    async with httpx.AsyncClient(timeout=15.0) as client:
        for attempt in range(3):
            try:
                resp = await client.post(webhook_url, json=payload)
                if resp.status_code == 429:
                    retry_after = resp.json().get("retry_after", 2)
                    import asyncio

                    await asyncio.sleep(float(retry_after))
                    continue
                resp.raise_for_status()
                logger.info("Discord alert sent for incident %s", incident.get("id"))
                return
            except httpx.TransportError:
                if attempt == 2:
                    raise
