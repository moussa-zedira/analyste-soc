"""Microsoft Teams webhook integration — Adaptive Card format."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from apps.api.alerting import SEVERITY_COLORS

logger = logging.getLogger(__name__)

_SEVERITY_STYLE = {
    "critical": "attention",
    "high": "warning",
    "medium": "accent",
    "low": "good",
}


def _build_adaptive_card(incident: dict[str, Any]) -> dict:
    """Build a Microsoft Adaptive Card payload."""
    severity = incident.get("severity", "medium")
    SEVERITY_COLORS.get(severity, "#808080")
    style = _SEVERITY_STYLE.get(severity, "default")

    facts = [
        {"title": "Severity", "value": severity.upper()},
        {"title": "Threat Score", "value": str(incident.get("threat_score", "N/A"))},
        {"title": "Rule", "value": incident.get("rule_id", "N/A")},
        {"title": "Entity", "value": incident.get("entity_key", "N/A")},
        {"title": "Incident ID", "value": incident.get("id", "N/A")},
        {"title": "Timestamp", "value": incident.get("timestamp", "N/A")},
    ]

    body: list[dict] = [
        {
            "type": "TextBlock",
            "text": incident.get("title", "Security Alert"),
            "weight": "Bolder",
            "size": "Large",
            "color": style,
        },
        {
            "type": "TextBlock",
            "text": incident.get("description", "No description"),
            "wrap": True,
        },
        {
            "type": "FactSet",
            "facts": facts,
        },
    ]

    actions_list = incident.get("recommended_actions", [])
    if actions_list:
        items = "\n".join(f"- {a}" for a in actions_list[:5])
        body.append({
            "type": "TextBlock",
            "text": f"**Recommended Actions:**\n{items}",
            "wrap": True,
        })

    card = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": body,
                    "actions": [
                        {
                            "type": "Action.OpenUrl",
                            "title": "Investigate",
                            "url": f"https://siem.local/incidents/{incident.get('id', '')}",
                        },
                        {
                            "type": "Action.OpenUrl",
                            "title": "Acknowledge",
                            "url": f"https://siem.local/incidents/{incident.get('id', '')}/ack",
                        },
                    ],
                },
            }
        ],
    }
    return card


async def send_alert(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Send a Microsoft Teams alert via incoming webhook.

    Config keys:
        webhook_url: str — Teams incoming webhook URL
    """
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        raise ValueError("No Teams webhook_url configured")

    payload = _build_adaptive_card(incident)

    async with httpx.AsyncClient(timeout=15.0) as client:
        for attempt in range(3):
            try:
                resp = await client.post(webhook_url, json=payload)
                if resp.status_code == 429:
                    import asyncio
                    retry_after = float(resp.headers.get("Retry-After", str(2 ** attempt)))
                    await asyncio.sleep(retry_after)
                    continue
                resp.raise_for_status()
                logger.info("Teams alert sent for incident %s", incident.get("id"))
                return
            except httpx.TransportError:
                if attempt == 2:
                    raise
