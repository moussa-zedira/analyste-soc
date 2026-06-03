"""Slack webhook integration — Block Kit messages with severity routing."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from apps.api.alerting import SEVERITY_COLORS

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":large_orange_circle:",
    "medium": ":large_yellow_circle:",
    "low": ":large_blue_circle:",
}


def _build_blocks(incident: dict[str, Any]) -> list[dict]:
    """Build Slack Block Kit blocks for an incident."""
    severity = incident.get("severity", "unknown")
    emoji = _SEVERITY_EMOJI.get(severity, ":white_circle:")
    title = incident.get("title", "New Incident")

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} {title}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Threat Score:*\n{incident.get('threat_score', 'N/A')}",
                },
                {"type": "mrkdwn", "text": f"*Rule:*\n{incident.get('rule_id', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Entity:*\n{incident.get('entity_key', 'N/A')}"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Description:*\n{incident.get('description', 'No description')}",
            },
        },
    ]

    # Recommended actions
    actions_list = incident.get("recommended_actions", [])
    if actions_list:
        actions_text = "\n".join(f"• {a}" for a in actions_list[:5])
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Recommended Actions:*\n{actions_text}",
                },
            }
        )

    # Context line
    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Incident ID: `{incident.get('id', 'N/A')}` | {incident.get('timestamp', '')}",
                }
            ],
        }
    )

    # Interactive buttons
    blocks.append(
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Acknowledge", "emoji": True},
                    "style": "primary",
                    "action_id": "ack_incident",
                    "value": str(incident.get("id", "")),
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Investigate", "emoji": True},
                    "action_id": "investigate_incident",
                    "value": str(incident.get("id", "")),
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Dismiss", "emoji": True},
                    "style": "danger",
                    "action_id": "dismiss_incident",
                    "value": str(incident.get("id", "")),
                },
            ],
        }
    )

    return blocks


async def send_alert(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Send a Slack alert via incoming webhook.

    Config keys:
        webhook_url: str — Slack incoming webhook URL
        channel_overrides: dict — severity -> webhook_url mapping for routing
    """
    severity = incident.get("severity", "low")
    color = SEVERITY_COLORS.get(severity, "#808080")

    # Channel routing by severity
    overrides = config.get("channel_overrides", {})
    webhook_url = overrides.get(severity) or config.get("webhook_url", "")
    if not webhook_url:
        raise ValueError("No Slack webhook_url configured")

    blocks = _build_blocks(incident)

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ],
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        for attempt in range(3):
            try:
                resp = await client.post(webhook_url, json=payload)
                resp.raise_for_status()
                logger.info("Slack alert sent for incident %s", incident.get("id"))
                return
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    retry_after = float(exc.response.headers.get("Retry-After", "2"))
                    import asyncio

                    await asyncio.sleep(retry_after)
                    continue
                if attempt == 2:
                    raise
            except httpx.TransportError:
                if attempt == 2:
                    raise
