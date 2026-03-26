"""Webhook notification sender — fire-and-forget."""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request

from apps.api.config import get_settings

logger = logging.getLogger(__name__)


def _build_payload(
    incident_id: str,
    title: str,
    severity: str,
    description: str,
    rule_id: str,
    entity_key: str,
    status: str,
    created_at: str,
) -> dict:
    """Build a webhook payload compatible with Discord embeds."""
    color_map = {
        "low": 0x3B82F6,
        "medium": 0xF59E0B,
        "high": 0xF97316,
        "critical": 0xEF4444,
    }
    color = color_map.get(severity, 0x6B7280)

    return {
        "content": None,
        "embeds": [
            {
                "title": f"New Incident: {title}",
                "description": description,
                "color": color,
                "fields": [
                    {"name": "Severity", "value": severity.upper(), "inline": True},
                    {"name": "Status", "value": status, "inline": True},
                    {"name": "Rule", "value": rule_id, "inline": True},
                    {"name": "Entity", "value": entity_key, "inline": True},
                    {"name": "Incident ID", "value": incident_id, "inline": False},
                ],
                "timestamp": created_at,
            }
        ],
    }


def _send_webhook(url: str, payload: dict) -> None:
    """Send the webhook HTTP POST (runs in background thread)."""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            logger.info("Webhook sent successfully: %d", resp.status)
    except Exception:
        logger.exception("Failed to send webhook to %s", url)


def notify_incident_created(
    incident_id: str,
    title: str,
    severity: str,
    description: str,
    rule_id: str,
    entity_key: str,
    status: str = "open",
    created_at: str = "",
) -> None:
    """Fire-and-forget webhook notification for a new incident."""
    settings = get_settings()
    if not settings.WEBHOOK_ENABLED or not settings.WEBHOOK_URL:
        return

    payload = _build_payload(
        incident_id=incident_id,
        title=title,
        severity=severity,
        description=description,
        rule_id=rule_id,
        entity_key=entity_key,
        status=status,
        created_at=created_at,
    )

    thread = threading.Thread(
        target=_send_webhook,
        args=(settings.WEBHOOK_URL, payload),
        daemon=True,
    )
    thread.start()
