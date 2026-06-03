"""Envoi de notifications webhook — fire-and-forget."""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request

from apps.api.config import get_settings
from apps.api.security_url import UnsafeURLError, validate_outbound_url

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
    """Construit un payload webhook compatible avec les embeds Discord."""
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


def _send_webhook(url: str, payload: dict, max_retries: int = 3) -> None:
    """Envoie le webhook POST avec backoff exponentiel (dans un thread d'arrière-plan)."""
    import time

    data = json.dumps(payload).encode("utf-8")
    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.info("Webhook sent successfully: %d", resp.status)
                return
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:
                logger.warning("Webhook rejected (HTTP %d), not retrying", e.code)
                return
            logger.warning(
                "Webhook attempt %d/%d failed (HTTP %d)", attempt + 1, max_retries, e.code
            )
        except Exception:
            logger.warning("Webhook attempt %d/%d failed", attempt + 1, max_retries, exc_info=True)

        if attempt < max_retries - 1:
            time.sleep(2**attempt)

    logger.error("Webhook delivery to %s failed after %d attempts", url, max_retries)


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
    """Notification webhook fire-and-forget pour un nouvel incident."""
    settings = get_settings()
    if not settings.WEBHOOK_ENABLED or not settings.WEBHOOK_URL:
        return

    try:
        safe_url = validate_outbound_url(settings.WEBHOOK_URL)
    except UnsafeURLError as exc:
        logger.error("webhook_url_blocked", url=settings.WEBHOOK_URL, reason=str(exc))
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
        args=(safe_url, payload),
        daemon=True,
    )
    thread.start()
