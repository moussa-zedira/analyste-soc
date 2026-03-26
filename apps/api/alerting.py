"""Alertes multicanaux — dispatchers Slack, Email et Webhook."""

from __future__ import annotations

import json
import logging
import smtplib
from email.mime.text import MIMEText

import httpx

from apps.api.config import get_settings
from apps.api.db.session import SessionLocal
from apps.api.models.alert_config import AlertChannel

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_COLORS = {
    "low": "#3B82F6",
    "medium": "#EAB308",
    "high": "#F97316",
    "critical": "#EF4444",
}


def dispatch_alert(incident_data: dict) -> None:
    """Distribue l'alerte à tous les canaux actifs correspondant au seuil de sévérité."""
    db = SessionLocal()
    try:
        channels = db.query(AlertChannel).filter(AlertChannel.enabled.is_(True)).all()
        incident_severity = incident_data.get("severity", "low")
        incident_rank = SEVERITY_RANK.get(incident_severity, 0)

        for channel in channels:
            min_rank = SEVERITY_RANK.get(channel.min_severity, 0)
            if incident_rank < min_rank:
                continue

            try:
                config = json.loads(channel.config_json)
            except (json.JSONDecodeError, TypeError):
                logger.warning("Invalid config_json for channel '%s', skipping", channel.name)
                continue
            try:
                if channel.channel_type == "slack":
                    _send_slack(config, incident_data)
                elif channel.channel_type == "email":
                    _send_email(config, incident_data)
                elif channel.channel_type == "webhook":
                    _send_webhook(config, incident_data)
                else:
                    logger.warning("Unknown channel type: %s", channel.channel_type)
            except Exception:
                logger.exception(
                    "Failed to send alert via %s channel '%s'",
                    channel.channel_type,
                    channel.name,
                )
    finally:
        db.close()

    # Also try global settings-based channels
    _try_global_slack(incident_data)
    _try_global_webhook(incident_data)


def _send_slack(config: dict, incident: dict) -> None:
    """Envoie une notification Slack via un webhook entrant."""
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        return

    severity = incident.get("severity", "unknown")
    color = SEVERITY_COLORS.get(severity, "#808080")

    payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🚨 {incident.get('title', 'New Incident')}",
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:* {severity.upper()}"},
                            {"type": "mrkdwn", "text": f"*Rule:* {incident.get('rule_id', 'N/A')}"},
                            {"type": "mrkdwn", "text": f"*Entity:* {incident.get('entity_key', 'N/A')}"},
                            {"type": "mrkdwn", "text": f"*ID:* {incident.get('id', 'N/A')}"},
                        ],
                    },
                ],
            }
        ]
    }

    httpx.post(webhook_url, json=payload, timeout=10.0)


def _send_email(config: dict, incident: dict) -> None:
    """Envoie une alerte par email via SMTP."""
    settings = get_settings()
    if not settings.SMTP_HOST:
        return

    to_address = config.get("to", "")
    if not to_address:
        return

    severity = incident.get("severity", "unknown")
    subject = f"[SIEM {severity.upper()}] {incident.get('title', 'New Incident')}"
    body = (
        f"Incident: {incident.get('title', 'N/A')}\n"
        f"Severity: {severity}\n"
        f"Rule: {incident.get('rule_id', 'N/A')}\n"
        f"Entity: {incident.get('entity_key', 'N/A')}\n"
        f"ID: {incident.get('id', 'N/A')}\n"
        f"Description: {incident.get('description', 'N/A')}\n"
    )

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_address

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
        if settings.SMTP_USER:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM, [to_address], msg.as_string())


def _send_webhook(config: dict, incident: dict) -> None:
    """Envoie une notification par webhook POST."""
    url = config.get("url", "")
    if not url:
        return
    httpx.post(url, json=incident, timeout=10.0)


def _try_global_slack(incident: dict) -> None:
    """Envoie via le SLACK_WEBHOOK_URL global si configuré."""
    settings = get_settings()
    if settings.SLACK_WEBHOOK_URL:
        _send_slack({"webhook_url": settings.SLACK_WEBHOOK_URL}, incident)


def _try_global_webhook(incident: dict) -> None:
    """Envoie via le WEBHOOK_URL global si configuré et activé."""
    settings = get_settings()
    if settings.WEBHOOK_ENABLED and settings.WEBHOOK_URL:
        _send_webhook({"url": settings.WEBHOOK_URL}, incident)
