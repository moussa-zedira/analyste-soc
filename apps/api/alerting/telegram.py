"""Telegram Bot API integration — Markdown alerts with inline keyboards."""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

TELEGRAM_API = "https://api.telegram.org"

_SEVERITY_ICON = {
    "critical": "\U0001f534",  # red circle
    "high": "\U0001f7e0",      # orange circle
    "medium": "\U0001f7e1",    # yellow circle
    "low": "\U0001f535",       # blue circle
}


def _build_message(incident: dict[str, Any]) -> str:
    """Build a Markdown-formatted Telegram message."""
    severity = incident.get("severity", "medium")
    icon = _SEVERITY_ICON.get(severity, "\u26aa")
    title = incident.get("title", "Security Alert")
    # Escape markdown special chars
    desc = incident.get("description", "N/A")

    lines = [
        f"{icon} *{_escape_md(title)}*",
        "",
        f"*Severity:* `{severity.upper()}`",
        f"*Threat Score:* `{incident.get('threat_score', 'N/A')}`",
        f"*Rule:* `{incident.get('rule_id', 'N/A')}`",
        f"*Entity:* `{incident.get('entity_key', 'N/A')}`",
        f"*Incident ID:* `{incident.get('id', 'N/A')}`",
        "",
        _escape_md(desc),
    ]

    actions = incident.get("recommended_actions", [])
    if actions:
        lines.append("")
        lines.append("*Recommended Actions:*")
        for a in actions[:5]:
            lines.append(f"  \\- {_escape_md(a)}")

    return "\n".join(lines)


def _escape_md(text: str) -> str:
    """Escape MarkdownV2 special characters."""
    special = r"_*[]()~`>#+-=|{}.!"
    result = []
    for ch in str(text):
        if ch in special:
            result.append("\\")
        result.append(ch)
    return "".join(result)


def _build_keyboard(incident: dict[str, Any]) -> dict:
    """Build an inline keyboard for the Telegram message."""
    incident_id = incident.get("id", "")
    return {
        "inline_keyboard": [
            [
                {"text": "Acknowledge", "callback_data": f"ack:{incident_id}"},
                {"text": "Investigate", "callback_data": f"investigate:{incident_id}"},
            ],
            [
                {"text": "Dismiss", "callback_data": f"dismiss:{incident_id}"},
            ],
        ]
    }


async def send_alert(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Send a Telegram alert via Bot API.

    Config keys:
        bot_token: str — Telegram bot token
        chat_id: str — Target chat/group/channel ID
    """
    bot_token = config.get("bot_token", "")
    chat_id = config.get("chat_id", "")
    if not bot_token or not chat_id:
        raise ValueError("bot_token and chat_id are required for Telegram")

    text = _build_message(incident)
    keyboard = _build_keyboard(incident)

    url = f"{TELEGRAM_API}/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "MarkdownV2",
        "reply_markup": keyboard,
    }

    async with httpx.AsyncClient(timeout=15.0) as client:
        for attempt in range(3):
            try:
                resp = await client.post(url, json=payload)
                data = resp.json()
                if resp.status_code == 429:
                    import asyncio
                    retry_after = data.get("parameters", {}).get("retry_after", 2)
                    await asyncio.sleep(float(retry_after))
                    continue
                if not data.get("ok"):
                    raise RuntimeError(f"Telegram API error: {data.get('description', resp.text)}")
                logger.info("Telegram alert sent to chat %s", chat_id)
                return
            except httpx.TransportError:
                if attempt == 2:
                    raise
