"""Multi-channel alerting system — dispatcher and channel registry.

Backward-compatible: ``from apps.api.alerting import dispatch_alert`` still works.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from apps.api.config import get_settings
from apps.api.db.session import SessionLocal
from apps.api.models.alert_config import AlertChannel, AlertRule
from apps.api.observability import record_alert

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SEVERITY_COLORS = {
    "low": "#3B82F6",
    "medium": "#EAB308",
    "high": "#F97316",
    "critical": "#EF4444",
}

# Channel type -> sender module mapping (lazy imports)
_CHANNEL_REGISTRY: dict[str, str] = {
    "slack": "apps.api.alerting.slack",
    "email": "apps.api.alerting.smtp",
    "smtp": "apps.api.alerting.smtp",
    "discord": "apps.api.alerting.discord",
    "pagerduty": "apps.api.alerting.pagerduty",
    "teams": "apps.api.alerting.teams",
    "telegram": "apps.api.alerting.telegram",
    "syslog": "apps.api.alerting.syslog_out",
    "webhook": "apps.api.alerting.webhook",
}

# Simple per-channel rate limiter: channel_id -> last_sent_ts
_rate_limit_cache: dict[str, float] = {}
RATE_LIMIT_SECONDS = 5  # min seconds between alerts on same channel


def _get_sender(channel_type: str):
    """Lazy-import and return the send_alert coroutine for a channel type."""
    import importlib

    module_path = _CHANNEL_REGISTRY.get(channel_type)
    if not module_path:
        return None
    mod = importlib.import_module(module_path)
    return getattr(mod, "send_alert", None)


def _check_rate_limit(channel_id: str) -> bool:
    """Return True if channel is rate-limited (should skip)."""
    now = time.time()
    last = _rate_limit_cache.get(channel_id, 0)
    if now - last < RATE_LIMIT_SECONDS:
        return True
    _rate_limit_cache[channel_id] = now
    return False


async def async_dispatch_alert(incident_data: dict) -> list[dict[str, Any]]:
    """Dispatch alert to all matching channels asynchronously.

    Returns a list of result dicts: [{channel_id, channel_type, status, error?}].
    """
    db = SessionLocal()
    results: list[dict[str, Any]] = []
    try:
        channels = db.query(AlertChannel).filter(AlertChannel.enabled.is_(True)).all()
        incident_severity = incident_data.get("severity", "low")
        incident_rank = SEVERITY_RANK.get(incident_severity, 0)

        # Also check alert rules for condition-based routing
        rules = db.query(AlertRule).filter(AlertRule.enabled.is_(True)).all()
        rule_channel_ids: set[str] = set()
        for rule in rules:
            if _rule_matches(rule, incident_data):
                rule_channel_ids.add(rule.channel_id)

        tasks = []
        for channel in channels:
            min_rank = SEVERITY_RANK.get(channel.min_severity, 0)
            # Channel fires if severity threshold met OR an alert rule targets it
            if incident_rank < min_rank and channel.id not in rule_channel_ids:
                continue

            if _check_rate_limit(channel.id):
                results.append({
                    "channel_id": channel.id,
                    "channel_type": channel.channel_type,
                    "status": "rate_limited",
                })
                continue

            try:
                config = json.loads(channel.config_json)
            except (json.JSONDecodeError, TypeError):
                logger.warning("Invalid config_json for channel '%s'", channel.name)
                results.append({
                    "channel_id": channel.id,
                    "channel_type": channel.channel_type,
                    "status": "error",
                    "error": "Invalid config_json",
                })
                continue

            sender = _get_sender(channel.channel_type)
            if sender is None:
                logger.warning("No sender for channel type: %s", channel.channel_type)
                results.append({
                    "channel_id": channel.id,
                    "channel_type": channel.channel_type,
                    "status": "error",
                    "error": f"Unknown channel type: {channel.channel_type}",
                })
                continue

            tasks.append((channel, config, sender))

        # Fire all channels concurrently
        async def _fire(ch: AlertChannel, cfg: dict, fn):
            try:
                await fn(cfg, incident_data)
                record_alert(ch.channel_type, success=True)
                return {"channel_id": ch.id, "channel_type": ch.channel_type, "status": "sent"}
            except Exception as exc:
                record_alert(ch.channel_type, success=False)
                logger.exception(
                    "Failed to send alert via %s channel '%s'", ch.channel_type, ch.name
                )
                return {
                    "channel_id": ch.id,
                    "channel_type": ch.channel_type,
                    "status": "error",
                    "error": str(exc),
                }

        if tasks:
            coro_results = await asyncio.gather(
                *[_fire(ch, cfg, fn) for ch, cfg, fn in tasks],
                return_exceptions=False,
            )
            results.extend(coro_results)

    finally:
        db.close()

    # Global channels from settings
    await _try_global_channels(incident_data)
    return results


def _rule_matches(rule: AlertRule, incident: dict) -> bool:
    """Check if an alert rule's conditions match the incident."""
    try:
        conditions = json.loads(rule.conditions_json)
    except (json.JSONDecodeError, TypeError):
        return False

    for field, expected in conditions.items():
        actual = incident.get(field)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif actual != expected:
            return False
    return True


async def _try_global_channels(incident: dict) -> None:
    """Fire alerts via global settings (backward compat)."""
    settings = get_settings()
    if settings.SLACK_WEBHOOK_URL:
        try:
            from apps.api.alerting.slack import send_alert as slack_send
            await slack_send({"webhook_url": settings.SLACK_WEBHOOK_URL}, incident)
        except Exception:
            logger.exception("Global Slack alert failed")

    if settings.WEBHOOK_ENABLED and settings.WEBHOOK_URL:
        try:
            from apps.api.alerting.webhook import send_alert as webhook_send
            await webhook_send({"url": settings.WEBHOOK_URL}, incident)
        except Exception:
            logger.exception("Global webhook alert failed")


def dispatch_alert(incident_data: dict) -> None:
    """Synchronous backward-compatible entry point.

    Used by Celery tasks that call ``from apps.api.alerting import dispatch_alert``.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # We're inside an async context (e.g. FastAPI) — schedule it
        asyncio.ensure_future(async_dispatch_alert(incident_data))
    else:
        asyncio.run(async_dispatch_alert(incident_data))


async def send_test_alert(channel: AlertChannel) -> dict[str, Any]:
    """Send a test alert through a specific channel. Returns status dict."""
    test_incident = {
        "id": "test-000",
        "title": "Test Alert — Channel Verification",
        "severity": "medium",
        "rule_id": "TEST-001",
        "entity_key": "test@example.com",
        "description": "This is a test alert to verify channel configuration.",
        "threat_score": 50,
        "recommended_actions": ["Verify you received this alert", "No action needed"],
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        config = json.loads(channel.config_json)
    except (json.JSONDecodeError, TypeError):
        return {"status": "error", "error": "Invalid config_json"}

    sender = _get_sender(channel.channel_type)
    if sender is None:
        return {"status": "error", "error": f"Unknown channel type: {channel.channel_type}"}

    try:
        await sender(config, test_incident)
        return {"status": "sent", "channel_type": channel.channel_type}
    except Exception as exc:
        return {"status": "error", "error": str(exc)}


__all__ = [
    "dispatch_alert",
    "async_dispatch_alert",
    "send_test_alert",
    "SEVERITY_RANK",
    "SEVERITY_COLORS",
]
