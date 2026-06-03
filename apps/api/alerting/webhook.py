"""Generic webhook sender — backward-compatible with the original webhook channel."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from apps.api.security_url import UnsafeURLError, validate_outbound_url

logger = logging.getLogger(__name__)


async def send_alert(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Send incident data via HTTP POST to a generic webhook.

    Config keys:
        url: str — Target webhook URL
        headers: dict — Extra headers (e.g. auth tokens)
        method: str — HTTP method (default POST)
    """
    url = config.get("url", "")
    if not url:
        raise ValueError("No webhook url configured")

    try:
        url = validate_outbound_url(url)
    except UnsafeURLError as exc:
        logger.error("webhook_url_blocked", url=url, reason=str(exc))
        raise ValueError(f"Webhook URL rejected: {exc}") from exc

    headers = config.get("headers", {})
    method = config.get("method", "POST").upper()

    async with httpx.AsyncClient(timeout=15.0) as client:
        for attempt in range(3):
            try:
                resp = await client.request(method, url, json=incident, headers=headers)
                resp.raise_for_status()
                logger.info("Webhook alert sent to %s", url)
                return
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    import asyncio

                    await asyncio.sleep(2**attempt)
                    continue
                if attempt == 2:
                    raise
            except httpx.TransportError:
                if attempt == 2:
                    raise
