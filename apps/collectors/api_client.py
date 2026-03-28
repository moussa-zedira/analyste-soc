"""Client HTTP pour envoyer les events normalises a l'API SIEM."""

from __future__ import annotations

import logging
from dataclasses import asdict
from typing import TYPE_CHECKING

import httpx

from apps.collectors.config import API_BASE_URL, API_KEY

if TYPE_CHECKING:
    from apps.collectors.normalizer import NormalizedEvent

logger = logging.getLogger(__name__)

_client: httpx.Client | None = None


def _get_client() -> httpx.Client:
    global _client
    if _client is None:
        _client = httpx.Client(
            base_url=API_BASE_URL,
            headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
            timeout=10.0,
        )
    return _client


def send_event(event: NormalizedEvent) -> bool:
    """Envoie un event unique. Retourne True si succes."""
    try:
        resp = _get_client().post("/events", json=asdict(event))
        resp.raise_for_status()
        return True
    except Exception:
        logger.exception("Failed to send event")
        return False


def send_batch(events: list[NormalizedEvent]) -> int:
    """Envoie un batch d'events. Retourne le nombre ingere."""
    if not events:
        return 0
    try:
        payload = [asdict(e) for e in events]
        resp = _get_client().post("/events/batch", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return data.get("ingested", len(events))
    except Exception:
        logger.exception("Failed to send batch of %d events", len(events))
        return 0
