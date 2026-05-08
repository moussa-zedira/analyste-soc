"""Triage des evenements — classification, liste blanche et filtrage par seuil de severite."""

from __future__ import annotations

import ipaddress
import logging
import time

from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.models.event import Event
from apps.api.models.whitelist import WhitelistEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event classification mapping
# ---------------------------------------------------------------------------

EVENT_CLASSIFICATION: dict[str, str] = {
    # Benign — never triggers detection
    "auth.success": "benign",
    # Suspicious — passes detection but severity threshold applies
    "dns_anomaly": "suspicious",
    "conn.attempt": "suspicious",
    # Malicious — always analysed, even if severity is low
    "auth.fail": "malicious",
    "blocked_connection": "malicious",
    "data_exfil": "malicious",
}

DEFAULT_CLASSIFICATION = "suspicious"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---------------------------------------------------------------------------
# Whitelist cache (avoids querying DB on every detection run)
# ---------------------------------------------------------------------------

_whitelist_cache: list[WhitelistEntry] = []
_whitelist_cache_ts: float = 0.0
_CACHE_TTL = 60.0  # seconds


def _load_whitelist(db: Session) -> list[WhitelistEntry]:
    """Retourne les entrees de liste blanche actives, mises en cache pendant 60 secondes."""
    global _whitelist_cache, _whitelist_cache_ts

    now = time.monotonic()
    if now - _whitelist_cache_ts < _CACHE_TTL and _whitelist_cache_ts > 0:
        return _whitelist_cache

    entries = (
        db.query(WhitelistEntry)
        .filter(WhitelistEntry.enabled.is_(True))
        .all()
    )
    _whitelist_cache = entries
    _whitelist_cache_ts = now
    return entries


def invalidate_whitelist_cache() -> None:
    """Force le rafraichissement du cache de la liste blanche au prochain appel."""
    global _whitelist_cache_ts
    _whitelist_cache_ts = 0.0


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def classify_event(event: Event) -> str:
    """Retourne 'benign', 'suspicious' ou 'malicious' pour un evenement."""
    return EVENT_CLASSIFICATION.get(event.event_type, DEFAULT_CLASSIFICATION)


# ---------------------------------------------------------------------------
# Whitelist check
# ---------------------------------------------------------------------------


def _is_whitelisted(event: Event, whitelist: list[WhitelistEntry]) -> bool:
    """Verifie si la source de l'evenement correspond a une entree de la liste blanche."""
    for entry in whitelist:
        if entry.entry_type == "ip" and event.src_ip == entry.value:
            return True

        if entry.entry_type == "username" and event.username == entry.value:
            return True

        if entry.entry_type == "ip_range" and event.src_ip:
            try:
                network = ipaddress.ip_network(entry.value, strict=False)
                if ipaddress.ip_address(event.src_ip) in network:
                    return True
            except ValueError:
                pass

    return False


# ---------------------------------------------------------------------------
# Severity threshold
# ---------------------------------------------------------------------------


def _below_threshold(event: Event) -> bool:
    """Retourne True si la severite de l'evenement est inferieure au minimum configure."""
    settings = get_settings()
    min_level = SEVERITY_ORDER.get(settings.MIN_SEVERITY, 1)
    event_level = SEVERITY_ORDER.get(event.severity, 0)
    return event_level < min_level


# ---------------------------------------------------------------------------
# Main filter function
# ---------------------------------------------------------------------------


def filter_events(events: list[Event], db: Session) -> list[Event]:
    """Filtre les evenements avant la detection. Retourne uniquement ceux a analyser."""
    settings = get_settings()

    if not settings.TRIAGE_ENABLED:
        return events

    whitelist = _load_whitelist(db)
    filtered = []
    stats = {"benign": 0, "whitelisted": 0, "below_threshold": 0, "passed": 0}

    for event in events:
        classification = classify_event(event)

        # 1. Benign events are always excluded
        if classification == "benign":
            stats["benign"] += 1
            continue

        # 2. Whitelisted IPs/users are excluded
        if _is_whitelisted(event, whitelist):
            stats["whitelisted"] += 1
            continue

        # 3. Severity threshold (only for suspicious, malicious always passes)
        if classification == "suspicious" and _below_threshold(event):
            stats["below_threshold"] += 1
            continue

        stats["passed"] += 1
        filtered.append(event)

    logger.info(
        "Triage: %d/%d events passed (benign=%d, whitelisted=%d, below_threshold=%d)",
        stats["passed"], len(events),
        stats["benign"], stats["whitelisted"], stats["below_threshold"],
    )
    return filtered
