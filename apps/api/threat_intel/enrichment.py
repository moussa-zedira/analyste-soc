"""Pipeline d'enrichissement TI — enrichit les events avec les donnees de threat intelligence."""

from __future__ import annotations

import asyncio
import json
import logging

from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.threat_intel.base import TIResult
from apps.api.threat_intel.cache import get_cached, set_cached

logger = logging.getLogger(__name__)


def _get_providers() -> list:
    """Initialise les providers TI configures."""
    settings = get_settings()
    providers = []

    abuseipdb_key = getattr(settings, "ABUSEIPDB_API_KEY", "")
    if abuseipdb_key:
        from apps.api.threat_intel.abuseipdb import AbuseIPDBProvider
        providers.append(AbuseIPDBProvider(abuseipdb_key))

    otx_key = getattr(settings, "OTX_API_KEY", "")
    if otx_key:
        from apps.api.threat_intel.otx import OTXProvider
        providers.append(OTXProvider(otx_key))

    return providers


async def _lookup_ip(ip: str, db: Session) -> TIResult | None:
    """Lookup une IP via tous les providers, avec cache."""
    providers = _get_providers()
    if not providers:
        return None

    # Check cache first
    for p in providers:
        cached = get_cached(ip, p.name, db)
        if cached is not None:
            return cached

    # Query providers
    best_result: TIResult | None = None

    for provider in providers:
        try:
            result = await provider.check_ip(ip)
            if result:
                set_cached(result, db)
                if best_result is None or result.risk_score > best_result.risk_score:
                    best_result = result
        except Exception:
            logger.exception("Provider %s failed for %s", provider.name, ip)

    return best_result


def enrich_event_sync(event_id: str, db: Session) -> None:
    """Enrichit un event avec les donnees TI (version synchrone pour Celery)."""
    from apps.api.models.event import Event

    event = db.get(Event, event_id)
    if not event:
        return

    ips_to_check = []
    if event.src_ip:
        ips_to_check.append(event.src_ip)
    if event.dst_ip:
        ips_to_check.append(event.dst_ip)

    if not ips_to_check:
        return

    loop = asyncio.new_event_loop()
    try:
        best_score = 0
        all_tags: list[str] = []

        for ip in ips_to_check:
            result = loop.run_until_complete(_lookup_ip(ip, db))
            if result:
                best_score = max(best_score, result.risk_score)
                all_tags.extend(result.tags)

        if best_score > 0 or all_tags:
            event.ti_score = best_score
            event.ti_tags = json.dumps(list(set(all_tags))[:20])
            db.commit()
            logger.info("Enriched event %s: ti_score=%d", event_id, best_score)
    except Exception:
        db.rollback()
        logger.exception("Failed to enrich event %s", event_id)
    finally:
        loop.close()


async def lookup_ip_manual(ip: str, db: Session) -> dict:
    """Lookup manuel d'une IP — retourne les resultats de tous les providers."""
    providers = _get_providers()
    results = []

    for provider in providers:
        # Check cache
        cached = get_cached(ip, provider.name, db)
        if cached:
            results.append({
                "source": cached.source,
                "risk_score": cached.risk_score,
                "is_malicious": cached.is_malicious,
                "categories": cached.categories,
                "tags": cached.tags,
                "total_reports": cached.total_reports,
                "cached": True,
            })
            continue

        try:
            result = await provider.check_ip(ip)
            if result:
                set_cached(result, db)
                results.append({
                    "source": result.source,
                    "risk_score": result.risk_score,
                    "is_malicious": result.is_malicious,
                    "categories": result.categories,
                    "tags": result.tags,
                    "total_reports": result.total_reports,
                    "cached": False,
                })
        except Exception:
            logger.exception("Provider %s failed for manual lookup %s", provider.name, ip)

    # Aggregate
    max_score = max((r["risk_score"] for r in results), default=0)
    is_malicious = any(r["is_malicious"] for r in results)
    all_tags = list(set(t for r in results for t in r.get("tags", [])))

    return {
        "ip": ip,
        "risk_score": max_score,
        "is_malicious": is_malicious,
        "tags": all_tags,
        "providers": results,
    }
