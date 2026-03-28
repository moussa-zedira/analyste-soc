"""API Threat Intelligence — lookup IP, stats, bulk check."""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])
logger = logging.getLogger(__name__)


class TILookupResponse(BaseModel):
    ip: str
    risk_score: int
    is_malicious: bool
    tags: list[str]
    providers: list[dict]


class TIStatsResponse(BaseModel):
    cache_entries: int
    providers_configured: list[str]
    abuseipdb_daily_used: int
    abuseipdb_daily_limit: int
    otx_hourly_used: int
    otx_hourly_limit: int


class BulkCheckRequest(BaseModel):
    ips: list[str]


class BulkCheckResponse(BaseModel):
    results: list[dict]


@router.get("/lookup/{ip}", response_model=TILookupResponse)
async def lookup_ip(
    ip: str,
    db: Session = Depends(get_db),
) -> dict:
    """Lookup manuel d'une adresse IP via les providers TI."""
    from apps.api.threat_intel.enrichment import lookup_ip_manual

    result = await lookup_ip_manual(ip, db)
    return result


@router.get("/stats", response_model=TIStatsResponse)
def ti_stats(db: Session = Depends(get_db)) -> dict:
    """Statistiques d'utilisation des APIs TI."""
    from apps.api.config import get_settings
    from apps.api.models.ti_cache import TICache

    settings = get_settings()

    cache_count = db.query(func.count(TICache.id)).scalar() or 0

    providers = []
    if getattr(settings, "ABUSEIPDB_API_KEY", ""):
        providers.append("abuseipdb")
    if getattr(settings, "OTX_API_KEY", ""):
        providers.append("otx")

    # Read Redis counters
    abuse_used = 0
    otx_used = 0
    try:
        from apps.api.cache import get_redis_client
        r = get_redis_client()
        if r:
            v = r.get("siem:ti:abuseipdb:daily_count")
            abuse_used = int(v) if v else 0
            v = r.get("siem:ti:otx:hourly_count")
            otx_used = int(v) if v else 0
    except Exception:
        pass

    return {
        "cache_entries": cache_count,
        "providers_configured": providers,
        "abuseipdb_daily_used": abuse_used,
        "abuseipdb_daily_limit": 1000,
        "otx_hourly_used": otx_used,
        "otx_hourly_limit": 10000,
    }


@router.post("/bulk-check", response_model=BulkCheckResponse)
async def bulk_check(
    payload: BulkCheckRequest,
    db: Session = Depends(get_db),
) -> dict:
    """Verifie un batch d'IPs via les providers TI."""
    from apps.api.threat_intel.enrichment import lookup_ip_manual

    if len(payload.ips) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 IPs per batch")

    results = []
    for ip in payload.ips:
        result = await lookup_ip_manual(ip, db)
        results.append(result)

    return {"results": results}
