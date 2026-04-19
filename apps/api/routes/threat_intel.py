"""API Threat Intelligence — lookup IP, stats, bulk check, provider-specific endpoints."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])
logger = logging.getLogger(__name__)


# ======================================================================
# Pydantic models
# ======================================================================

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


class GenericLookupRequest(BaseModel):
    indicator: str
    indicator_type: str = "ip"  # ip, domain, hash, url, host, tag


class ShodanSearchRequest(BaseModel):
    query: str
    page: int = 1


class MISPSearchRequest(BaseModel):
    value: Optional[str] = None
    eventinfo: Optional[str] = None
    tags: Optional[list[str]] = None
    type_attribute: Optional[str] = None
    category: Optional[str] = None
    limit: int = 25


class MISPExportRequest(BaseModel):
    event_id: Optional[str] = None
    tags: Optional[list[str]] = None
    type_attribute: Optional[str] = None
    limit: int = 500


class URLhausTagRequest(BaseModel):
    tag: str


class PayloadLookupRequest(BaseModel):
    sha256: Optional[str] = None
    md5: Optional[str] = None


# ======================================================================
# Existing endpoints
# ======================================================================

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
    if getattr(settings, "VIRUSTOTAL_API_KEY", ""):
        providers.append("virustotal")
    if getattr(settings, "SHODAN_API_KEY", ""):
        providers.append("shodan")
    if getattr(settings, "GREYNOISE_API_KEY", ""):
        providers.append("greynoise")
    if getattr(settings, "MISP_URL", "") and getattr(settings, "MISP_API_KEY", ""):
        providers.append("misp")
    providers.append("circl")
    providers.append("urlhaus")

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
        logger.debug("threat_intel: ignored exception", exc_info=True)

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


# ======================================================================
# Provider listing
# ======================================================================

@router.get("/providers")
def list_providers() -> dict:
    """Liste tous les providers TI disponibles avec leur statut."""
    from apps.api.threat_intel.enrichment import get_provider_status

    providers = get_provider_status()
    configured_count = sum(1 for p in providers if p["configured"])
    return {
        "total": len(providers),
        "configured": configured_count,
        "providers": providers,
    }


# ======================================================================
# VirusTotal endpoints
# ======================================================================

@router.post("/virustotal/lookup")
async def virustotal_lookup(payload: GenericLookupRequest) -> dict:
    """Lookup VirusTotal — IP, domain, hash, or URL."""
    from apps.api.config import get_settings
    from apps.api.threat_intel.virustotal import VirusTotalProvider

    settings = get_settings()
    api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="VirusTotal API key not configured")

    provider = VirusTotalProvider(api_key)
    itype = payload.indicator_type.lower()

    if itype == "ip":
        result = await provider.check_ip(payload.indicator)
    elif itype == "domain":
        result = await provider.check_domain(payload.indicator)
    elif itype == "hash":
        result = await provider.check_hash(payload.indicator)
    elif itype == "url":
        result = await provider.check_url(payload.indicator)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported indicator_type: {itype}. Use ip, domain, hash, or url.")

    if result is None:
        raise HTTPException(status_code=429, detail="Rate limited or lookup failed")

    return {
        "indicator": result.indicator,
        "source": result.source,
        "risk_score": result.risk_score,
        "is_malicious": result.is_malicious,
        "categories": result.categories,
        "tags": result.tags,
        "total_reports": result.total_reports,
        "raw": result.raw,
    }


# ======================================================================
# Shodan endpoints
# ======================================================================

@router.post("/shodan/lookup")
async def shodan_lookup(payload: GenericLookupRequest) -> dict:
    """Lookup Shodan — IP info, host search, exploit search, DNS."""
    from apps.api.config import get_settings
    from apps.api.threat_intel.shodan import ShodanProvider

    settings = get_settings()
    api_key = getattr(settings, "SHODAN_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="Shodan API key not configured")

    provider = ShodanProvider(api_key)
    itype = payload.indicator_type.lower()

    if itype == "ip":
        result = await provider.check_ip(payload.indicator)
        if result is None:
            raise HTTPException(status_code=429, detail="Rate limited or lookup failed")
        return {
            "indicator": result.indicator,
            "source": result.source,
            "risk_score": result.risk_score,
            "is_malicious": result.is_malicious,
            "categories": result.categories,
            "tags": result.tags,
            "total_reports": result.total_reports,
            "raw": result.raw,
        }
    elif itype == "search":
        data = await provider.search_hosts(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or search failed")
        return data
    elif itype == "exploit":
        data = await provider.search_exploits(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or search failed")
        return data
    elif itype == "dns":
        hostnames = [h.strip() for h in payload.indicator.split(",") if h.strip()]
        data = await provider.dns_resolve(hostnames)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or DNS failed")
        return data
    elif itype == "honeypot":
        score = await provider.honeypot_score(payload.indicator)
        if score is None:
            raise HTTPException(status_code=429, detail="Rate limited or honeypot check failed")
        return {"ip": payload.indicator, "honeypot_score": score}
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported indicator_type: {itype}. Use ip, search, exploit, dns, or honeypot.")


# ======================================================================
# GreyNoise endpoints
# ======================================================================

@router.post("/greynoise/lookup")
async def greynoise_lookup(payload: GenericLookupRequest) -> dict:
    """Lookup GreyNoise — IP context, RIOT, noise check."""
    from apps.api.config import get_settings
    from apps.api.threat_intel.greynoise import GreyNoiseProvider

    settings = get_settings()
    api_key = getattr(settings, "GREYNOISE_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="GreyNoise API key not configured")

    provider = GreyNoiseProvider(api_key)
    itype = payload.indicator_type.lower()

    if itype == "ip":
        result = await provider.check_ip(payload.indicator)
        if result is None:
            raise HTTPException(status_code=429, detail="Rate limited or lookup failed")
        return {
            "indicator": result.indicator,
            "source": result.source,
            "risk_score": result.risk_score,
            "is_malicious": result.is_malicious,
            "categories": result.categories,
            "tags": result.tags,
            "total_reports": result.total_reports,
            "raw": result.raw,
        }
    elif itype == "riot":
        data = await provider.riot_check(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or RIOT check failed")
        return data
    elif itype == "noise":
        data = await provider.noise_check(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or noise check failed")
        return data
    elif itype == "context":
        data = await provider.ip_context(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or context lookup failed")
        return data
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported indicator_type: {itype}. Use ip, riot, noise, or context.")


# ======================================================================
# CIRCL endpoints
# ======================================================================

@router.post("/circl/lookup")
async def circl_lookup(payload: GenericLookupRequest) -> dict:
    """Lookup CIRCL — Passive DNS, Passive SSL, Hashlookup."""
    from apps.api.config import get_settings
    from apps.api.threat_intel.circl import CIRCLProvider

    settings = get_settings()
    circl_user = getattr(settings, "CIRCL_PDNS_USER", "")
    circl_pass = getattr(settings, "CIRCL_PDNS_PASSWORD", "")
    provider = CIRCLProvider(circl_user, circl_pass)
    itype = payload.indicator_type.lower()

    if itype in ("ip", "domain", "pdns"):
        data = await provider.passive_dns(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or PDNS lookup failed")
        return data
    elif itype == "ssl":
        data = await provider.passive_ssl(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or PSSL lookup failed")
        return data
    elif itype == "hash":
        data = await provider.hash_lookup(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or hashlookup failed")
        return data
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported indicator_type: {itype}. Use ip, domain, pdns, ssl, or hash.")


# ======================================================================
# MISP endpoints
# ======================================================================

@router.post("/misp/lookup")
async def misp_lookup(payload: GenericLookupRequest) -> dict:
    """Lookup MISP — search events, attributes, galaxies, export IOCs."""
    from apps.api.config import get_settings
    from apps.api.threat_intel.misp import MISPProvider

    settings = get_settings()
    misp_url = getattr(settings, "MISP_URL", "")
    misp_key = getattr(settings, "MISP_API_KEY", "")
    if not misp_url or not misp_key:
        raise HTTPException(status_code=503, detail="MISP URL or API key not configured")

    verify_ssl = getattr(settings, "MISP_VERIFY_SSL", True)
    provider = MISPProvider(misp_url, misp_key, verify_ssl)
    itype = payload.indicator_type.lower()

    if itype == "ip":
        result = await provider.check_ip(payload.indicator)
        if result is None:
            raise HTTPException(status_code=429, detail="Rate limited or MISP lookup failed")
        return {
            "indicator": result.indicator,
            "source": result.source,
            "risk_score": result.risk_score,
            "is_malicious": result.is_malicious,
            "categories": result.categories,
            "tags": result.tags,
            "total_reports": result.total_reports,
            "raw": result.raw,
        }
    elif itype in ("domain", "hash", "attribute"):
        data = await provider.search_attributes(value=payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or attribute search failed")
        return data
    elif itype == "event":
        data = await provider.search_events(value=payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or event search failed")
        return data
    elif itype == "galaxy":
        data = await provider.search_galaxies(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or galaxy search failed")
        return data
    elif itype == "ioc_export":
        data = await provider.export_iocs(tags=[payload.indicator] if payload.indicator else None)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or IOC export failed")
        return data
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported indicator_type: {itype}. Use ip, domain, hash, attribute, event, galaxy, or ioc_export.")


# ======================================================================
# URLhaus endpoints
# ======================================================================

@router.post("/urlhaus/lookup")
async def urlhaus_lookup(payload: GenericLookupRequest) -> dict:
    """Lookup URLhaus — URL, host, payload/hash, tag search."""
    from apps.api.threat_intel.urlhaus import URLhausProvider

    provider = URLhausProvider()
    itype = payload.indicator_type.lower()

    if itype in ("ip", "host", "domain"):
        data = await provider.host_lookup(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or host lookup failed")
        return data
    elif itype == "url":
        data = await provider.url_lookup(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or URL lookup failed")
        return data
    elif itype == "hash":
        indicator = payload.indicator
        if len(indicator) == 64:
            data = await provider.payload_lookup(sha256_hash=indicator)
        else:
            data = await provider.payload_lookup(md5_hash=indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or payload lookup failed")
        return data
    elif itype == "tag":
        data = await provider.tag_lookup(payload.indicator)
        if data is None:
            raise HTTPException(status_code=429, detail="Rate limited or tag lookup failed")
        return data
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported indicator_type: {itype}. Use ip, host, domain, url, hash, or tag.")
