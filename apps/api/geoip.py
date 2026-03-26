"""GeoIP lookup using MaxMind GeoLite2 database with fallback to ip-api.com."""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

import httpx

from apps.api.config import get_settings

logger = logging.getLogger(__name__)

_reader = None
_geoip_available = False

# Rate limiting for ip-api.com (45 requests/minute free tier)
_api_lock = threading.Lock()
_api_calls: list[float] = []
_API_RATE_LIMIT = 40  # stay under 45/min
_API_WINDOW = 60.0


def _rate_limit_ip_api() -> bool:
    """Check and enforce rate limit for ip-api.com. Returns True if allowed."""
    now = time.monotonic()
    with _api_lock:
        _api_calls[:] = [t for t in _api_calls if now - t < _API_WINDOW]
        if len(_api_calls) >= _API_RATE_LIMIT:
            return False
        _api_calls.append(now)
        return True


def _init_geoip() -> None:
    """Lazy-load the MaxMind GeoLite2 database."""
    global _reader, _geoip_available
    if _reader is not None or _geoip_available:
        return
    try:
        import geoip2.database

        settings = get_settings()
        db_path = Path(settings.GEOIP_DB_PATH)
        if db_path.exists():
            _reader = geoip2.database.Reader(str(db_path))
            _geoip_available = True
            logger.info("GeoIP database loaded: %s", db_path)
        else:
            logger.warning("GeoIP database not found at %s, using ip-api.com fallback", db_path)
    except ImportError:
        logger.warning("geoip2 not installed, using ip-api.com fallback")
    except Exception:
        logger.exception("Failed to load GeoIP database")


def lookup_ip(ip: str) -> dict | None:
    """Look up a single IP. Returns {lat, lon, country, city} or None."""
    _init_geoip()
    if _reader is not None:
        try:
            response = _reader.city(ip)
            return {
                "lat": response.location.latitude or 0,
                "lon": response.location.longitude or 0,
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
            }
        except Exception:
            return None
    return None


def lookup_batch(ips: list[str]) -> dict[str, dict]:
    """Look up a batch of IPs. Returns {ip: {lat, lon, country, city}}."""
    _init_geoip()
    results: dict[str, dict] = {}

    # Try MaxMind first
    if _reader is not None:
        for ip in ips:
            geo = lookup_ip(ip)
            if geo is not None:
                results[ip] = geo
        return results

    # Fallback to ip-api.com batch endpoint (rate-limited)
    if not _rate_limit_ip_api():
        logger.warning("ip-api.com rate limit reached, skipping batch lookup")
        return results

    try:
        resp = httpx.post(
            "http://ip-api.com/batch",
            json=[{"query": ip, "fields": "status,query,country,city,lat,lon"} for ip in ips[:100]],
            timeout=10.0,
        )
        for item in resp.json():
            if item.get("status") == "success":
                results[item["query"]] = {
                    "lat": item.get("lat", 0),
                    "lon": item.get("lon", 0),
                    "country": item.get("country", "Unknown"),
                    "city": item.get("city", "Unknown"),
                }
    except Exception:
        logger.exception("ip-api.com batch lookup failed")

    return results
