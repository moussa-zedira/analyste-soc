"""Recherche GeoIP via la base MaxMind GeoLite2 avec repli sur ip-api.com.

Expose :
- ``GeoIPLookup`` : classe orientée objet (chargement DB + cache LRU + Haversine)
- ``lookup_ip`` / ``lookup_batch`` : helpers fonctionnels pour la rétrocompatibilité.
"""

from __future__ import annotations

import logging
import math
import threading
import time
from functools import lru_cache
from pathlib import Path

import httpx

from apps.api.config import get_settings

logger = logging.getLogger(__name__)

_reader = None
_geoip_available = False
_geoip_warning_logged = False

# Rate limiting for ip-api.com (45 requests/minute free tier)
_api_lock = threading.Lock()
_api_calls: list[float] = []
_API_RATE_LIMIT = 40  # stay under 45/min
_API_WINDOW = 60.0


def _rate_limit_ip_api() -> bool:
    """Vérifie et applique la limite de débit pour ip-api.com. Retourne True si autorisé."""
    now = time.monotonic()
    with _api_lock:
        _api_calls[:] = [t for t in _api_calls if now - t < _API_WINDOW]
        if len(_api_calls) >= _API_RATE_LIMIT:
            return False
        _api_calls.append(now)
        return True


def _init_geoip() -> None:
    """Charge paresseusement la base de données MaxMind GeoLite2."""
    global _reader, _geoip_available, _geoip_warning_logged
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
            if not _geoip_warning_logged:
                logger.warning(
                    "GeoIP database not found at %s — set MAXMIND_LICENSE_KEY and run scripts/download_geolite.{sh,ps1}",
                    db_path,
                )
                _geoip_warning_logged = True
    except ImportError:
        if not _geoip_warning_logged:
            logger.warning("geoip2 not installed, GeoIP lookups disabled")
            _geoip_warning_logged = True
    except Exception:
        logger.exception("Failed to load GeoIP database")


# ---------------------------------------------------------------------------
# Classe GeoIPLookup — interface OO + cache LRU + Haversine
# ---------------------------------------------------------------------------


class GeoIPLookup:
    """Wrapper haut-niveau autour de MaxMind GeoLite2-City."""

    def __init__(self, db_path: str | None = None) -> None:
        """Initialise le lecteur GeoIP. Si ``db_path`` est None, utilise la config."""
        self._db_path = db_path or get_settings().GEOIP_DB_PATH
        self._reader = None
        self._available = False
        self._warning_logged = False
        self._load()

    def _load(self) -> None:
        """Charge la base GeoLite2 si elle existe, sinon log un avertissement unique."""
        try:
            import geoip2.database

            path = Path(self._db_path)
            if path.exists():
                self._reader = geoip2.database.Reader(str(path))
                self._available = True
                logger.info("GeoIPLookup: database loaded from %s", path)
            else:
                if not self._warning_logged:
                    logger.warning(
                        "GeoIPLookup: database not found at %s — set MAXMIND_LICENSE_KEY",
                        path,
                    )
                    self._warning_logged = True
        except ImportError:
            if not self._warning_logged:
                logger.warning("GeoIPLookup: geoip2 module not installed")
                self._warning_logged = True
        except Exception:
            logger.exception("GeoIPLookup: failed to open database %s", self._db_path)

    @property
    def available(self) -> bool:
        """Retourne True si la base GeoIP est chargée."""
        return self._available

    def lookup(self, ip: str) -> dict | None:
        """Recherche une IP. Retourne ``{"lat", "lon", "country", "city"}`` ou ``None``.

        Le résultat est mis en cache via ``functools.lru_cache``.
        """
        return _cached_lookup(self, ip)

    def _do_lookup(self, ip: str) -> dict | None:
        """Implémentation réelle (sans cache) — appelée par le wrapper LRU."""
        if not self._reader:
            return None
        try:
            response = self._reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            if lat is None or lon is None:
                return None
            return {
                "lat": float(lat),
                "lon": float(lon),
                "country": response.country.name or "Unknown",
                "city": response.city.name or "Unknown",
            }
        except Exception:
            return None

    @staticmethod
    def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """Distance Haversine en kilomètres entre deux points GPS."""
        radius = 6371.0  # rayon Terre en km
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = (
            math.sin(dphi / 2) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return radius * c


@lru_cache(maxsize=10000)
def _cached_lookup(instance: GeoIPLookup, ip: str) -> dict | None:
    """Cache LRU partagé pour ``GeoIPLookup.lookup``.

    L'instance est utilisée comme partie de la clé pour éviter de mélanger
    les bases entre plusieurs instances.
    """
    return instance._do_lookup(ip)


# Singleton global pour réutilisation
_default_lookup: GeoIPLookup | None = None
_default_lock = threading.Lock()


def get_geoip_lookup() -> GeoIPLookup:
    """Retourne (et crée si nécessaire) l'instance GeoIPLookup partagée."""
    global _default_lookup
    if _default_lookup is None:
        with _default_lock:
            if _default_lookup is None:
                _default_lookup = GeoIPLookup()
    return _default_lookup


# ---------------------------------------------------------------------------
# API fonctionnelle (rétrocompatible)
# ---------------------------------------------------------------------------


def lookup_ip(ip: str) -> dict | None:
    """Recherche une IP. Retourne {lat, lon, country, city} ou None."""
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
    """Recherche un lot d'IPs. Retourne {ip: {lat, lon, country, city}}."""
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
