"""Provider CIRCL — Passive DNS, Passive SSL, Hashlookup (free, no key required)."""

from __future__ import annotations

import logging

import httpx

from apps.api.threat_intel.base import TIResult
from apps.api.threat_intel.observability import (
    CircuitOpenError,
    get_circuit_breaker,
    instrument,
)

logger = logging.getLogger(__name__)

PDNS_URL = "https://www.circl.lu/pdns/query"
PSSL_URL = "https://www.circl.lu/pssl/query"
HASHLOOKUP_URL = "https://hashlookup.circl.lu/lookup"
RATE_LIMIT = 60  # req/min conservative
REDIS_COUNTER_KEY = "siem:ti:circl:minute_count"
REDIS_COUNTER_TTL = 60


class CIRCLProvider:
    name = "circl"

    def __init__(self, username: str = "", password: str = "") -> None:
        self._auth = (username, password) if username and password else None
        self._client = httpx.AsyncClient(timeout=15.0)
        self._cb = get_circuit_breaker(self.name)

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _check_rate_limit(self) -> bool:
        try:
            from apps.api.cache import get_redis_client
            r = get_redis_client()
            if r is None:
                return True
            count = r.get(REDIS_COUNTER_KEY)
            if count and int(count) >= RATE_LIMIT:
                logger.warning("CIRCL rate limit reached (%d/min)", RATE_LIMIT)
                return False
            return True
        except Exception:
            return True

    async def _increment_counter(self) -> None:
        try:
            from apps.api.cache import get_redis_client
            r = get_redis_client()
            if r is None:
                return
            pipe = r.pipeline()
            pipe.incr(REDIS_COUNTER_KEY)
            pipe.expire(REDIS_COUNTER_KEY, REDIS_COUNTER_TTL)
            pipe.execute()
        except Exception as exc:
            logger.debug("CIRCL rate-limit counter update failed: %s", exc)

    # ------------------------------------------------------------------
    # Public API — IP via passive DNS
    # ------------------------------------------------------------------

    @instrument("circl", "check_ip")
    async def check_ip(self, ip: str) -> TIResult | None:
        """Lookup IP via CIRCL Passive DNS."""
        result = await self.passive_dns(ip)
        if result is None:
            return None

        records = result.get("records", [])
        count = len(records)
        unique_domains = list(set(r.get("rrname", "") for r in records))[:20]

        # Heuristic: more passive DNS records = more exposure
        score = min(count * 2, 60)

        return TIResult(
            indicator=ip,
            source=self.name,
            risk_score=score,
            is_malicious=False,  # CIRCL is passive, no verdict
            categories=["passive_dns"],
            tags=[f"domains:{len(unique_domains)}"] + unique_domains[:5],
            total_reports=count,
            raw={"record_count": count, "domains": unique_domains[:50]},
        )

    # ------------------------------------------------------------------
    # Passive DNS
    # ------------------------------------------------------------------

    @instrument("circl", "passive_dns")
    async def passive_dns(self, indicator: str) -> dict | None:
        """Query CIRCL Passive DNS for an IP or domain."""
        if not await self._check_rate_limit():
            return None
        try:
            kwargs: dict = {"headers": {"Accept": "application/json"}}
            if self._auth:
                kwargs["auth"] = self._auth
            resp = await self._cb.call(
                self._client.get,
                f"{PDNS_URL}/{indicator}",
                **kwargs,
            )
            resp.raise_for_status()
            await self._increment_counter()

            # CIRCL returns NDJSON (one JSON object per line)
            records = []
            for line in resp.text.strip().splitlines():
                if line.strip():
                    import json
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        continue

            return {
                "indicator": indicator,
                "record_count": len(records),
                "records": records[:100],
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"indicator": indicator, "record_count": 0, "records": []}
            logger.warning("CIRCL PDNS error for %s: %s", indicator, e.response.status_code)
            return None
        except Exception:
            logger.exception("CIRCL passive_dns failed for %s", indicator)
            return None

    # ------------------------------------------------------------------
    # Passive SSL
    # ------------------------------------------------------------------

    @instrument("circl", "passive_ssl")
    async def passive_ssl(self, indicator: str) -> dict | None:
        """Query CIRCL Passive SSL for an IP (certificate history)."""
        if not await self._check_rate_limit():
            return None
        try:
            kwargs: dict = {"headers": {"Accept": "application/json"}}
            if self._auth:
                kwargs["auth"] = self._auth
            resp = await self._cb.call(
                self._client.get,
                f"{PSSL_URL}/{indicator}",
                **kwargs,
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            certs = data.get("certificates", []) if isinstance(data, dict) else []
            subjects = data.get("subjects", {}) if isinstance(data, dict) else {}

            return {
                "indicator": indicator,
                "certificate_count": len(certs),
                "certificates": certs[:50],
                "subjects": dict(list(subjects.items())[:20]) if isinstance(subjects, dict) else {},
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"indicator": indicator, "certificate_count": 0, "certificates": [], "subjects": {}}
            logger.warning("CIRCL PSSL error for %s: %s", indicator, e.response.status_code)
            return None
        except Exception:
            logger.exception("CIRCL passive_ssl failed for %s", indicator)
            return None

    # ------------------------------------------------------------------
    # Hashlookup
    # ------------------------------------------------------------------

    @instrument("circl", "hash_lookup")
    async def hash_lookup(self, file_hash: str) -> dict | None:
        """Lookup a file hash (MD5 or SHA-1 or SHA-256) in CIRCL hashlookup."""
        if not await self._check_rate_limit():
            return None

        # Determine hash type
        hash_len = len(file_hash)
        if hash_len == 32:
            endpoint = "md5"
        elif hash_len == 40:
            endpoint = "sha1"
        elif hash_len == 64:
            endpoint = "sha256"
        else:
            logger.warning("CIRCL hashlookup: unsupported hash length %d", hash_len)
            return None

        try:
            resp = await self._cb.call(
                self._client.get,
                f"{HASHLOOKUP_URL}/{endpoint}/{file_hash}",
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            return {
                "hash": file_hash,
                "hash_type": endpoint,
                "known": True,
                "file_name": data.get("FileName", ""),
                "file_size": data.get("FileSize"),
                "product_name": data.get("ProductName", ""),
                "vendor": data.get("CompanyName", ""),
                "known_source": data.get("KnownMalicious") or data.get("source", ""),
                "parents": data.get("parents", [])[:10],
                "children": data.get("children", [])[:10],
            }
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"hash": file_hash, "hash_type": endpoint, "known": False}
            logger.warning("CIRCL hashlookup error for %s: %s", file_hash, e.response.status_code)
            return None
        except Exception:
            logger.exception("CIRCL hashlookup failed for %s", file_hash)
            return None
