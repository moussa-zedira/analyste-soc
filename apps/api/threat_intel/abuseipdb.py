"""Provider AbuseIPDB — free tier 1000 checks/jour."""

from __future__ import annotations

import logging
from datetime import timedelta

import httpx

from apps.api.threat_intel.base import TIResult
from apps.api.threat_intel.observability import (
    CircuitOpenError,
    get_circuit_breaker,
    instrument,
)

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"
DAILY_LIMIT = 1000
REDIS_COUNTER_KEY = "siem:ti:abuseipdb:daily_count"
REDIS_COUNTER_TTL = 86400  # 24h


class AbuseIPDBProvider:
    name = "abuseipdb"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=10.0)
        self._cb = get_circuit_breaker(self.name)

    async def _check_rate_limit(self) -> bool:
        """Verifie si on a encore du quota."""
        try:
            from apps.api.cache import get_redis_client
            r = get_redis_client()
            if r is None:
                return True
            count = r.get(REDIS_COUNTER_KEY)
            if count and int(count) >= DAILY_LIMIT:
                logger.warning("AbuseIPDB daily limit reached (%d)", DAILY_LIMIT)
                return False
            return True
        except Exception:
            return True

    async def _increment_counter(self) -> None:
        """Incremente le compteur journalier."""
        try:
            from apps.api.cache import get_redis_client
            r = get_redis_client()
            if r is None:
                return
            pipe = r.pipeline()
            pipe.incr(REDIS_COUNTER_KEY)
            pipe.expire(REDIS_COUNTER_KEY, REDIS_COUNTER_TTL)
            pipe.execute()
        except Exception:
            pass

    @instrument("abuseipdb", "check_ip")
    async def check_ip(self, ip: str) -> TIResult | None:
        """Interroge AbuseIPDB pour une IP."""
        if not self._api_key:
            return None

        if not await self._check_rate_limit():
            return None

        try:
            resp = await self._cb.call(
                self._client.get,
                API_URL,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={
                    "Key": self._api_key,
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            categories = [str(c) for c in data.get("reports", [])[0:5]] if data.get("reports") else []

            return TIResult(
                indicator=ip,
                source=self.name,
                risk_score=score,
                is_malicious=score >= 50,
                categories=categories,
                tags=["abuseipdb"],
                total_reports=total_reports,
                raw=data,
            )
        except CircuitOpenError:
            logger.warning("AbuseIPDB circuit open, skipping %s", ip)
            return None
        except httpx.HTTPStatusError as e:
            logger.warning("AbuseIPDB HTTP error for %s: %s", ip, e.response.status_code)
            return None
        except Exception:
            logger.exception("AbuseIPDB check failed for %s", ip)
            return None
