"""Provider AlienVault OTX — free tier 10000 req/heure."""

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

API_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4"
HOURLY_LIMIT = 10000
REDIS_COUNTER_KEY = "siem:ti:otx:hourly_count"
REDIS_COUNTER_TTL = 3600  # 1h


class OTXProvider:
    name = "otx"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=10.0)
        self._cb = get_circuit_breaker(self.name)

    async def _check_rate_limit(self) -> bool:
        try:
            from apps.api.cache import get_redis_client
            r = get_redis_client()
            if r is None:
                return True
            count = r.get(REDIS_COUNTER_KEY)
            if count and int(count) >= HOURLY_LIMIT:
                logger.warning("OTX hourly limit reached (%d)", HOURLY_LIMIT)
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
        except Exception:
            pass

    @instrument("otx", "check_ip")
    async def check_ip(self, ip: str) -> TIResult | None:
        """Interroge AlienVault OTX pour une IP."""
        if not self._api_key:
            return None

        if not await self._check_rate_limit():
            return None

        try:
            resp = await self._cb.call(
                self._client.get,
                f"{API_URL}/{ip}/general",
                headers={"X-OTX-API-KEY": self._api_key},
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            pulse_count = data.get("pulse_info", {}).get("count", 0)
            reputation = data.get("reputation", 0) or 0

            # OTX risk = pulse_count * 10, capped at 100
            risk_score = min(pulse_count * 10 + abs(reputation), 100)

            tags: list[str] = []
            for pulse in data.get("pulse_info", {}).get("pulses", [])[:5]:
                tags.extend(pulse.get("tags", [])[:3])
            tags = list(set(tags))[:10]

            return TIResult(
                indicator=ip,
                source=self.name,
                risk_score=risk_score,
                is_malicious=risk_score >= 30,
                categories=[],
                tags=tags,
                total_reports=pulse_count,
                raw={"pulse_count": pulse_count, "reputation": reputation},
            )
        except CircuitOpenError:
            logger.warning("OTX circuit open, skipping %s", ip)
            return None
        except httpx.HTTPStatusError as e:
            logger.warning("OTX HTTP error for %s: %s", ip, e.response.status_code)
            return None
        except Exception:
            logger.exception("OTX check failed for %s", ip)
            return None
