"""Provider GreyNoise — Community API free tier (daily limit)."""

from __future__ import annotations

import logging

import httpx

from apps.api.threat_intel.base import TIResult

logger = logging.getLogger(__name__)

BASE_URL = "https://api.greynoise.io/v3"
COMMUNITY_URL = "https://api.greynoise.io/v3/community"
DAILY_LIMIT = 500
REDIS_COUNTER_KEY = "siem:ti:greynoise:daily_count"
REDIS_COUNTER_TTL = 86400


class GreyNoiseProvider:
    name = "greynoise"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=12.0)

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
            if count and int(count) >= DAILY_LIMIT:
                logger.warning("GreyNoise daily limit reached (%d)", DAILY_LIMIT)
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

    def _headers(self) -> dict:
        return {"key": self._api_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    # Public API — IP context (full)
    # ------------------------------------------------------------------

    async def check_ip(self, ip: str) -> TIResult | None:
        """Full IP context — classification, actor, tags."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._client.get(
                f"{BASE_URL}/community/{ip}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            classification = data.get("classification", "unknown")
            noise = data.get("noise", False)
            riot = data.get("riot", False)
            name = data.get("name", "unknown")

            # Score mapping
            score_map = {"malicious": 85, "unknown": 40, "benign": 5}
            score = score_map.get(classification, 30)
            if riot:
                score = max(score - 30, 0)

            tags_list = [classification]
            if noise:
                tags_list.append("noise")
            if riot:
                tags_list.append("riot")
            if name and name != "unknown":
                tags_list.append(f"actor:{name}")

            return TIResult(
                indicator=ip,
                source=self.name,
                risk_score=score,
                is_malicious=classification == "malicious",
                categories=[classification],
                tags=tags_list,
                total_reports=1 if noise else 0,
                raw={
                    "classification": classification,
                    "noise": noise,
                    "riot": riot,
                    "name": name,
                    "link": data.get("link"),
                    "last_seen": data.get("last_seen"),
                    "message": data.get("message"),
                },
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                # IP not found in GreyNoise — not malicious
                return TIResult(
                    indicator=ip,
                    source=self.name,
                    risk_score=0,
                    is_malicious=False,
                    categories=["not_found"],
                    tags=["greynoise"],
                    total_reports=0,
                    raw={"message": "IP not observed by GreyNoise"},
                )
            logger.warning("GreyNoise HTTP error for %s: %s", ip, e.response.status_code)
            return None
        except Exception:
            logger.exception("GreyNoise check_ip failed for %s", ip)
            return None

    # ------------------------------------------------------------------
    # RIOT check — known benign services
    # ------------------------------------------------------------------

    async def riot_check(self, ip: str) -> dict | None:
        """Check if IP belongs to a known benign service (RIOT dataset)."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._client.get(
                f"{BASE_URL}/riot/{ip}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            await self._increment_counter()
            data = resp.json()
            return {
                "ip": ip,
                "riot": data.get("riot", False),
                "name": data.get("name", ""),
                "category": data.get("category", ""),
                "description": data.get("description", ""),
                "trust_level": data.get("trust_level", ""),
                "last_updated": data.get("last_updated"),
            }
        except Exception:
            logger.exception("GreyNoise RIOT check failed for %s", ip)
            return None

    # ------------------------------------------------------------------
    # Noise quick check
    # ------------------------------------------------------------------

    async def noise_check(self, ip: str) -> dict | None:
        """Quick check — is this IP generating internet noise?"""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._client.get(
                f"{BASE_URL}/noise/quick/{ip}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            await self._increment_counter()
            data = resp.json()
            return {
                "ip": ip,
                "noise": data.get("noise", False),
                "code": data.get("code", ""),
            }
        except Exception:
            logger.exception("GreyNoise noise check failed for %s", ip)
            return None

    # ------------------------------------------------------------------
    # IP context (enterprise — full details)
    # ------------------------------------------------------------------

    async def ip_context(self, ip: str) -> dict | None:
        """Full enterprise context with tags, CVEs, metadata."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._client.get(
                f"{BASE_URL}/noise/context/{ip}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            await self._increment_counter()
            data = resp.json()
            return {
                "ip": ip,
                "seen": data.get("seen", False),
                "classification": data.get("classification", "unknown"),
                "actor": data.get("actor", "unknown"),
                "tags": data.get("tags", []),
                "cve": data.get("cve", []),
                "os": data.get("metadata", {}).get("os", ""),
                "city": data.get("metadata", {}).get("city", ""),
                "country": data.get("metadata", {}).get("country", ""),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
                "raw_data": {
                    "ports": data.get("raw_data", {}).get("scan", []),
                    "web": data.get("raw_data", {}).get("web", {}),
                },
            }
        except Exception:
            logger.exception("GreyNoise ip_context failed for %s", ip)
            return None
