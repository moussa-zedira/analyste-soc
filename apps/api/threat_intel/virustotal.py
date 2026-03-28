"""Provider VirusTotal API v3 — free tier 4 req/min, 500 req/jour."""

from __future__ import annotations

import logging

import httpx

from apps.api.threat_intel.base import TIResult

logger = logging.getLogger(__name__)

BASE_URL = "https://www.virustotal.com/api/v3"
MINUTE_LIMIT = 4
DAILY_LIMIT = 500
REDIS_MINUTE_KEY = "siem:ti:virustotal:minute_count"
REDIS_DAILY_KEY = "siem:ti:virustotal:daily_count"
REDIS_MINUTE_TTL = 60
REDIS_DAILY_TTL = 86400


class VirusTotalProvider:
    name = "virustotal"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=15.0)

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    async def _check_rate_limit(self) -> bool:
        try:
            from apps.api.cache import get_redis_client
            r = get_redis_client()
            if r is None:
                return True
            minute = r.get(REDIS_MINUTE_KEY)
            if minute and int(minute) >= MINUTE_LIMIT:
                logger.warning("VirusTotal minute limit reached (%d)", MINUTE_LIMIT)
                return False
            daily = r.get(REDIS_DAILY_KEY)
            if daily and int(daily) >= DAILY_LIMIT:
                logger.warning("VirusTotal daily limit reached (%d)", DAILY_LIMIT)
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
            pipe.incr(REDIS_MINUTE_KEY)
            pipe.expire(REDIS_MINUTE_KEY, REDIS_MINUTE_TTL)
            pipe.incr(REDIS_DAILY_KEY)
            pipe.expire(REDIS_DAILY_KEY, REDIS_DAILY_TTL)
            pipe.execute()
        except Exception:
            pass

    def _headers(self) -> dict:
        return {"x-apikey": self._api_key, "Accept": "application/json"}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_analysis_stats(self, stats: dict) -> tuple[int, bool]:
        """Return (risk_score 0-100, is_malicious) from last_analysis_stats."""
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected or 1
        score = min(int((malicious + suspicious * 0.5) / total * 100), 100)
        return score, malicious >= 3

    # ------------------------------------------------------------------
    # Public API — IP
    # ------------------------------------------------------------------

    async def check_ip(self, ip: str) -> TIResult | None:
        """Lookup IP reputation on VirusTotal."""
        if not self._api_key:
            return None
        if not await self._check_rate_limit():
            return None
        try:
            resp = await self._client.get(
                f"{BASE_URL}/ip_addresses/{ip}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            await self._increment_counter()

            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            score, malicious = self._parse_analysis_stats(stats)
            reputation = attrs.get("reputation", 0)

            tags = attrs.get("tags", [])[:10]
            categories = list(set(
                v for v in (attrs.get("last_analysis_results") or {}).values()
                if isinstance(v, dict) and v.get("category") == "malicious"
            ))[:5]

            return TIResult(
                indicator=ip,
                source=self.name,
                risk_score=score,
                is_malicious=malicious,
                categories=[f"reputation:{reputation}"],
                tags=tags or ["virustotal"],
                total_reports=stats.get("malicious", 0),
                raw={"stats": stats, "reputation": reputation, "country": attrs.get("country")},
            )
        except httpx.HTTPStatusError as e:
            logger.warning("VirusTotal HTTP error for IP %s: %s", ip, e.response.status_code)
            return None
        except Exception:
            logger.exception("VirusTotal check_ip failed for %s", ip)
            return None

    # ------------------------------------------------------------------
    # Public API — Domain
    # ------------------------------------------------------------------

    async def check_domain(self, domain: str) -> TIResult | None:
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._client.get(
                f"{BASE_URL}/domains/{domain}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            await self._increment_counter()

            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            score, malicious = self._parse_analysis_stats(stats)

            return TIResult(
                indicator=domain,
                source=self.name,
                risk_score=score,
                is_malicious=malicious,
                categories=list(set((attrs.get("categories") or {}).values()))[:10],
                tags=attrs.get("tags", [])[:10] or ["virustotal"],
                total_reports=stats.get("malicious", 0),
                raw={"stats": stats, "registrar": attrs.get("registrar"), "creation_date": attrs.get("creation_date")},
            )
        except httpx.HTTPStatusError as e:
            logger.warning("VirusTotal HTTP error for domain %s: %s", domain, e.response.status_code)
            return None
        except Exception:
            logger.exception("VirusTotal check_domain failed for %s", domain)
            return None

    # ------------------------------------------------------------------
    # Public API — File hash
    # ------------------------------------------------------------------

    async def check_hash(self, file_hash: str) -> TIResult | None:
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._client.get(
                f"{BASE_URL}/files/{file_hash}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            await self._increment_counter()

            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            score, malicious = self._parse_analysis_stats(stats)
            community = attrs.get("reputation", 0)

            return TIResult(
                indicator=file_hash,
                source=self.name,
                risk_score=score,
                is_malicious=malicious,
                categories=[attrs.get("type_description", "unknown")],
                tags=attrs.get("tags", [])[:10] or ["virustotal"],
                total_reports=stats.get("malicious", 0),
                raw={
                    "stats": stats,
                    "community_score": community,
                    "sha256": attrs.get("sha256"),
                    "meaningful_name": attrs.get("meaningful_name"),
                    "size": attrs.get("size"),
                },
            )
        except httpx.HTTPStatusError as e:
            logger.warning("VirusTotal HTTP error for hash %s: %s", file_hash, e.response.status_code)
            return None
        except Exception:
            logger.exception("VirusTotal check_hash failed for %s", file_hash)
            return None

    # ------------------------------------------------------------------
    # Public API — URL scan
    # ------------------------------------------------------------------

    async def check_url(self, url: str) -> TIResult | None:
        """Submit a URL for scanning and retrieve results."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
            resp = await self._client.get(
                f"{BASE_URL}/urls/{url_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
            await self._increment_counter()

            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            score, malicious = self._parse_analysis_stats(stats)

            return TIResult(
                indicator=url,
                source=self.name,
                risk_score=score,
                is_malicious=malicious,
                categories=list(set((attrs.get("categories") or {}).values()))[:10],
                tags=attrs.get("tags", [])[:10] or ["virustotal"],
                total_reports=stats.get("malicious", 0),
                raw={"stats": stats, "url": attrs.get("url"), "last_http_response_code": attrs.get("last_http_response_code")},
            )
        except httpx.HTTPStatusError as e:
            logger.warning("VirusTotal HTTP error for URL: %s", e.response.status_code)
            return None
        except Exception:
            logger.exception("VirusTotal check_url failed")
            return None
