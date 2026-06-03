"""Provider URLhaus (abuse.ch) — 100% free, no API key required."""

from __future__ import annotations

import logging

import httpx

from apps.api.threat_intel.base import TIResult
from apps.api.threat_intel.observability import (
    get_circuit_breaker,
    instrument,
)

logger = logging.getLogger(__name__)

BASE_URL = "https://urlhaus-api.abuse.ch/v1"
RATE_LIMIT = 60  # req/min conservative self-limit
REDIS_COUNTER_KEY = "siem:ti:urlhaus:minute_count"
REDIS_COUNTER_TTL = 60


class URLhausProvider:
    name = "urlhaus"

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(timeout=12.0)
        self._cb = get_circuit_breaker(self.name)

    # ------------------------------------------------------------------
    # Rate limiting (self-imposed)
    # ------------------------------------------------------------------

    async def _check_rate_limit(self) -> bool:
        try:
            from apps.api.cache import get_redis_client

            r = get_redis_client()
            if r is None:
                return True
            count = r.get(REDIS_COUNTER_KEY)
            if count and int(count) >= RATE_LIMIT:
                logger.warning("URLhaus self-imposed rate limit reached (%d/min)", RATE_LIMIT)
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
            logger.debug("URLhaus rate-limit counter update failed: %s", exc)

    # ------------------------------------------------------------------
    # Public API — IP check via host lookup
    # ------------------------------------------------------------------

    @instrument("urlhaus", "check_ip")
    async def check_ip(self, ip: str) -> TIResult | None:
        """Lookup an IP/host via URLhaus."""
        result = await self.host_lookup(ip)
        if result is None:
            return None

        url_count = result.get("url_count", 0)
        urls = result.get("urls", [])

        # Score: based on number of malware URLs hosted
        score = min(url_count * 15, 100)
        tags_set: set[str] = set()
        for u in urls[:20]:
            for tag in u.get("tags") or []:
                if tag:
                    tags_set.add(tag)

        return TIResult(
            indicator=ip,
            source=self.name,
            risk_score=score,
            is_malicious=url_count >= 1,
            categories=["malware_hosting"] if url_count > 0 else [],
            tags=list(tags_set)[:15] or ["urlhaus"],
            total_reports=url_count,
            raw={"url_count": url_count, "first_seen": result.get("firstseen")},
        )

    # ------------------------------------------------------------------
    # URL lookup
    # ------------------------------------------------------------------

    @instrument("urlhaus", "url_lookup")
    async def url_lookup(self, url: str) -> dict | None:
        """Lookup a specific URL in URLhaus."""
        if not await self._check_rate_limit():
            return None
        try:
            resp = await self._cb.call(
                self._client.post,
                f"{BASE_URL}/url/",
                data={"url": url},
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            status = data.get("query_status", "")
            if status == "no_results":
                return {"url": url, "found": False, "threat": None, "tags": []}

            return {
                "url": url,
                "found": True,
                "id": data.get("id"),
                "status": data.get("url_status"),
                "threat": data.get("threat"),
                "date_added": data.get("date_added"),
                "last_online": data.get("last_online"),
                "tags": data.get("tags") or [],
                "payloads": [
                    {
                        "filename": p.get("filename"),
                        "file_type": p.get("file_type"),
                        "sha256": p.get("sha256_hash"),
                        "signature": p.get("signature"),
                        "virustotal_percent": p.get("virustotal", {}).get("percent")
                        if p.get("virustotal")
                        else None,
                    }
                    for p in (data.get("payloads") or [])[:10]
                ],
            }
        except Exception:
            logger.exception("URLhaus url_lookup failed for %s", url)
            return None

    # ------------------------------------------------------------------
    # Host lookup
    # ------------------------------------------------------------------

    @instrument("urlhaus", "host_lookup")
    async def host_lookup(self, host: str) -> dict | None:
        """Lookup a host (IP or domain) in URLhaus."""
        if not await self._check_rate_limit():
            return None
        try:
            resp = await self._cb.call(
                self._client.post,
                f"{BASE_URL}/host/",
                data={"host": host},
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            status = data.get("query_status", "")
            if status == "no_results":
                return {"host": host, "url_count": 0, "urls": []}

            urls = data.get("urls", []) or []
            return {
                "host": host,
                "url_count": data.get("urls_online", len(urls)),
                "firstseen": data.get("firstseen"),
                "blacklists": data.get("blacklists", {}),
                "urls": [
                    {
                        "url": u.get("url", "")[:200],
                        "status": u.get("url_status"),
                        "date_added": u.get("date_added"),
                        "threat": u.get("threat"),
                        "tags": u.get("tags") or [],
                    }
                    for u in urls[:25]
                ],
            }
        except Exception:
            logger.exception("URLhaus host_lookup failed for %s", host)
            return None

    # ------------------------------------------------------------------
    # Payload / hash lookup
    # ------------------------------------------------------------------

    @instrument("urlhaus", "payload_lookup")
    async def payload_lookup(
        self, sha256_hash: str | None = None, md5_hash: str | None = None
    ) -> dict | None:
        """Lookup a malware payload by hash."""
        if not await self._check_rate_limit():
            return None
        try:
            body: dict = {}
            if sha256_hash:
                body["sha256_hash"] = sha256_hash
            elif md5_hash:
                body["md5_hash"] = md5_hash
            else:
                return None

            resp = await self._cb.call(
                self._client.post,
                f"{BASE_URL}/payload/",
                data=body,
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            status = data.get("query_status", "")
            if status == "no_results":
                return {"hash": sha256_hash or md5_hash, "found": False}

            return {
                "hash": sha256_hash or md5_hash,
                "found": True,
                "md5": data.get("md5_hash"),
                "sha256": data.get("sha256_hash"),
                "file_type": data.get("file_type"),
                "file_size": data.get("file_size"),
                "signature": data.get("signature"),
                "firstseen": data.get("firstseen"),
                "lastseen": data.get("lastseen"),
                "url_count": data.get("url_count", 0),
                "virustotal_percent": data.get("virustotal", {}).get("percent")
                if data.get("virustotal")
                else None,
                "urls": [
                    {
                        "url": u.get("url", "")[:200],
                        "status": u.get("url_status"),
                        "filename": u.get("filename"),
                    }
                    for u in (data.get("urls") or [])[:20]
                ],
            }
        except Exception:
            logger.exception("URLhaus payload_lookup failed")
            return None

    # ------------------------------------------------------------------
    # Tag search
    # ------------------------------------------------------------------

    @instrument("urlhaus", "tag_lookup")
    async def tag_lookup(self, tag: str) -> dict | None:
        """Search URLhaus by tag (e.g. 'emotet', 'qakbot')."""
        if not await self._check_rate_limit():
            return None
        try:
            resp = await self._cb.call(
                self._client.post,
                f"{BASE_URL}/tag/",
                data={"tag": tag},
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            status = data.get("query_status", "")
            if status == "no_results":
                return {"tag": tag, "url_count": 0, "urls": []}

            urls = data.get("urls", []) or []
            return {
                "tag": tag,
                "url_count": len(urls),
                "firstseen": data.get("firstseen"),
                "urls": [
                    {
                        "url": u.get("url", "")[:200],
                        "status": u.get("url_status"),
                        "date_added": u.get("date_added"),
                        "host": u.get("host"),
                        "threat": u.get("threat"),
                    }
                    for u in urls[:25]
                ],
            }
        except Exception:
            logger.exception("URLhaus tag_lookup failed for tag: %s", tag)
            return None
