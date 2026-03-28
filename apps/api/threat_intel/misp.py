"""Provider MISP — Malware Information Sharing Platform integration."""

from __future__ import annotations

import logging

import httpx

from apps.api.threat_intel.base import TIResult

logger = logging.getLogger(__name__)

REDIS_COUNTER_KEY = "siem:ti:misp:minute_count"
REDIS_COUNTER_TTL = 60
MINUTE_LIMIT = 120


class MISPProvider:
    name = "misp"

    def __init__(self, url: str, api_key: str, verify_ssl: bool = True) -> None:
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._client = httpx.AsyncClient(timeout=20.0, verify=verify_ssl)

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
            if count and int(count) >= MINUTE_LIMIT:
                logger.warning("MISP rate limit reached (%d/min)", MINUTE_LIMIT)
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
        return {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------
    # Public API — IP check
    # ------------------------------------------------------------------

    async def check_ip(self, ip: str) -> TIResult | None:
        """Search MISP for attributes matching the given IP."""
        result = await self.search_attributes(value=ip, type_attribute="ip-src")
        if result is None:
            # Try ip-dst
            result = await self.search_attributes(value=ip, type_attribute="ip-dst")
        if result is None:
            return None

        attributes = result.get("attributes", [])
        count = len(attributes)
        if count == 0:
            return TIResult(
                indicator=ip,
                source=self.name,
                risk_score=0,
                is_malicious=False,
                categories=["not_found"],
                tags=["misp"],
                total_reports=0,
                raw={"message": "No MISP attributes found"},
            )

        # Collect tags from events
        tags: list[str] = []
        event_ids: list[str] = []
        for attr in attributes[:20]:
            for tag in attr.get("Tag", []):
                tag_name = tag.get("name", "")
                if tag_name:
                    tags.append(tag_name)
            event_id = attr.get("event_id", "")
            if event_id:
                event_ids.append(str(event_id))

        tags = list(set(tags))[:15]
        # Heuristic: more events referencing this IP = higher risk
        score = min(count * 20, 100)

        return TIResult(
            indicator=ip,
            source=self.name,
            risk_score=score,
            is_malicious=count >= 2,
            categories=list(set(event_ids))[:10],
            tags=tags or ["misp"],
            total_reports=count,
            raw={"attribute_count": count, "event_ids": list(set(event_ids))[:20]},
        )

    # ------------------------------------------------------------------
    # Event search
    # ------------------------------------------------------------------

    async def search_events(
        self,
        value: str | None = None,
        eventinfo: str | None = None,
        tags: list[str] | None = None,
        limit: int = 25,
    ) -> dict | None:
        """Search MISP events."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            body: dict = {"returnFormat": "json", "limit": limit}
            if value:
                body["value"] = value
            if eventinfo:
                body["eventinfo"] = eventinfo
            if tags:
                body["tags"] = tags

            resp = await self._client.post(
                f"{self._url}/events/restSearch",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            events = data.get("response", [])
            return {
                "count": len(events),
                "events": [
                    {
                        "id": ev.get("Event", {}).get("id"),
                        "info": ev.get("Event", {}).get("info", ""),
                        "date": ev.get("Event", {}).get("date"),
                        "threat_level_id": ev.get("Event", {}).get("threat_level_id"),
                        "tag_names": [
                            t.get("name") for t in ev.get("Event", {}).get("Tag", [])
                        ][:10],
                        "attribute_count": ev.get("Event", {}).get("attribute_count"),
                        "org": ev.get("Event", {}).get("Orgc", {}).get("name", ""),
                    }
                    for ev in events[:limit]
                ],
            }
        except Exception:
            logger.exception("MISP search_events failed")
            return None

    # ------------------------------------------------------------------
    # Attribute search
    # ------------------------------------------------------------------

    async def search_attributes(
        self,
        value: str | None = None,
        type_attribute: str | None = None,
        category: str | None = None,
        limit: int = 50,
    ) -> dict | None:
        """Search MISP attributes (IP, domain, hash, etc.)."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            body: dict = {"returnFormat": "json", "limit": limit}
            if value:
                body["value"] = value
            if type_attribute:
                body["type"] = type_attribute
            if category:
                body["category"] = category

            resp = await self._client.post(
                f"{self._url}/attributes/restSearch",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            attributes = data.get("response", {}).get("Attribute", [])
            return {
                "count": len(attributes),
                "attributes": [
                    {
                        "id": a.get("id"),
                        "event_id": a.get("event_id"),
                        "type": a.get("type"),
                        "category": a.get("category"),
                        "value": a.get("value"),
                        "comment": a.get("comment", ""),
                        "timestamp": a.get("timestamp"),
                        "Tag": a.get("Tag", []),
                    }
                    for a in attributes[:limit]
                ],
            }
        except Exception:
            logger.exception("MISP search_attributes failed for value=%s", value)
            return None

    # ------------------------------------------------------------------
    # Galaxy / cluster lookup
    # ------------------------------------------------------------------

    async def search_galaxies(self, query: str) -> dict | None:
        """Search MISP galaxies and clusters."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._client.post(
                f"{self._url}/galaxies/restSearch",
                headers=self._headers(),
                json={"value": query, "returnFormat": "json"},
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            galaxies = data if isinstance(data, list) else data.get("response", [])
            return {
                "count": len(galaxies),
                "galaxies": [
                    {
                        "id": g.get("Galaxy", {}).get("id") if isinstance(g, dict) else None,
                        "name": g.get("Galaxy", {}).get("name", "") if isinstance(g, dict) else "",
                        "type": g.get("Galaxy", {}).get("type", "") if isinstance(g, dict) else "",
                        "description": g.get("Galaxy", {}).get("description", "")[:200] if isinstance(g, dict) else "",
                    }
                    for g in galaxies[:20]
                ],
            }
        except Exception:
            logger.exception("MISP search_galaxies failed for: %s", query)
            return None

    # ------------------------------------------------------------------
    # IOC export
    # ------------------------------------------------------------------

    async def export_iocs(
        self,
        event_id: str | None = None,
        tags: list[str] | None = None,
        type_attribute: str | None = None,
        limit: int = 500,
    ) -> dict | None:
        """Export IOCs from MISP (attributes as IOC list)."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            body: dict = {"returnFormat": "json", "limit": limit, "to_ids": 1}
            if event_id:
                body["eventid"] = event_id
            if tags:
                body["tags"] = tags
            if type_attribute:
                body["type"] = type_attribute

            resp = await self._client.post(
                f"{self._url}/attributes/restSearch",
                headers=self._headers(),
                json=body,
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            attributes = data.get("response", {}).get("Attribute", [])
            iocs = [
                {
                    "type": a.get("type"),
                    "value": a.get("value"),
                    "category": a.get("category"),
                    "event_id": a.get("event_id"),
                    "comment": a.get("comment", ""),
                }
                for a in attributes[:limit]
            ]
            return {"count": len(iocs), "iocs": iocs}
        except Exception:
            logger.exception("MISP export_iocs failed")
            return None
