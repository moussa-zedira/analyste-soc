"""Provider Shodan — plan free 100 req/mois (scan credits separes)."""

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

BASE_URL = "https://api.shodan.io"
MONTHLY_LIMIT = 100
REDIS_COUNTER_KEY = "siem:ti:shodan:monthly_count"
REDIS_COUNTER_TTL = 2_592_000  # 30 jours


class ShodanProvider:
    name = "shodan"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
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
            if count and int(count) >= MONTHLY_LIMIT:
                logger.warning("Shodan monthly limit reached (%d)", MONTHLY_LIMIT)
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

    def _params(self, **extra: str) -> dict:
        return {"key": self._api_key, **extra}

    # ------------------------------------------------------------------
    # Public API — IP info
    # ------------------------------------------------------------------

    @instrument("shodan", "check_ip")
    async def check_ip(self, ip: str) -> TIResult | None:
        """Retrieve host information for an IP (ports, vulns, location)."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._cb.call(
                self._client.get,
                f"{BASE_URL}/shodan/host/{ip}",
                params=self._params(),
            )
            resp.raise_for_status()
            await self._increment_counter()

            data = resp.json()
            vulns = data.get("vulns", [])
            ports = data.get("ports", [])
            os_name = data.get("os") or "unknown"
            org = data.get("org", "")

            # Risk heuristic: vulns count + open port exposure
            vuln_score = min(len(vulns) * 15, 70)
            port_score = min(len(ports) * 2, 30)
            score = min(vuln_score + port_score, 100)

            tags = [f"port:{p}" for p in ports[:10]]
            tags += [v for v in vulns[:5]]

            return TIResult(
                indicator=ip,
                source=self.name,
                risk_score=score,
                is_malicious=len(vulns) >= 3,
                categories=[os_name, org][:5],
                tags=tags[:15] or ["shodan"],
                total_reports=len(vulns),
                raw={
                    "ports": ports,
                    "vulns": vulns[:20],
                    "os": os_name,
                    "org": org,
                    "country": data.get("country_code"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "hostnames": data.get("hostnames", []),
                },
            )
        except CircuitOpenError:
            logger.warning("Shodan circuit open, skipping %s", ip)
            return None
        except httpx.HTTPStatusError as e:
            logger.warning("Shodan HTTP error for %s: %s", ip, e.response.status_code)
            return None
        except Exception:
            logger.exception("Shodan check_ip failed for %s", ip)
            return None

    # ------------------------------------------------------------------
    # Search hosts
    # ------------------------------------------------------------------

    @instrument("shodan", "search_hosts")
    async def search_hosts(self, query: str, page: int = 1) -> dict | None:
        """Search Shodan with a query string (e.g. 'apache country:FR')."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._cb.call(
                self._client.get,
                f"{BASE_URL}/shodan/host/search",
                params=self._params(query=query, page=str(page)),
            )
            resp.raise_for_status()
            await self._increment_counter()
            data = resp.json()
            return {
                "total": data.get("total", 0),
                "matches": [
                    {
                        "ip": m.get("ip_str"),
                        "port": m.get("port"),
                        "org": m.get("org"),
                        "product": m.get("product"),
                        "os": m.get("os"),
                        "country": m.get("location", {}).get("country_name"),
                    }
                    for m in data.get("matches", [])[:25]
                ],
            }
        except Exception:
            logger.exception("Shodan search failed for query: %s", query)
            return None

    # ------------------------------------------------------------------
    # Exploit search
    # ------------------------------------------------------------------

    @instrument("shodan", "search_exploits")
    async def search_exploits(self, query: str) -> dict | None:
        """Search Shodan exploits database."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._cb.call(
                self._client.get,
                f"https://exploits.shodan.io/api/search",
                params=self._params(query=query),
            )
            resp.raise_for_status()
            await self._increment_counter()
            data = resp.json()
            return {
                "total": data.get("total", 0),
                "matches": [
                    {
                        "description": m.get("description", "")[:200],
                        "source": m.get("source"),
                        "cve": m.get("cve", []),
                        "type": m.get("type"),
                    }
                    for m in data.get("matches", [])[:20]
                ],
            }
        except Exception:
            logger.exception("Shodan exploit search failed for: %s", query)
            return None

    # ------------------------------------------------------------------
    # DNS lookup
    # ------------------------------------------------------------------

    @instrument("shodan", "dns_resolve")
    async def dns_resolve(self, hostnames: list[str]) -> dict | None:
        """Resolve hostnames to IPs via Shodan DNS."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._cb.call(
                self._client.get,
                f"{BASE_URL}/dns/resolve",
                params=self._params(hostnames=",".join(hostnames[:10])),
            )
            resp.raise_for_status()
            await self._increment_counter()
            return resp.json()
        except Exception:
            logger.exception("Shodan DNS resolve failed")
            return None

    # ------------------------------------------------------------------
    # Honeypot score
    # ------------------------------------------------------------------

    @instrument("shodan", "honeypot_score")
    async def honeypot_score(self, ip: str) -> float | None:
        """Return honeypot probability (0.0 = not, 1.0 = honeypot)."""
        if not self._api_key or not await self._check_rate_limit():
            return None
        try:
            resp = await self._cb.call(
                self._client.get,
                f"{BASE_URL}/labs/honeyscore/{ip}",
                params=self._params(),
            )
            resp.raise_for_status()
            await self._increment_counter()
            return float(resp.text)
        except Exception:
            logger.exception("Shodan honeypot score failed for %s", ip)
            return None
