"""ServiceNow Table API connector."""

from __future__ import annotations

import base64
from typing import Any

import httpx

from apps.api.integrations.outbound.base import HTTP_TIMEOUT_SECONDS, OutboundConnector


_URGENCY_MAP = {
    "critical": "1",
    "high": "2",
    "medium": "3",
    "low": "3",
}


class ServiceNowConnector(OutboundConnector):
    """ServiceNow Table API connector.

    Required config:
      - instance_url: e.g. https://dev12345.service-now.com
      - username, password (basic auth) OR oauth_token (Bearer)
    Optional:
      - table (default "incident")
      - category (default "security")
    """

    name = "servicenow"

    def is_configured(self) -> bool:
        if not self.config.get("instance_url"):
            return False
        if self.config.get("oauth_token"):
            return True
        return bool(self.config.get("username")) and bool(self.config.get("password"))

    def _auth_headers(self) -> dict[str, str]:
        if self.config.get("oauth_token"):
            return {"Authorization": f"Bearer {self.config['oauth_token']}"}
        raw = f"{self.config['username']}:{self.config['password']}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}

    def _base(self) -> str:
        return str(self.config["instance_url"]).rstrip("/")

    def _table(self) -> str:
        return self.config.get("table") or "incident"

    async def create_ticket(self, incident: dict[str, Any]) -> dict[str, Any]:
        severity = (incident.get("severity") or "low").lower()
        title = self._safe_str(incident.get("title"), "SOC Incident")
        description = self._safe_str(incident.get("description"), "")
        payload = {
            "short_description": title[:160],
            "description": description,
            "urgency": _URGENCY_MAP.get(severity, "3"),
            "impact": _URGENCY_MAP.get(severity, "3"),
            "category": self.config.get("category") or "security",
        }
        if incident.get("rule_id"):
            payload["work_notes"] = f"SOC rule: {incident['rule_id']}"

        url = f"{self._base()}/api/now/table/{self._table()}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            **self._auth_headers(),
        }
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            r = await client.post(url, json=payload, headers=headers)
            if r.status_code >= 400:
                raise RuntimeError(f"servicenow_create_failed status={r.status_code} body={r.text[:300]}")
            data = (r.json() or {}).get("result") or {}
        sys_id = data.get("sys_id")
        number = data.get("number") or sys_id
        if not sys_id:
            raise RuntimeError(f"servicenow_create_no_sys_id response={data}")
        view_url = f"{self._base()}/nav_to.do?uri={self._table()}.do?sys_id={sys_id}"
        return {
            "external_id": number,
            "url": view_url,
            "status": data.get("state") or "New",
        }

    async def sync_status(self, ticket: dict[str, Any]) -> str:
        number = ticket.get("external_ticket_id")
        if not number:
            raise RuntimeError("servicenow_sync_missing_number")
        url = f"{self._base()}/api/now/table/{self._table()}"
        headers = {
            "Accept": "application/json",
            **self._auth_headers(),
        }
        params = {"sysparm_query": f"number={number}", "sysparm_limit": "1"}
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            r = await client.get(url, headers=headers, params=params)
            if r.status_code >= 400:
                raise RuntimeError(f"servicenow_sync_failed status={r.status_code}")
            results = (r.json() or {}).get("result") or []
        if not results:
            return "unknown"
        return self._safe_str(results[0].get("state"), "unknown")
