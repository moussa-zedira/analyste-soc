"""Jira Cloud REST v3 connector."""

from __future__ import annotations

import base64
from typing import Any

import httpx

from apps.api.integrations.outbound.base import HTTP_TIMEOUT_SECONDS, OutboundConnector

_PRIORITY_MAP = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}


def _adf_paragraph(text: str) -> dict[str, Any]:
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": text or ""}],
            }
        ],
    }


class JiraConnector(OutboundConnector):
    """Jira Cloud via REST API v3.

    Required config:
      - api_url: e.g. https://yourorg.atlassian.net
      - email: user email for basic auth
      - token: API token
      - project_key: e.g. SEC
    Optional:
      - issue_type (default "Task")
    """

    name = "jira"

    def is_configured(self) -> bool:
        required = ("api_url", "email", "token", "project_key")
        return all(self.config.get(k) for k in required)

    def _auth_header(self) -> str:
        raw = f"{self.config['email']}:{self.config['token']}".encode()
        return "Basic " + base64.b64encode(raw).decode()

    def _base(self) -> str:
        return str(self.config["api_url"]).rstrip("/")

    async def create_ticket(self, incident: dict[str, Any]) -> dict[str, Any]:
        severity = (incident.get("severity") or "low").lower()
        title = self._safe_str(incident.get("title"), "SOC Incident")
        description = self._safe_str(incident.get("description"), "")
        labels = ["soc-incident", f"sev:{severity}"]
        rule_id = incident.get("rule_id")
        if rule_id:
            labels.append(f"rule:{rule_id}")

        fields: dict[str, Any] = {
            "project": {"key": self.config["project_key"]},
            "summary": title[:250],
            "description": _adf_paragraph(description),
            "issuetype": {"name": self.config.get("issue_type") or "Task"},
            "labels": labels,
        }
        priority_name = _PRIORITY_MAP.get(severity)
        if priority_name and self.config.get("set_priority", True):
            fields["priority"] = {"name": priority_name}

        url = f"{self._base()}/rest/api/3/issue"
        headers = {
            "Authorization": self._auth_header(),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            r = await client.post(url, json={"fields": fields}, headers=headers)
            if r.status_code >= 400:
                raise RuntimeError(f"jira_create_failed status={r.status_code} body={r.text[:300]}")
            data = r.json()
        key = data.get("key")
        if not key:
            raise RuntimeError(f"jira_create_no_key response={data}")
        browse_url = f"{self._base()}/browse/{key}"
        return {"external_id": key, "url": browse_url, "status": "Open"}

    async def sync_status(self, ticket: dict[str, Any]) -> str:
        key = ticket.get("external_ticket_id")
        if not key:
            raise RuntimeError("jira_sync_missing_key")
        url = f"{self._base()}/rest/api/3/issue/{key}?fields=status"
        headers = {
            "Authorization": self._auth_header(),
            "Accept": "application/json",
        }
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            r = await client.get(url, headers=headers)
            if r.status_code >= 400:
                raise RuntimeError(f"jira_sync_failed status={r.status_code}")
            data = r.json()
        return ((data.get("fields") or {}).get("status") or {}).get("name") or "unknown"
