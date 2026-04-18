"""GitHub Issues REST connector."""

from __future__ import annotations

from typing import Any

import httpx

from apps.api.integrations.outbound.base import HTTP_TIMEOUT_SECONDS, OutboundConnector


class GitHubIssuesConnector(OutboundConnector):
    """GitHub Issues via REST API.

    Required config:
      - token: PAT with repo scope (or fine-grained issues:write)
      - owner, repo
    Optional:
      - api_url (default https://api.github.com) for GHES
      - assignees: list[str]
    """

    name = "github_issues"

    def is_configured(self) -> bool:
        required = ("token", "owner", "repo")
        return all(self.config.get(k) for k in required)

    def _base(self) -> str:
        return (self.config.get("api_url") or "https://api.github.com").rstrip("/")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config['token']}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def create_ticket(self, incident: dict[str, Any]) -> dict[str, Any]:
        severity = (incident.get("severity") or "low").lower()
        title = self._safe_str(incident.get("title"), "SOC Incident")
        description = self._safe_str(incident.get("description"), "")
        labels = ["security", severity]
        if incident.get("rule_id"):
            labels.append(f"rule-{incident['rule_id']}")
        body = {"title": title[:250], "body": description, "labels": labels}
        if self.config.get("assignees"):
            body["assignees"] = self.config["assignees"]

        owner = self.config["owner"]
        repo = self.config["repo"]
        url = f"{self._base()}/repos/{owner}/{repo}/issues"
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            r = await client.post(url, json=body, headers=self._headers())
            if r.status_code >= 400:
                raise RuntimeError(f"github_create_failed status={r.status_code} body={r.text[:300]}")
            data = r.json()
        number = data.get("number")
        if number is None:
            raise RuntimeError(f"github_create_no_number response={data}")
        return {
            "external_id": str(number),
            "url": data.get("html_url") or "",
            "status": data.get("state") or "open",
        }

    async def sync_status(self, ticket: dict[str, Any]) -> str:
        number = ticket.get("external_ticket_id")
        if not number:
            raise RuntimeError("github_sync_missing_number")
        owner = self.config["owner"]
        repo = self.config["repo"]
        url = f"{self._base()}/repos/{owner}/{repo}/issues/{number}"
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            r = await client.get(url, headers=self._headers())
            if r.status_code >= 400:
                raise RuntimeError(f"github_sync_failed status={r.status_code}")
            data = r.json()
        return self._safe_str(data.get("state"), "unknown")
