"""Linear GraphQL connector."""

from __future__ import annotations

from typing import Any

import httpx

from apps.api.integrations.outbound.base import HTTP_TIMEOUT_SECONDS, OutboundConnector


_PRIORITY_MAP = {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4,
}

_LINEAR_API = "https://api.linear.app/graphql"


class LinearConnector(OutboundConnector):
    """Linear GraphQL API connector.

    Required config:
      - api_key: Linear personal API key
      - team_id: target team UUID
    Optional:
      - api_url (default https://api.linear.app/graphql)
    """

    name = "linear"

    def is_configured(self) -> bool:
        return bool(self.config.get("api_key")) and bool(self.config.get("team_id"))

    def _api_url(self) -> str:
        return self.config.get("api_url") or _LINEAR_API

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self.config["api_key"],
            "Content-Type": "application/json",
        }

    async def _gql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            r = await client.post(
                self._api_url(),
                json={"query": query, "variables": variables},
                headers=self._headers(),
            )
            if r.status_code >= 400:
                raise RuntimeError(f"linear_http_failed status={r.status_code} body={r.text[:300]}")
            data = r.json()
        if data.get("errors"):
            raise RuntimeError(f"linear_gql_errors {data['errors']}")
        return data.get("data") or {}

    async def create_ticket(self, incident: dict[str, Any]) -> dict[str, Any]:
        severity = (incident.get("severity") or "low").lower()
        title = self._safe_str(incident.get("title"), "SOC Incident")
        description = self._safe_str(incident.get("description"), "")
        priority = _PRIORITY_MAP.get(severity, 4)

        mutation = """
        mutation IssueCreate($input: IssueCreateInput!) {
          issueCreate(input: $input) {
            success
            issue { id identifier url state { name } }
          }
        }
        """
        variables = {
            "input": {
                "teamId": self.config["team_id"],
                "title": title[:250],
                "description": description,
                "priority": priority,
            }
        }
        data = await self._gql(mutation, variables)
        result = (data.get("issueCreate") or {})
        if not result.get("success"):
            raise RuntimeError(f"linear_create_unsuccessful response={data}")
        issue = result.get("issue") or {}
        return {
            "external_id": issue.get("identifier") or issue.get("id"),
            "url": issue.get("url") or "",
            "status": ((issue.get("state") or {}).get("name")) or "Triage",
        }

    async def sync_status(self, ticket: dict[str, Any]) -> str:
        ext_id = ticket.get("external_ticket_id")
        if not ext_id:
            raise RuntimeError("linear_sync_missing_id")
        query = """
        query IssueByIdent($id: String!) {
          issue(id: $id) { state { name } }
        }
        """
        data = await self._gql(query, {"id": ext_id})
        issue = data.get("issue") or {}
        return ((issue.get("state") or {}).get("name")) or "unknown"
