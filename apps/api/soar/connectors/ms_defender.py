"""Microsoft Defender for Endpoint connector via Microsoft Graph API."""

from __future__ import annotations

import time
from typing import Any

import httpx

from apps.api.soar.connectors.base import Connector

GRAPH_SECURITY_BASE = "https://api.securitycenter.microsoft.com/api"
LOGIN_URL = "https://login.microsoftonline.com"


class DefenderConnector(Connector):
    """Microsoft Defender for Endpoint (MDE) via Graph Security API.

    Env : AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
    """

    name = "ms_defender"
    required_env = ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"]

    def __init__(self) -> None:
        super().__init__()
        self._token: str | None = None
        self._token_exp: float = 0.0

    async def _get_token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        tenant = self.env("AZURE_TENANT_ID")
        url = f"{LOGIN_URL}/{tenant}/oauth2/v2.0/token"
        data = {
            "client_id": self.env("AZURE_CLIENT_ID"),
            "client_secret": self.env("AZURE_CLIENT_SECRET"),
            "scope": "https://api.securitycenter.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(url, data=data)
            r.raise_for_status()
            tok = r.json()
        self._token = tok["access_token"]
        self._token_exp = time.time() + int(tok.get("expires_in", 3600))
        return self._token

    async def available(self) -> bool:
        if not self.configured:
            return False
        try:
            await self._get_token()
            return True
        except Exception:
            return False

    async def _post(self, path: str, payload: dict) -> dict[str, Any]:
        token = await self._get_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.post(f"{GRAPH_SECURITY_BASE}{path}", json=payload, headers=headers)
            if r.status_code >= 400:
                return {"applied": False, "status_code": r.status_code, "error": r.text[:500]}
            return {
                "applied": True,
                "status_code": r.status_code,
                "response": r.json() if r.content else {},
            }

    async def isolate_device(self, device_id: str, isolation_type: str = "Full") -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "defender_not_configured"}
        payload = {
            "Comment": "SOAR automated isolation",
            "IsolationType": isolation_type,  # Full | Selective
        }
        res = await self._post(f"/machines/{device_id}/isolate", payload)
        res["device_id"] = device_id
        res["action"] = "isolate"
        return res

    async def unisolate_device(self, device_id: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "defender_not_configured"}
        res = await self._post(
            f"/machines/{device_id}/unisolate", {"Comment": "SOAR lift containment"}
        )
        res["device_id"] = device_id
        return res

    async def run_antivirus_scan(self, device_id: str, scan_type: str = "Full") -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "defender_not_configured"}
        payload = {"Comment": "SOAR AV scan", "ScanType": scan_type}
        res = await self._post(f"/machines/{device_id}/runAntiVirusScan", payload)
        res["device_id"] = device_id
        return res

    async def stop_and_quarantine_file(self, device_id: str, sha1: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "defender_not_configured"}
        payload = {"Comment": "SOAR quarantine", "Sha1": sha1}
        res = await self._post(f"/machines/{device_id}/StopAndQuarantineFile", payload)
        res["device_id"] = device_id
        res["sha1"] = sha1
        return res

    async def run_script(
        self, device_id: str, script_name: str, script_args: str = ""
    ) -> dict[str, Any]:
        """Execute un Live Response script (kill process, etc.)."""
        if not self.configured:
            return {"applied": False, "reason": "defender_not_configured"}
        payload = {
            "Commands": [
                {
                    "type": "RunScript",
                    "params": [
                        {"key": "ScriptName", "value": script_name},
                        {"key": "Args", "value": script_args},
                    ],
                }
            ],
            "Comment": "SOAR live response",
        }
        res = await self._post(f"/machines/{device_id}/runliveresponse", payload)
        res["device_id"] = device_id
        res["script"] = script_name
        return res
