"""CrowdStrike Falcon connector via OAuth2 API."""

from __future__ import annotations

import time
from typing import Any

import httpx

from apps.api.soar.connectors.base import Connector


class FalconConnector(Connector):
    """CrowdStrike Falcon via OAuth2 client credentials.

    Env : FALCON_CLIENT_ID, FALCON_CLIENT_SECRET, FALCON_BASE_URL
    (ex: https://api.crowdstrike.com ou https://api.eu-1.crowdstrike.com)
    """

    name = "crowdstrike"
    required_env = ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET", "FALCON_BASE_URL"]

    def __init__(self) -> None:
        super().__init__()
        self._token: str | None = None
        self._token_exp: float = 0.0

    def _base(self) -> str:
        return self.env("FALCON_BASE_URL", "https://api.crowdstrike.com").rstrip("/")

    async def _get_token(self) -> str:
        if self._token and time.time() < self._token_exp - 60:
            return self._token
        url = f"{self._base()}/oauth2/token"
        data = {
            "client_id": self.env("FALCON_CLIENT_ID"),
            "client_secret": self.env("FALCON_CLIENT_SECRET"),
        }
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(url, data=data)
            r.raise_for_status()
            tok = r.json()
        self._token = tok["access_token"]
        self._token_exp = time.time() + int(tok.get("expires_in", 1800))
        return self._token

    async def available(self) -> bool:
        if not self.configured:
            return False
        try:
            await self._get_token()
            return True
        except Exception:
            return False

    async def _api(self, method: str, path: str, **kw) -> dict[str, Any]:
        token = await self._get_token()
        headers = kw.pop("headers", {}) or {}
        headers["Authorization"] = f"Bearer {token}"
        async with httpx.AsyncClient(timeout=60) as c:
            r = await c.request(method, f"{self._base()}{path}", headers=headers, **kw)
            data: Any = {}
            try:
                data = r.json()
            except Exception:
                data = {"raw": r.text[:500]}
            return {"status_code": r.status_code, "data": data, "ok": 200 <= r.status_code < 300}

    async def contain_host(self, aid: str) -> dict[str, Any]:
        """Network containment sur un host (Device ID alias AID)."""
        if not self.configured:
            return {"applied": False, "reason": "falcon_not_configured"}
        path = "/devices/entities/devices-actions/v2?action_name=contain"
        payload = {"ids": [aid]}
        res = await self._api("POST", path, json=payload)
        return {"applied": res["ok"], "aid": aid, "action": "contain", **res}

    async def lift_containment(self, aid: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "falcon_not_configured"}
        path = "/devices/entities/devices-actions/v2?action_name=lift_containment"
        res = await self._api("POST", path, json={"ids": [aid]})
        return {"applied": res["ok"], "aid": aid, "action": "lift_containment", **res}

    async def search_hosts(self, query: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "falcon_not_configured"}
        res = await self._api("GET", f"/devices/queries/devices/v1?filter={query}")
        return res

    async def run_rtr_command(self, aid: str, command: str, command_string: str) -> dict[str, Any]:
        """Real-Time Response - execute commandes admin (kill, rm...).
        Necessite une session RTR active — flow complet :
          1. POST /real-time-response/entities/sessions/v1 (init)
          2. POST /real-time-response/entities/admin-command/v1 (execute)
        """
        if not self.configured:
            return {"applied": False, "reason": "falcon_not_configured"}
        init = await self._api(
            "POST",
            "/real-time-response/entities/sessions/v1",
            json={"device_id": aid},
        )
        if not init["ok"]:
            return {"applied": False, "step": "init_session", **init}
        resources = init["data"].get("resources") or []
        if not resources:
            return {"applied": False, "step": "init_session", "reason": "no_session"}
        session_id = resources[0].get("session_id")
        exec_res = await self._api(
            "POST",
            "/real-time-response/entities/admin-command/v1",
            json={
                "base_command": command,
                "command_string": command_string,
                "session_id": session_id,
                "persist": False,
            },
        )
        return {"applied": exec_res["ok"], "aid": aid, "session_id": session_id, "command": command_string, **exec_res}
