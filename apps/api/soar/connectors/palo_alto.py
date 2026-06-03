"""Palo Alto Panorama / PAN-OS connector via XML REST API."""

from __future__ import annotations

from typing import Any

import httpx

from apps.api.soar.connectors.base import Connector


class PanoramaConnector(Connector):
    """Palo Alto Panorama via API XML.

    Env : PANORAMA_HOST, PANORAMA_API_KEY
    (API key obtenue via /api/?type=keygen&user=...&password=...)
    """

    name = "palo_alto"
    required_env = ["PANORAMA_HOST", "PANORAMA_API_KEY"]

    def _base(self) -> str:
        host = self.env("PANORAMA_HOST").rstrip("/")
        if not host.startswith("http"):
            host = f"https://{host}"
        return f"{host}/api/"

    async def available(self) -> bool:
        if not self.configured:
            return False
        try:
            async with httpx.AsyncClient(timeout=15, verify=False) as c:
                r = await c.get(
                    self._base(),
                    params={
                        "type": "op",
                        "cmd": "<show><system><info></info></system></show>",
                        "key": self.env("PANORAMA_API_KEY"),
                    },
                )
                return r.status_code == 200 and "response" in r.text
        except Exception:
            return False

    async def _api(self, params: dict) -> dict[str, Any]:
        params = {**params, "key": self.env("PANORAMA_API_KEY")}
        async with httpx.AsyncClient(timeout=60, verify=False) as c:
            r = await c.get(self._base(), params=params)
            ok = r.status_code == 200 and 'status="success"' in r.text
            return {"status_code": r.status_code, "ok": ok, "xml": r.text[:1000]}

    async def block_ip(self, ip: str, address_group: str = "SOAR-Blocklist") -> dict[str, Any]:
        """Ajoute l'IP dans un address-object, puis au group referencé par une security rule deny."""
        if not self.configured:
            return {"applied": False, "reason": "panorama_not_configured"}

        obj_name = f"soar-ip-{ip.replace('.', '-').replace(':', '-')}"
        # 1. Creer l'address-object
        xpath_obj = f"/config/shared/address/entry[@name='{obj_name}']"
        element_obj = f"<ip-netmask>{ip}</ip-netmask>"
        r1 = await self._api(
            {"type": "config", "action": "set", "xpath": xpath_obj, "element": element_obj}
        )
        if not r1["ok"]:
            return {"applied": False, "step": "create_address", **r1}

        # 2. Ajouter au group
        xpath_grp = f"/config/shared/address-group/entry[@name='{address_group}']/static"
        element_grp = f"<member>{obj_name}</member>"
        r2 = await self._api(
            {"type": "config", "action": "set", "xpath": xpath_grp, "element": element_grp}
        )
        if not r2["ok"]:
            return {"applied": False, "step": "add_to_group", **r2}

        return {
            "applied": True,
            "ip": ip,
            "address_object": obj_name,
            "group": address_group,
            "note": "Pensez a commit() pour appliquer",
        }

    async def block_domain(
        self, fqdn: str, address_group: str = "SOAR-Domains-Blocklist"
    ) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "panorama_not_configured"}
        obj_name = f"soar-fqdn-{fqdn.replace('.', '-')}"
        xpath_obj = f"/config/shared/address/entry[@name='{obj_name}']"
        element_obj = f"<fqdn>{fqdn}</fqdn>"
        r1 = await self._api(
            {"type": "config", "action": "set", "xpath": xpath_obj, "element": element_obj}
        )
        if not r1["ok"]:
            return {"applied": False, "step": "create_fqdn", **r1}
        xpath_grp = f"/config/shared/address-group/entry[@name='{address_group}']/static"
        element_grp = f"<member>{obj_name}</member>"
        r2 = await self._api(
            {"type": "config", "action": "set", "xpath": xpath_grp, "element": element_grp}
        )
        if not r2["ok"]:
            return {"applied": False, "step": "add_to_group", **r2}
        return {
            "applied": True,
            "fqdn": fqdn,
            "address_object": obj_name,
            "group": address_group,
            "note": "Pensez a commit()",
        }

    async def commit(self) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "panorama_not_configured"}
        r = await self._api({"type": "commit", "cmd": "<commit></commit>"})
        return {"applied": r["ok"], "action": "commit", **r}
