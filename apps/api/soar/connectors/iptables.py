"""IPTables connector — host-level firewall blocking."""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

from apps.api.soar.connectors.base import Connector


class IPTablesConnector(Connector):
    """Blocage d'IP via iptables. Ne fonctionne que si le conteneur
    a les privileges requis (cap_add: NET_ADMIN ou --privileged)."""

    name = "iptables"
    required_env: list[str] = []  # Pas d'env, mais besoin du binaire

    @property
    def configured(self) -> bool:
        """iptables disponible + nous avons les privileges pour l'utiliser."""
        return shutil.which("iptables") is not None

    async def available(self) -> bool:
        if not self.configured:
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                "iptables",
                "-L",
                "-n",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            rc = await proc.wait()
            return rc == 0
        except Exception:
            return False

    async def _run(self, *args: str) -> tuple[int, str, str]:
        proc = await asyncio.create_subprocess_exec(
            "iptables",
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await proc.communicate()
        return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")

    async def _rule_exists(self, ip: str, chain: str) -> bool:
        rc, _, _ = await self._run(
            "-C", chain, "-s" if chain == "INPUT" else "-d", ip, "-j", "DROP"
        )
        return rc == 0

    async def block_ip(self, ip: str, direction: str = "both") -> dict[str, Any]:
        """Ajoute une regle DROP. direction ∈ {inbound, outbound, both}."""
        if not self.configured:
            return {"applied": False, "reason": "iptables_not_available"}

        chains: list[str] = []
        if direction in ("inbound", "both"):
            chains.append("INPUT")
        if direction in ("outbound", "both"):
            chains.append("OUTPUT")

        results: dict[str, Any] = {"ip": ip, "chains": {}}
        applied_any = False
        for chain in chains:
            flag = "-s" if chain == "INPUT" else "-d"
            # Skip si deja present
            if await self._rule_exists(ip, chain):
                results["chains"][chain] = "already_present"
                applied_any = True
                continue
            rc, _, err = await self._run("-A", chain, flag, ip, "-j", "DROP")
            if rc == 0:
                results["chains"][chain] = "added"
                applied_any = True
            else:
                results["chains"][chain] = f"error: {err.strip()[:200]}"
                if "Permission denied" in err or "Operation not permitted" in err:
                    return {
                        "applied": False,
                        "reason": "no_privileges",
                        "detail": err.strip()[:200],
                    }

        return {"applied": applied_any, **results}

    async def unblock_ip(self, ip: str, direction: str = "both") -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "iptables_not_available"}
        chains = []
        if direction in ("inbound", "both"):
            chains.append(("INPUT", "-s"))
        if direction in ("outbound", "both"):
            chains.append(("OUTPUT", "-d"))
        removed = []
        for chain, flag in chains:
            rc, _, _ = await self._run("-D", chain, flag, ip, "-j", "DROP")
            if rc == 0:
                removed.append(chain)
        return {"applied": bool(removed), "chains_removed": removed, "ip": ip}
