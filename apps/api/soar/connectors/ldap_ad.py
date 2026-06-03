"""LDAP/Active Directory connector via ldap3."""

from __future__ import annotations

import asyncio
from typing import Any

from apps.api.soar.connectors.base import Connector


class LDAPConnector(Connector):
    """Connector AD/LDAP via ldap3.

    Env vars : LDAP_SERVER, LDAP_BIND_DN, LDAP_BIND_PASSWORD, LDAP_BASE_DN
    """

    name = "ldap_ad"
    required_env = ["LDAP_SERVER", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD", "LDAP_BASE_DN"]

    def _connect(self):
        try:
            import ldap3
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("ldap3 non installe (pip install ldap3)") from exc

        server = ldap3.Server(self.env("LDAP_SERVER"), get_info=ldap3.ALL)
        conn = ldap3.Connection(
            server,
            user=self.env("LDAP_BIND_DN"),
            password=self.env("LDAP_BIND_PASSWORD"),
            auto_bind=True,
        )
        return conn

    async def available(self) -> bool:
        if not self.configured:
            return False
        try:
            conn = await asyncio.to_thread(self._connect)
            conn.unbind()
            return True
        except Exception:
            return False

    def _find_user_dn(self, conn, username: str) -> str | None:
        import ldap3

        base_dn = self.env("LDAP_BASE_DN")
        # Essaie sAMAccountName (AD) puis uid (OpenLDAP)
        for attr in ("sAMAccountName", "uid", "cn"):
            conn.search(
                base_dn,
                f"({attr}={ldap3.utils.conv.escape_filter_chars(username)})",
                attributes=["distinguishedName"],
            )
            if conn.entries:
                return conn.entries[0].entry_dn
        return None

    async def disable_user(self, username: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "ldap_not_configured"}

        def _do():
            from ldap3 import MODIFY_REPLACE

            conn = self._connect()
            try:
                dn = self._find_user_dn(conn, username)
                if not dn:
                    return {"applied": False, "reason": "user_not_found", "username": username}
                # AD : userAccountControl |= 2 (ACCOUNTDISABLE)
                conn.search(dn, "(objectClass=*)", attributes=["userAccountControl"])
                if conn.entries and "userAccountControl" in conn.entries[0]:
                    current = int(conn.entries[0].userAccountControl.value)
                    new_val = current | 0x2  # ACCOUNTDISABLE
                    conn.modify(dn, {"userAccountControl": [(MODIFY_REPLACE, [new_val])]})
                else:
                    # OpenLDAP : ajoute pwdAccountLockedTime ou shadowExpire
                    conn.modify(dn, {"pwdAccountLockedTime": [(MODIFY_REPLACE, ["000001010000Z"])]})
                ok = conn.result.get("result") == 0
                return {
                    "applied": ok,
                    "dn": dn,
                    "username": username,
                    "ldap_result": conn.result.get("description"),
                }
            finally:
                conn.unbind()

        return await asyncio.to_thread(_do)

    async def reset_password(self, username: str, new_password: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "ldap_not_configured"}

        def _do():
            from ldap3 import MODIFY_REPLACE

            conn = self._connect()
            try:
                dn = self._find_user_dn(conn, username)
                if not dn:
                    return {"applied": False, "reason": "user_not_found", "username": username}
                # AD attend unicodePwd encode en UTF-16-LE avec guillemets
                try:
                    pwd_value = f'"{new_password}"'.encode("utf-16-le")
                    conn.modify(dn, {"unicodePwd": [(MODIFY_REPLACE, [pwd_value])]})
                    if conn.result.get("result") != 0:
                        raise RuntimeError("AD password reset failed")
                except Exception:
                    # Fallback OpenLDAP userPassword
                    conn.modify(dn, {"userPassword": [(MODIFY_REPLACE, [new_password])]})
                ok = conn.result.get("result") == 0
                return {
                    "applied": ok,
                    "dn": dn,
                    "username": username,
                    "ldap_result": conn.result.get("description"),
                }
            finally:
                conn.unbind()

        return await asyncio.to_thread(_do)

    async def add_to_group(self, username: str, group_dn: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "ldap_not_configured"}

        def _do():
            from ldap3 import MODIFY_ADD

            conn = self._connect()
            try:
                user_dn = self._find_user_dn(conn, username)
                if not user_dn:
                    return {"applied": False, "reason": "user_not_found"}
                conn.modify(group_dn, {"member": [(MODIFY_ADD, [user_dn])]})
                return {
                    "applied": conn.result.get("result") == 0,
                    "group": group_dn,
                    "user_dn": user_dn,
                }
            finally:
                conn.unbind()

        return await asyncio.to_thread(_do)

    async def remove_from_group(self, username: str, group_dn: str) -> dict[str, Any]:
        if not self.configured:
            return {"applied": False, "reason": "ldap_not_configured"}

        def _do():
            from ldap3 import MODIFY_DELETE

            conn = self._connect()
            try:
                user_dn = self._find_user_dn(conn, username)
                if not user_dn:
                    return {"applied": False, "reason": "user_not_found"}
                conn.modify(group_dn, {"member": [(MODIFY_DELETE, [user_dn])]})
                return {
                    "applied": conn.result.get("result") == 0,
                    "group": group_dn,
                    "user_dn": user_dn,
                }
            finally:
                conn.unbind()

        return await asyncio.to_thread(_do)
