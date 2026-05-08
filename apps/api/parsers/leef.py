"""LEEF (Log Event Extended Format) parser — IBM QRadar compatible.

Supports LEEF 1.0 and LEEF 2.0 with custom delimiter.

LEEF 1.0:  LEEF:1.0|Vendor|Product|Version|EventID|key=value\tkey=value
LEEF 2.0:  LEEF:2.0|Vendor|Product|Version|EventID|delimiter|key=value...
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser, _normalize_severity

# ---------------------------------------------------------------------------
# Header regex
# ---------------------------------------------------------------------------

_LEEF_HEADER_RE = re.compile(
    r"LEEF:(\d+\.\d+)\|"  # version
    r"([^|]*)\|"           # vendor
    r"([^|]*)\|"           # product
    r"([^|]*)\|"           # version
    r"([^|]*)\|"           # event id
    r"(.*)",               # rest (optional delimiter byte + attributes)
    re.DOTALL,
)

# Default LEEF 1.0 delimiter is tab
_DEFAULT_DELIM = "\t"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITY_KEYS = ("sev", "severity", "cat")
_SRC_IP_KEYS = ("src", "srcIP", "sourceAddress", "srcIp")
_DST_IP_KEYS = ("dst", "dstIP", "destinationAddress", "dstIp")
_USER_KEYS = ("usrName", "userName", "identSrc", "srcUser", "dstUser")
_MSG_KEYS = ("msg", "message", "reason", "action")
_TS_KEYS = ("devTime", "devTimeFormat", "calLanguage")


def _extract(attrs: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = attrs.get(k)
        if v:
            return v.strip()
    return None


def _parse_leef_ts(attrs: dict[str, str]) -> datetime | None:
    raw = attrs.get("devTime")
    if not raw:
        return None
    if raw.isdigit():
        return datetime.fromtimestamp(int(raw) / 1000, tz=UTC)
    for fmt in (
        "%b %d %Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%d/%b/%Y:%H:%M:%S %z",
    ):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _classify_leef(event_id: str, attrs: dict[str, str]) -> str:
    eid = event_id.lower()
    cat = (attrs.get("cat") or "").lower()
    if "auth" in eid or "login" in eid or "logon" in eid or "auth" in cat:
        return "auth.fail" if "fail" in eid or "fail" in cat else "auth.success"
    if any(w in eid for w in ("deny", "block", "drop")):
        return "network.blocked"
    if any(w in eid for w in ("allow", "permit", "accept")):
        return "network.allowed"
    if "malware" in eid or "malware" in cat:
        return "malware.detected"
    if "ids" in eid or "intrusion" in eid:
        return "ids.alert"
    return f"leef.{event_id}"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class LEEFParser(BaseParser):
    name = "leef"
    formats = ["LEEF 1.0", "LEEF 2.0"]
    priority = 11

    def can_parse(self, raw: str) -> bool:
        return "LEEF:" in raw

    def parse(self, raw: str) -> dict[str, Any] | None:
        idx = raw.find("LEEF:")
        if idx < 0:
            return None
        leef_part = raw[idx:]

        m = _LEEF_HEADER_RE.match(leef_part)
        if not m:
            return None

        version = m.group(1)
        vendor = m.group(2)
        product = m.group(3)
        prod_version = m.group(4)
        event_id = m.group(5)
        rest = m.group(6)

        # LEEF 2.0: first character of rest is custom delimiter
        if version.startswith("2"):
            if rest:
                delim = rest[0]
                attr_str = rest[1:]
            else:
                delim = _DEFAULT_DELIM
                attr_str = ""
        else:
            delim = _DEFAULT_DELIM
            attr_str = rest

        # Parse key=value pairs
        attrs: dict[str, str] = {}
        parts = attr_str.split(delim) if delim else [attr_str]
        for part in parts:
            part = part.strip()
            if "=" not in part:
                continue
            key, _, val = part.partition("=")
            attrs[key.strip()] = val.strip()

        ts = _parse_leef_ts(attrs) or datetime.now(UTC)
        severity_raw = _extract(attrs, _SEVERITY_KEYS) or "low"

        return {
            "ts": ts,
            "source": f"leef:{vendor}/{product}",
            "event_type": _classify_leef(event_id, attrs),
            "severity": _normalize_severity(severity_raw),
            "src_ip": _extract(attrs, _SRC_IP_KEYS),
            "dst_ip": _extract(attrs, _DST_IP_KEYS),
            "username": _extract(attrs, _USER_KEYS),
            "message": _extract(attrs, _MSG_KEYS) or event_id,
            "raw": raw,
            "_leef_version": version,
            "_vendor": vendor,
            "_product": product,
            "_prod_version": prod_version,
            "_event_id": event_id,
            "_attrs": attrs,
        }
