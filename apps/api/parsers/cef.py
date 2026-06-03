"""CEF (Common Event Format) parser.

Handles the standard ArcSight CEF format:
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

Supports:
- Full CEF header parsing
- Extension key=value pairs
- CEF escape sequences  (\\=, \\|, \\n, \\\\)
- CEF embedded inside syslog headers
- Severity mapping (numeric 0-10 and text labels)
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser, _normalize_severity

# ---------------------------------------------------------------------------
# Regex
# ---------------------------------------------------------------------------

_CEF_RE = re.compile(
    r"CEF:(\d+)\|"  # version
    r"([^|]*)\|"  # vendor
    r"([^|]*)\|"  # product
    r"([^|]*)\|"  # device version
    r"([^|]*)\|"  # signature id
    r"([^|]*)\|"  # name
    r"([^|]*)\|"  # severity
    r"(.*)",  # extensions
    re.DOTALL,
)

# Extension parser — handles values that contain spaces but not key=
_EXT_RE = re.compile(r"(\w+)=((?:[^ =]|\s(?!\w+=))*)")

# ---------------------------------------------------------------------------
# CEF escape sequences
# ---------------------------------------------------------------------------

_CEF_ESCAPES = {
    r"\=": "=",
    r"\|": "|",
    r"\n": "\n",
    r"\r": "\r",
    r"\\": "\\",
}


def _unescape_cef(value: str) -> str:
    for esc, repl in _CEF_ESCAPES.items():
        value = value.replace(esc, repl)
    return value


# ---------------------------------------------------------------------------
# CEF severity → unified severity
# ---------------------------------------------------------------------------


def _cef_severity(sev: str) -> str:
    try:
        n = int(sev)
        if n >= 9:
            return "critical"
        if n >= 7:
            return "high"
        if n >= 4:
            return "medium"
        return "low"
    except ValueError:
        return _normalize_severity(sev)


# ---------------------------------------------------------------------------
# CEF field → Event field mapping
# ---------------------------------------------------------------------------

_SRC_IP_KEYS = ("src", "sourceAddress", "cs1", "saddr")
_DST_IP_KEYS = ("dst", "destinationAddress", "daddr")
_USER_KEYS = ("suser", "duser", "sourceUserName", "destinationUserName", "cs2")
_MSG_KEYS = ("msg", "message", "reason")
_TS_KEYS = ("rt", "end", "start", "deviceReceiptTime")


def _extract(ext: dict[str, str], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = ext.get(k)
        if v:
            return v.strip()
    return None


def _parse_cef_timestamp(ext: dict[str, str]) -> datetime | None:
    raw = _extract(ext, _TS_KEYS)
    if not raw:
        return None
    # Epoch millis
    if raw.isdigit():
        return datetime.fromtimestamp(int(raw) / 1000, tz=UTC)
    # Try ISO
    for fmt in ("%b %d %Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Event type classification
# ---------------------------------------------------------------------------


def _classify_cef(name: str, sig_id: str) -> str:
    nl = name.lower()
    if any(w in nl for w in ("intrusion", "attack", "exploit")):
        return "ids.alert"
    if "malware" in nl:
        return "malware.detected"
    if any(w in nl for w in ("deny", "block", "drop", "reject")):
        return "network.blocked"
    if any(w in nl for w in ("allow", "permit", "accept")):
        return "network.allowed"
    if "auth" in nl or "login" in nl or "logon" in nl:
        return "auth.fail" if "fail" in nl else "auth.success"
    if "scan" in nl:
        return "scan.detected"
    if "policy" in nl:
        return "policy.violation"
    return f"cef.{sig_id}"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class CEFParser(BaseParser):
    name = "cef"
    formats = ["CEF"]
    priority = 10

    def can_parse(self, raw: str) -> bool:
        return "CEF:" in raw

    def parse(self, raw: str) -> dict[str, Any] | None:
        idx = raw.find("CEF:")
        if idx < 0:
            return None
        cef_part = raw[idx:]

        m = _CEF_RE.match(cef_part)
        if not m:
            return None

        version = m.group(1)
        vendor = _unescape_cef(m.group(2))
        product = _unescape_cef(m.group(3))
        device_version = _unescape_cef(m.group(4))
        sig_id = _unescape_cef(m.group(5))
        name = _unescape_cef(m.group(6))
        severity_raw = m.group(7)
        ext_raw = m.group(8)

        # Parse extensions
        ext: dict[str, str] = {}
        for em in _EXT_RE.finditer(ext_raw):
            ext[em.group(1)] = _unescape_cef(em.group(2).strip())

        ts = _parse_cef_timestamp(ext) or datetime.now(UTC)

        return {
            "ts": ts,
            "source": f"cef:{vendor}/{product}",
            "event_type": _classify_cef(name, sig_id),
            "severity": _cef_severity(severity_raw),
            "src_ip": _extract(ext, _SRC_IP_KEYS),
            "dst_ip": _extract(ext, _DST_IP_KEYS),
            "username": _extract(ext, _USER_KEYS),
            "message": name,
            "raw": raw,
            # Extra metadata kept for enrichment
            "_cef_version": version,
            "_vendor": vendor,
            "_product": product,
            "_device_version": device_version,
            "_sig_id": sig_id,
            "_extensions": ext,
        }
