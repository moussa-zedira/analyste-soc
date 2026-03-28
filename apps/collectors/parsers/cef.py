"""Parser CEF (Common Event Format) pour firewalls et IDS."""

from __future__ import annotations

import re
from apps.collectors.normalizer import NormalizedEvent

# CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
_CEF_RE = re.compile(
    r"CEF:(\d+)\|"
    r"([^|]*)\|"   # vendor
    r"([^|]*)\|"   # product
    r"([^|]*)\|"   # version
    r"([^|]*)\|"   # sig id
    r"([^|]*)\|"   # name
    r"([^|]*)\|"   # severity
    r"(.*)"         # extension
)


def _parse_extensions(ext: str) -> dict[str, str]:
    """Parse les paires cle=valeur de l'extension CEF."""
    result: dict[str, str] = {}
    # Simple key=value parsing
    for m in re.finditer(r"(\w+)=((?:[^ =]+(?:\s+(?!\w+=))*)*)", ext):
        result[m.group(1)] = m.group(2).strip()
    return result


def _cef_severity_to_siem(sev: str) -> str:
    try:
        n = int(sev)
    except ValueError:
        s = sev.lower()
        if s in ("critical", "very-high"):
            return "critical"
        if s == "high":
            return "high"
        if s in ("medium", "warning"):
            return "medium"
        return "low"

    if n >= 9:
        return "critical"
    if n >= 7:
        return "high"
    if n >= 4:
        return "medium"
    return "low"


class CefParser:
    name = "cef"

    def can_parse(self, line: str) -> bool:
        return "CEF:" in line

    def parse(self, line: str) -> NormalizedEvent | None:
        # CEF can be embedded after syslog header
        idx = line.find("CEF:")
        if idx < 0:
            return None
        cef_part = line[idx:]

        m = _CEF_RE.match(cef_part)
        if not m:
            return None

        vendor = m.group(2)
        product = m.group(3)
        sig_id = m.group(5)
        name = m.group(6)
        severity = _cef_severity_to_siem(m.group(7))
        ext = _parse_extensions(m.group(8))

        src_ip = ext.get("src") or ext.get("sourceAddress")
        dst_ip = ext.get("dst") or ext.get("destinationAddress")
        username = ext.get("suser") or ext.get("duser")

        # Classify event type
        name_lower = name.lower()
        if "intrusion" in name_lower or "attack" in name_lower:
            event_type = "ids.alert"
        elif "malware" in name_lower:
            event_type = "malware.detected"
        elif "deny" in name_lower or "block" in name_lower or "drop" in name_lower:
            event_type = "network.blocked"
        elif "allow" in name_lower or "permit" in name_lower:
            event_type = "network.allowed"
        elif "auth" in name_lower or "login" in name_lower:
            event_type = "auth.fail" if "fail" in name_lower else "auth.success"
        else:
            event_type = f"cef.{sig_id}"

        return NormalizedEvent(
            source=f"cef:{vendor}/{product}",
            event_type=event_type,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            username=username,
            message=name,
            raw=line,
        )
