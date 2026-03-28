"""Parser syslog RFC 5424 (format structure)."""

from __future__ import annotations

import re
from apps.collectors.normalizer import NormalizedEvent

# <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
_RFC5424_RE = re.compile(
    r"<(\d{1,3})>(\d+)\s+"
    r"(\S+)\s+"     # timestamp
    r"(\S+)\s+"     # hostname
    r"(\S+)\s+"     # app-name
    r"(\S+)\s+"     # procid
    r"(\S+)\s+"     # msgid
    r"(?:\[.*?\]|-)\s*"  # structured-data
    r"(.*)"         # message
)

_SEVERITY_MAP = {
    0: "critical", 1: "critical", 2: "critical", 3: "high",
    4: "medium", 5: "low", 6: "low", 7: "low",
}

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class Rfc5424Parser:
    name = "syslog_rfc5424"

    def can_parse(self, line: str) -> bool:
        if not line.startswith("<"):
            return False
        # RFC 5424 has version number right after PRI
        m = re.match(r"<\d{1,3}>\d+\s", line)
        return m is not None

    def parse(self, line: str) -> NormalizedEvent | None:
        m = _RFC5424_RE.match(line)
        if not m:
            return None

        pri = int(m.group(1))
        severity_code = pri & 0x07
        hostname = m.group(4)
        app = m.group(5)
        message = m.group(8)

        severity = _SEVERITY_MAP.get(severity_code, "low")

        ips = _IP_RE.findall(message)
        src_ip = ips[0] if ips else None

        lower = message.lower()
        if "fail" in lower or "denied" in lower:
            event_type = "auth.fail"
        elif "accept" in lower or "success" in lower:
            event_type = "auth.success"
        elif "error" in lower:
            event_type = "system.error"
        else:
            event_type = "system.info"

        return NormalizedEvent(
            source=f"syslog:{hostname}",
            event_type=event_type,
            severity=severity,
            src_ip=src_ip,
            message=f"[{app}] {message}",
            raw=line,
        )
