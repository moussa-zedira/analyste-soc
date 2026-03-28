"""Parser syslog RFC 3164 (BSD format classique)."""

from __future__ import annotations

import re
from apps.collectors.normalizer import NormalizedEvent

# <PRI>Mmm dd HH:MM:SS hostname app[pid]: message
_RFC3164_RE = re.compile(
    r"<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s+"
    r"(.+)"
)

_SEVERITY_MAP = {
    0: "critical",  # Emergency
    1: "critical",  # Alert
    2: "critical",  # Critical
    3: "high",      # Error
    4: "medium",    # Warning
    5: "low",       # Notice
    6: "low",       # Informational
    7: "low",       # Debug
}

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class Rfc3164Parser:
    name = "syslog_rfc3164"

    def can_parse(self, line: str) -> bool:
        return line.startswith("<") and _RFC3164_RE.match(line) is not None

    def parse(self, line: str) -> NormalizedEvent | None:
        m = _RFC3164_RE.match(line)
        if not m:
            return None

        pri = int(m.group(1))
        severity_code = pri & 0x07
        hostname = m.group(3)
        app = m.group(4)
        message = m.group(6)

        severity = _SEVERITY_MAP.get(severity_code, "low")
        event_type = _classify_message(app, message)

        ips = _IP_RE.findall(message)
        src_ip = ips[0] if ips else None

        username = _extract_username(message)

        return NormalizedEvent(
            source=f"syslog:{hostname}",
            event_type=event_type,
            severity=severity,
            src_ip=src_ip,
            username=username,
            message=f"[{app}] {message}",
            raw=line,
        )


def _classify_message(app: str, message: str) -> str:
    lower = message.lower()
    app_lower = app.lower()

    if "sshd" in app_lower:
        if "failed password" in lower or "authentication failure" in lower:
            return "auth.fail"
        if "accepted" in lower:
            return "auth.success"
        if "invalid user" in lower:
            return "auth.fail"

    if "sudo" in app_lower:
        if "authentication failure" in lower:
            return "auth.fail"
        return "priv.escalation"

    if "firewall" in app_lower or "iptables" in app_lower or "ufw" in app_lower:
        if "block" in lower or "drop" in lower or "deny" in lower:
            return "network.blocked"
        return "network.allowed"

    if "failed" in lower or "error" in lower or "denied" in lower:
        return "system.error"

    return "system.info"


def _extract_username(message: str) -> str | None:
    patterns = [
        re.compile(r"for (?:invalid user )?(\S+) from"),
        re.compile(r"user[= ](\S+)"),
        re.compile(r"USER=(\S+)"),
    ]
    for p in patterns:
        m = p.search(message)
        if m:
            return m.group(1)
    return None
