"""Parser /var/log/auth.log (Linux SSH, sudo, PAM)."""

from __future__ import annotations

import re
from apps.collectors.normalizer import NormalizedEvent

# Mar 26 22:00:00 hostname sshd[12345]: Failed password for root from 1.2.3.4 port 22 ssh2
_AUTH_RE = re.compile(
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"        # hostname
    r"(\S+?)(?:\[\d+\])?:\s+"  # process
    r"(.+)"            # message
)

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


class AuthLogParser:
    name = "auth_log"

    def can_parse(self, line: str) -> bool:
        if not _AUTH_RE.match(line):
            return False
        # Only match auth-related lines
        lower = line.lower()
        return any(kw in lower for kw in [
            "sshd", "sudo", "pam", "login", "passwd",
            "authentication", "session", "su[",
        ])

    def parse(self, line: str) -> NormalizedEvent | None:
        m = _AUTH_RE.match(line)
        if not m:
            return None

        hostname = m.group(2)
        process = m.group(3)
        message = m.group(4)

        event_type, severity = _classify(process, message)

        ips = _IP_RE.findall(message)
        src_ip = ips[0] if ips else None

        username = _extract_user(message)

        return NormalizedEvent(
            source=f"authlog:{hostname}",
            event_type=event_type,
            severity=severity,
            src_ip=src_ip,
            username=username,
            message=f"[{process}] {message}",
            raw=line,
        )


def _classify(process: str, message: str) -> tuple[str, str]:
    lower = message.lower()
    proc = process.lower()

    if "sshd" in proc:
        if "failed password" in lower or "authentication failure" in lower:
            return "auth.fail", "medium"
        if "invalid user" in lower:
            return "auth.fail", "medium"
        if "accepted" in lower:
            return "auth.success", "low"
        if "disconnected" in lower or "connection closed" in lower:
            return "auth.disconnect", "low"
        if "did not receive identification" in lower:
            return "scan.ssh", "medium"

    if "sudo" in proc:
        if "authentication failure" in lower:
            return "auth.fail", "medium"
        if "command" in lower:
            return "priv.escalation", "medium"
        return "priv.sudo", "low"

    if "su" in proc:
        if "failed" in lower:
            return "auth.fail", "medium"
        return "priv.su", "medium"

    if "session opened" in lower:
        return "session.open", "low"
    if "session closed" in lower:
        return "session.close", "low"

    return "auth.info", "low"


def _extract_user(message: str) -> str | None:
    patterns = [
        re.compile(r"for (?:invalid user )?(\S+) from"),
        re.compile(r"for user (\S+)"),
        re.compile(r"user=(\S+)"),
        re.compile(r"USER=(\S+)"),
        re.compile(r"by (\S+)"),
    ]
    for p in patterns:
        m = p.search(message)
        if m:
            val = m.group(1)
            if val not in ("from", "on", "to"):
                return val
    return None
