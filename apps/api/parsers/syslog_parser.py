"""Enhanced syslog parser — RFC 3164 (BSD) and RFC 5424 (structured).

Features:
- Priority / facility / severity extraction
- RFC 5424 structured-data parsing  ([id key="val" ...])
- Multi-line message support (pass full block)
- Automatic version detection
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    12: "ntp", 13: "audit", 14: "alert", 15: "clock",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}

_SEVERITY_MAP = {
    0: "critical",   # Emergency
    1: "critical",   # Alert
    2: "critical",   # Critical
    3: "high",       # Error
    4: "medium",     # Warning
    5: "low",        # Notice
    6: "low",        # Informational
    7: "low",        # Debug
}

# ---------------------------------------------------------------------------
# RFC 3164:  <PRI>Mmm dd HH:MM:SS hostname app[pid]: msg
# ---------------------------------------------------------------------------

_RFC3164_RE = re.compile(
    r"<(\d{1,3})>"
    r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(\S+)\s+"                        # hostname
    r"(\S+?)(?:\[(\d+)\])?:\s+"        # app[pid]:
    r"([\s\S]+)"                        # msg (multiline)
)

# ---------------------------------------------------------------------------
# RFC 5424:  <PRI>VER TIMESTAMP HOSTNAME APP PID MSGID SD MSG
# ---------------------------------------------------------------------------

_RFC5424_RE = re.compile(
    r"<(\d{1,3})>(\d+)\s+"             # PRI + version
    r"(\S+)\s+"                         # timestamp
    r"(\S+)\s+"                         # hostname
    r"(\S+)\s+"                         # app-name
    r"(\S+)\s+"                         # procid
    r"(\S+)\s+"                         # msgid
    r"((?:\[.*?\]\s*)*|-)\s*"           # structured data
    r"([\s\S]*)"                        # msg
)

_SD_ELEMENT_RE = re.compile(r"\[(\S+?)(?:\s+([^\]]+))?\]")
_SD_PARAM_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_pri(pri: int) -> tuple[int, int, str, str]:
    """Return (facility_code, severity_code, facility_name, severity_label)."""
    facility = pri >> 3
    severity = pri & 0x07
    return (
        facility,
        severity,
        _FACILITY_NAMES.get(facility, f"facility{facility}"),
        _SEVERITY_MAP.get(severity, "low"),
    )


def _parse_sd(sd_raw: str) -> dict[str, dict[str, str]]:
    """Parse RFC 5424 structured data into {sd_id: {key: val}}."""
    result: dict[str, dict[str, str]] = {}
    if not sd_raw or sd_raw == "-":
        return result
    for elem_m in _SD_ELEMENT_RE.finditer(sd_raw):
        sd_id = elem_m.group(1)
        params_raw = elem_m.group(2) or ""
        params: dict[str, str] = {}
        for pm in _SD_PARAM_RE.finditer(params_raw):
            params[pm.group(1)] = pm.group(2).replace('\\"', '"').replace("\\\\", "\\")
        result[sd_id] = params
    return result


def _classify_syslog(app: str, message: str) -> str:
    lower = message.lower()
    app_l = app.lower()

    if "sshd" in app_l:
        if "failed password" in lower or "authentication failure" in lower:
            return "auth.fail"
        if "accepted" in lower:
            return "auth.success"
        if "invalid user" in lower:
            return "auth.fail"
        if "disconnect" in lower:
            return "auth.disconnect"
        return "auth.info"

    if "sudo" in app_l:
        if "authentication failure" in lower:
            return "auth.fail"
        return "priv.escalation"

    if app_l in ("pam", "login", "gdm", "lightdm", "systemd-logind"):
        if "fail" in lower or "denied" in lower:
            return "auth.fail"
        if "success" in lower or "opened" in lower:
            return "auth.success"
        return "auth.info"

    if any(fw in app_l for fw in ("firewall", "iptables", "ufw", "nftables", "pf")):
        if any(w in lower for w in ("block", "drop", "deny", "reject")):
            return "network.blocked"
        return "network.allowed"

    if "kernel" in app_l or "kern" in app_l:
        if "segfault" in lower:
            return "system.crash"
        if "oom" in lower or "out of memory" in lower:
            return "system.oom"
        return "system.kernel"

    if "cron" in app_l:
        return "system.cron"

    if "fail" in lower or "error" in lower or "denied" in lower:
        return "system.error"

    return "system.info"


def _extract_username(message: str) -> str | None:
    patterns = [
        re.compile(r"for (?:invalid user )?(\S+) from"),
        re.compile(r"user[= ](\S+)"),
        re.compile(r"USER=(\S+)"),
        re.compile(r"session opened for user (\S+)"),
        re.compile(r"Accepted \S+ for (\S+) from"),
    ]
    for p in patterns:
        m = p.search(message)
        if m:
            return m.group(1)
    return None


def _parse_bsd_timestamp(ts_str: str) -> datetime | None:
    """Parse RFC 3164 timestamp (no year — assume current year)."""
    now = datetime.now(UTC)
    try:
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        dt = dt.replace(year=now.year, tzinfo=UTC)
        if dt > now:
            dt = dt.replace(year=now.year - 1)
        return dt
    except ValueError:
        return None


def _parse_5424_timestamp(ts_str: str) -> datetime | None:
    if ts_str == "-":
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class SyslogParser(BaseParser):
    name = "syslog"
    formats = ["RFC 3164 (BSD)", "RFC 5424 (Structured)"]
    priority = 20

    def can_parse(self, raw: str) -> bool:
        return raw.startswith("<") and raw[1:4].strip("0123456789") != raw[1:4]

    def parse(self, raw: str) -> dict[str, Any] | None:
        # Try RFC 5424 first (has version number after PRI)
        if re.match(r"<\d{1,3}>\d+\s", raw):
            result = self._parse_5424(raw)
            if result is not None:
                return result

        # Fallback to RFC 3164
        return self._parse_3164(raw)

    # ---- RFC 3164 ----

    def _parse_3164(self, raw: str) -> dict[str, Any] | None:
        m = _RFC3164_RE.match(raw)
        if not m:
            return None

        pri = int(m.group(1))
        ts_str = m.group(2)
        hostname = m.group(3)
        app = m.group(4)
        pid = m.group(5)
        message = m.group(6)

        facility_code, severity_code, facility_name, severity = _decode_pri(pri)

        return {
            "ts": _parse_bsd_timestamp(ts_str) or datetime.now(UTC),
            "source": f"syslog:{hostname}",
            "event_type": _classify_syslog(app, message),
            "severity": severity,
            "src_ip": (_IP_RE.findall(message) or [None])[0],
            "dst_ip": (_IP_RE.findall(message)[1:2] or [None])[0],
            "username": _extract_username(message),
            "message": f"[{app}] {message}",
            "raw": raw,
            "_rfc": "3164",
            "_facility": facility_name,
            "_facility_code": facility_code,
            "_severity_code": severity_code,
            "_app": app,
            "_pid": pid,
            "_hostname": hostname,
        }

    # ---- RFC 5424 ----

    def _parse_5424(self, raw: str) -> dict[str, Any] | None:
        m = _RFC5424_RE.match(raw)
        if not m:
            return None

        pri = int(m.group(1))
        version = m.group(2)
        ts_str = m.group(3)
        hostname = m.group(4)
        app = m.group(5)
        procid = m.group(6)
        msgid = m.group(7)
        sd_raw = m.group(8)
        message = m.group(9)

        facility_code, severity_code, facility_name, severity = _decode_pri(pri)
        structured_data = _parse_sd(sd_raw)

        ips = _IP_RE.findall(message)

        return {
            "ts": _parse_5424_timestamp(ts_str) or datetime.now(UTC),
            "source": f"syslog:{hostname}",
            "event_type": _classify_syslog(app, message),
            "severity": severity,
            "src_ip": ips[0] if ips else None,
            "dst_ip": ips[1] if len(ips) > 1 else None,
            "username": _extract_username(message),
            "message": f"[{app}] {message}",
            "raw": raw,
            "_rfc": "5424",
            "_version": version,
            "_facility": facility_name,
            "_facility_code": facility_code,
            "_severity_code": severity_code,
            "_app": app,
            "_procid": procid,
            "_msgid": msgid,
            "_hostname": hostname,
            "_structured_data": structured_data,
        }
