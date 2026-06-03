"""Apache / Nginx access and error log parser.

Supports:
- Common Log Format (CLF)
- Combined Log Format
- Nginx default format (same as combined)
- Error log format (Apache and Nginx)
- Custom format string detection
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser

# ---------------------------------------------------------------------------
# Access log regex
# ---------------------------------------------------------------------------

# Combined:  IP ident user [date] "method path proto" status bytes "referer" "ua"
_COMBINED_RE = re.compile(
    r"(\S+)\s+"  # client IP
    r"(\S+)\s+"  # ident
    r"(\S+)\s+"  # user
    r"\[([^\]]+)\]\s+"  # date
    r'"(\S+)\s+(\S+)\s*(\S*)"\s+'  # method path protocol
    r"(\d{3})\s+"  # status
    r"(\d+|-)"  # bytes
    r'(?:\s+"([^"]*)")?'  # referer
    r'(?:\s+"([^"]*)")?'  # user-agent
)

# CLF (no referer/ua):  IP ident user [date] "method path proto" status bytes
_CLF_RE = re.compile(
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"\[([^\]]+)\]\s+"
    r'"(\S+)\s+(\S+)\s*(\S*)"\s+'
    r"(\d{3})\s+"
    r"(\d+|-)\s*$"
)

# ---------------------------------------------------------------------------
# Error log regex
# ---------------------------------------------------------------------------

# Apache error:  [day_of_week month day time year] [module:level] [pid tid] [client IP:port] msg
_APACHE_ERROR_RE = re.compile(
    r"\[(\w+ \w+ \d+ [\d:]+ \d+)\]\s+"
    r"\[([^\]]+)\]\s+"  # module:level
    r"(?:\[pid \d+(?::tid \d+)?\]\s+)?"
    r"(?:\[client (\S+?)(?::\d+)?\]\s+)?"
    r"(.*)",
    re.DOTALL,
)

# Nginx error:  YYYY/MM/DD HH:MM:SS [level] pid#tid: *connid msg, client: IP, ...
_NGINX_ERROR_RE = re.compile(
    r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"\[(\w+)\]\s+"
    r"\d+#\d+:\s+"
    r"(?:\*\d+ )?"
    r"(.*)",
    re.DOTALL,
)

# ---------------------------------------------------------------------------
# Security-related patterns in URLs
# ---------------------------------------------------------------------------

_SUSPICIOUS_PATTERNS = [
    (re.compile(r"(?:\.\.[\\/]|etc/passwd|etc/shadow|proc/self)", re.I), "path.traversal", "high"),
    (re.compile(r"(?:<script|javascript:|onerror=|onload=|onfocus=)", re.I), "xss.attempt", "high"),
    (
        re.compile(r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*'|--\s*$|;\s*DROP\s)", re.I),
        "sql.injection",
        "high",
    ),
    (
        re.compile(r"(?:cmd=|exec=|system\(|passthru|shell_exec|eval\()", re.I),
        "rce.attempt",
        "critical",
    ),
    (
        re.compile(r"(?:wp-admin|wp-login|xmlrpc\.php|wp-content/uploads)", re.I),
        "scan.wordpress",
        "medium",
    ),
    (re.compile(r"(?:\.env|\.git/|\.aws/|\.ssh/|id_rsa)", re.I), "scan.sensitive_files", "high"),
    (re.compile(r"(?:phpinfo|phpmyadmin|adminer|\.sql\.gz)", re.I), "scan.admin_tools", "medium"),
    (re.compile(r"(?:/cgi-bin/|/shell|/c99|/r57|/webshell)", re.I), "scan.webshell", "critical"),
    (re.compile(r"(?:%00|%0d%0a|\r\n)", re.I), "injection.null_byte", "high"),
    (re.compile(r"(?:base64_decode|gzinflate|str_rot13)", re.I), "rce.obfuscated", "high"),
]

# Suspicious user agents
_SUSPICIOUS_UA = [
    (
        re.compile(r"(?:sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|wfuzz)", re.I),
        "scan.tool",
    ),
    (re.compile(r"(?:curl|wget|python-requests|httpie)", re.I), "scan.scripted"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_clf_ts(ts_str: str) -> datetime | None:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    return None


def _classify_access(method: str, path: str, status: int, ua: str | None) -> tuple[str, str]:
    """Return (event_type, severity) based on request content."""
    # Check path for attack patterns
    for pattern, evt_type, sev in _SUSPICIOUS_PATTERNS:
        if pattern.search(path):
            return evt_type, sev

    # Check user-agent
    if ua:
        for pattern, evt_type in _SUSPICIOUS_UA:
            if pattern.search(ua):
                return evt_type, "medium"

    # Status-based classification
    if status == 401:
        return "web.unauthorized", "medium"
    if status == 403:
        return "web.forbidden", "medium"
    if status >= 500:
        return "web.server_error", "medium"
    if status == 404:
        return "web.not_found", "low"
    if status == 301 or status == 302:
        return "web.redirect", "low"

    return "web.access", "low"


def _classify_error_level(level: str) -> str:
    level_l = level.lower().split(":")[-1].strip()
    if level_l in ("emerg", "alert", "crit"):
        return "critical"
    if level_l in ("error", "err"):
        return "high"
    if level_l in ("warn", "warning"):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class ApacheParser(BaseParser):
    name = "apache"
    formats = ["Common Log Format", "Combined Log Format", "Apache Error", "Nginx Error"]
    priority = 30

    def can_parse(self, raw: str) -> bool:
        if _COMBINED_RE.match(raw) or _CLF_RE.match(raw):
            return True
        if _APACHE_ERROR_RE.match(raw):
            return True
        return bool(_NGINX_ERROR_RE.match(raw))

    def parse(self, raw: str) -> dict[str, Any] | None:
        # Try combined / CLF first
        result = self._parse_access(raw)
        if result:
            return result
        # Try error logs
        result = self._parse_apache_error(raw)
        if result:
            return result
        return self._parse_nginx_error(raw)

    def _parse_access(self, raw: str) -> dict[str, Any] | None:
        m = _COMBINED_RE.match(raw) or _CLF_RE.match(raw)
        if not m:
            return None

        groups = m.groups()
        src_ip = groups[0]
        user = groups[2] if groups[2] != "-" else None
        ts_str = groups[3]
        method = groups[4]
        path = groups[5]
        protocol = groups[6] if len(groups) > 6 else ""
        status = int(groups[7])
        bytes_sent = groups[8]
        referer = groups[9] if len(groups) > 9 else None
        ua = groups[10] if len(groups) > 10 else None

        ts = _parse_clf_ts(ts_str) or datetime.now(UTC)
        event_type, severity = _classify_access(method, path, status, ua)

        return {
            "ts": ts,
            "source": "weblog",
            "event_type": event_type,
            "severity": severity,
            "src_ip": src_ip,
            "dst_ip": None,
            "username": user,
            "message": f"{method} {path} -> {status}",
            "raw": raw,
            "_method": method,
            "_path": path,
            "_protocol": protocol,
            "_status": status,
            "_bytes": bytes_sent,
            "_referer": referer if referer and referer != "-" else None,
            "_user_agent": ua if ua and ua != "-" else None,
        }

    def _parse_apache_error(self, raw: str) -> dict[str, Any] | None:
        m = _APACHE_ERROR_RE.match(raw)
        if not m:
            return None

        ts_str = m.group(1)
        level = m.group(2)
        client_ip = m.group(3)
        message = m.group(4)

        # Parse timestamp
        ts = None
        for fmt in ("%a %b %d %H:%M:%S %Y", "%a %b %d %H:%M:%S.%f %Y"):
            try:
                ts = datetime.strptime(ts_str, fmt).replace(tzinfo=UTC)
                break
            except ValueError:
                continue

        severity = _classify_error_level(level)

        return {
            "ts": ts or datetime.now(UTC),
            "source": "apache:error",
            "event_type": "web.error",
            "severity": severity,
            "src_ip": client_ip,
            "dst_ip": None,
            "username": None,
            "message": message.strip(),
            "raw": raw,
            "_log_type": "apache_error",
            "_level": level,
        }

    def _parse_nginx_error(self, raw: str) -> dict[str, Any] | None:
        m = _NGINX_ERROR_RE.match(raw)
        if not m:
            return None

        ts_str = m.group(1)
        level = m.group(2)
        message = m.group(3)

        try:
            ts = datetime.strptime(ts_str, "%Y/%m/%d %H:%M:%S").replace(tzinfo=UTC)
        except ValueError:
            ts = datetime.now(UTC)

        # Extract client IP from message
        client_match = re.search(r"client:\s*(\S+)", message)
        client_ip = client_match.group(1).rstrip(",") if client_match else None

        severity = _classify_error_level(level)

        return {
            "ts": ts,
            "source": "nginx:error",
            "event_type": "web.error",
            "severity": severity,
            "src_ip": client_ip,
            "dst_ip": None,
            "username": None,
            "message": message.strip(),
            "raw": raw,
            "_log_type": "nginx_error",
            "_level": level,
        }
