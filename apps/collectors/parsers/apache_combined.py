"""Parser Apache/Nginx combined access log."""

from __future__ import annotations

import re
from apps.collectors.normalizer import NormalizedEvent

# 192.168.1.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla/4.08"
_COMBINED_RE = re.compile(
    r"(\S+)\s+"           # client IP
    r"(\S+)\s+"           # ident
    r"(\S+)\s+"           # user
    r"\[([^\]]+)\]\s+"    # date
    r'"(\S+)\s+(\S+)\s+(\S+)"\s+'  # method, path, protocol
    r"(\d{3})\s+"         # status code
    r"(\d+|-)"            # bytes
    r'(?:\s+"([^"]*)")?'  # referer
    r'(?:\s+"([^"]*)")?'  # user agent
)

_SUSPICIOUS_PATTERNS = [
    (re.compile(r"(?:etc/passwd|etc/shadow|\.\./)"), "path.traversal"),
    (re.compile(r"(?:<script|javascript:|onerror=)", re.I), "xss.attempt"),
    (re.compile(r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|--\s*$)", re.I), "sql.injection"),
    (re.compile(r"(?:\.php\?|cmd=|exec=|system\()"), "rce.attempt"),
    (re.compile(r"(?:wp-admin|wp-login|xmlrpc\.php)"), "scan.wordpress"),
    (re.compile(r"(?:\.env|\.git/|\.aws/)"), "scan.sensitive_files"),
]


class ApacheCombinedParser:
    name = "apache_combined"

    def can_parse(self, line: str) -> bool:
        return _COMBINED_RE.match(line) is not None

    def parse(self, line: str) -> NormalizedEvent | None:
        m = _COMBINED_RE.match(line)
        if not m:
            return None

        src_ip = m.group(1)
        user = m.group(3) if m.group(3) != "-" else None
        method = m.group(5)
        path = m.group(6)
        status = int(m.group(8))

        event_type, severity = _classify_request(method, path, status)

        return NormalizedEvent(
            source="weblog",
            event_type=event_type,
            severity=severity,
            src_ip=src_ip,
            username=user,
            message=f"{method} {path} -> {status}",
            raw=line,
        )


def _classify_request(method: str, path: str, status: int) -> tuple[str, str]:
    # Check suspicious patterns first
    for pattern, evt_type in _SUSPICIOUS_PATTERNS:
        if pattern.search(path):
            return evt_type, "high"

    if status == 401 or status == 403:
        return "web.forbidden", "medium"
    if status >= 500:
        return "web.server_error", "medium"
    if status == 404:
        return "web.not_found", "low"

    return "web.access", "low"
