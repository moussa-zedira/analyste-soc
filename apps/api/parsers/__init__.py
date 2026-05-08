"""Parser registry — auto-detection, chaining, and normalization to Event model.

Every parser inherits from :class:`BaseParser` and is auto-registered when
this package is imported.  The :func:`detect` function tries each parser in
priority order; :func:`parse_line` returns a normalised dict ready to become
an :class:`~apps.api.models.event.Event`.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class BaseParser:
    """Common interface every parser must implement."""

    name: str = "base"
    formats: list[str] = []
    priority: int = 50  # lower = tried first

    def can_parse(self, raw: str) -> bool:
        """Return *True* if this parser can handle *raw*."""
        return False

    def parse(self, raw: str) -> dict[str, Any] | None:
        """Parse *raw* into an intermediate dict.  Return ``None`` on failure."""
        return None

    def normalize(self, parsed: dict[str, Any], raw: str | None = None) -> dict[str, Any]:
        """Map *parsed* dict to unified Event-compatible dict."""
        now = datetime.now(UTC)
        return {
            "id": parsed.get("id") or str(uuid.uuid4()),
            "ts": parsed.get("ts") or parsed.get("timestamp") or now,
            "source": parsed.get("source", self.name),
            "event_type": parsed.get("event_type", "unknown"),
            "severity": _normalize_severity(parsed.get("severity", "low")),
            "src_ip": parsed.get("src_ip"),
            "dst_ip": parsed.get("dst_ip"),
            "username": parsed.get("username"),
            "message": parsed.get("message"),
            "raw": raw or parsed.get("raw"),
        }


# ---------------------------------------------------------------------------
# Severity helper (reused by all parsers)
# ---------------------------------------------------------------------------

def _normalize_severity(val: str | int | None) -> str:
    if val is None:
        return "low"
    if isinstance(val, int):
        if val >= 9:
            return "critical"
        if val >= 7:
            return "high"
        if val >= 4:
            return "medium"
        return "low"
    s = str(val).strip().lower()
    if s in ("critical", "fatal", "emergency", "emerg", "alert", "panic"):
        return "critical"
    if s in ("high", "error", "err", "severe"):
        return "high"
    if s in ("medium", "warning", "warn", "notice"):
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_registry: list[BaseParser] = []


def register(parser: BaseParser) -> None:
    """Add *parser* to the global registry, sorted by priority."""
    _registry.append(parser)
    _registry.sort(key=lambda p: p.priority)
    logger.debug("Parser registered: %s (priority %d)", parser.name, parser.priority)


def get_registry() -> list[BaseParser]:
    """Return the current ordered registry (read-only snapshot)."""
    return list(_registry)


# ---------------------------------------------------------------------------
# Detection & parsing
# ---------------------------------------------------------------------------

def detect(raw: str) -> BaseParser | None:
    """Return the first parser that can handle *raw*, or ``None``."""
    for parser in _registry:
        try:
            if parser.can_parse(raw):
                return parser
        except Exception:
            logger.exception("detect: parser %s raised", parser.name)
    return None


def detect_format(raw: str) -> str | None:
    """Return the *name* of the detected format, or ``None``."""
    p = detect(raw)
    return p.name if p else None


def parse_line(raw: str) -> dict[str, Any] | None:
    """Try every registered parser; return a normalised Event dict or ``None``."""
    for parser in _registry:
        try:
            if not parser.can_parse(raw):
                continue
            parsed = parser.parse(raw)
            if parsed is not None:
                return parser.normalize(parsed, raw=raw)
        except Exception:
            logger.exception("parse_line: parser %s failed", parser.name)
    return None


def parse_bulk(lines: list[str]) -> list[dict[str, Any]]:
    """Parse multiple lines, skipping unparseable ones."""
    results: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        result = parse_line(line)
        if result is not None:
            results.append(result)
    return results


def supported_formats() -> list[dict[str, Any]]:
    """Return metadata about every registered parser."""
    return [
        {"name": p.name, "formats": p.formats, "priority": p.priority}
        for p in _registry
    ]


# ---------------------------------------------------------------------------
# Auto-register all built-in parsers on import
# ---------------------------------------------------------------------------

def _init_parsers() -> None:
    """Import and register all built-in parsers."""
    from apps.api.parsers.apache import ApacheParser
    from apps.api.parsers.cef import CEFParser
    from apps.api.parsers.cloud import CloudLogParser
    from apps.api.parsers.csv_parser import CSVLogParser
    from apps.api.parsers.firewall import FirewallParser
    from apps.api.parsers.json_log import JSONLogParser
    from apps.api.parsers.leef import LEEFParser
    from apps.api.parsers.syslog_parser import SyslogParser
    from apps.api.parsers.windows_event import WindowsEventParser

    for cls in [
        CEFParser,
        LEEFParser,
        SyslogParser,
        WindowsEventParser,
        ApacheParser,
        FirewallParser,
        CloudLogParser,
        JSONLogParser,   # JSON last-ish — many formats embed JSON
        CSVLogParser,     # CSV is the most generic fallback
    ]:
        register(cls())


_init_parsers()
