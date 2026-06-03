"""CSV / TSV log parser — auto-detect delimiter and header mapping.

Features:
- Auto-detect delimiter (comma, tab, pipe, semicolon)
- Header detection (first line as headers, or provide custom mapping)
- Configurable field mapping to Event model
- Handles quoted fields and embedded delimiters
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser, _normalize_severity

# ---------------------------------------------------------------------------
# Default field mapping — maps common CSV header names to Event fields
# ---------------------------------------------------------------------------

_TS_HEADERS = {
    "timestamp",
    "ts",
    "time",
    "datetime",
    "date",
    "event_time",
    "eventtime",
    "start_time",
    "created",
    "log_time",
    "@timestamp",
    "receive_time",
    "generated_time",
}

_SOURCE_HEADERS = {
    "source",
    "hostname",
    "host",
    "device",
    "log_source",
    "device_name",
    "appliance",
    "sensor",
}

_EVENT_TYPE_HEADERS = {
    "event_type",
    "type",
    "action",
    "event",
    "category",
    "eventtype",
    "event_name",
    "activity",
}

_SEVERITY_HEADERS = {
    "severity",
    "level",
    "priority",
    "risk",
    "sev",
    "threat_level",
    "risk_level",
}

_SRC_IP_HEADERS = {
    "src_ip",
    "source_ip",
    "srcip",
    "src",
    "client_ip",
    "source_address",
    "srcaddr",
    "remote_addr",
    "attacker_ip",
}

_DST_IP_HEADERS = {
    "dst_ip",
    "dest_ip",
    "dstip",
    "dst",
    "server_ip",
    "destination_address",
    "dstaddr",
    "target_ip",
}

_USER_HEADERS = {
    "username",
    "user",
    "actor",
    "account",
    "user_name",
    "src_user",
    "login",
    "userid",
    "subject",
}

_MSG_HEADERS = {
    "message",
    "msg",
    "description",
    "summary",
    "detail",
    "reason",
    "info",
    "text",
    "log_message",
}


def _find_header(headers: list[str], candidates: set[str]) -> int | None:
    """Return index of the first header matching *candidates*, or ``None``."""
    for i, h in enumerate(headers):
        if h.strip().lower().replace(" ", "_") in candidates:
            return i
    return None


# ---------------------------------------------------------------------------
# Delimiter detection
# ---------------------------------------------------------------------------

_DELIMITERS = [",", "\t", "|", ";"]


def _detect_delimiter(sample: str) -> str:
    """Guess the delimiter from a sample line."""
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters="".join(_DELIMITERS))
        return dialect.delimiter
    except csv.Error:
        pass
    # Fallback: most frequent candidate
    counts = {d: sample.count(d) for d in _DELIMITERS}
    best = max(counts, key=counts.get)  # type: ignore[arg-type]
    return best if counts[best] > 0 else ","


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class CSVLogParser(BaseParser):
    """Generic CSV/TSV log parser with auto-detection.

    Because CSV is extremely generic, this parser has low priority and
    stricter ``can_parse`` checks to avoid false positives.
    """

    name = "csv_log"
    formats = ["CSV", "TSV", "Pipe-separated", "Semicolon-separated"]
    priority = 90  # very generic — last resort

    def can_parse(self, raw: str) -> bool:
        stripped = raw.strip()
        # Reject JSON, XML, syslog, CEF, LEEF
        if stripped.startswith(("{", "<", "CEF:", "LEEF:")):
            return False
        if stripped.startswith("<") and ">" in stripped[:6]:
            return False

        # Must have at least 3 delimited fields
        delim = _detect_delimiter(stripped)
        parts = stripped.split(delim)
        return not len(parts) < 3

    def parse(self, raw: str) -> dict[str, Any] | None:
        return self.parse_with_headers(raw)

    def parse_with_headers(
        self,
        raw: str,
        headers: list[str] | None = None,
        delimiter: str | None = None,
        field_map: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Parse a CSV line.

        Parameters
        ----------
        raw : str
            The raw CSV line.
        headers : list[str] | None
            Column headers.  If ``None``, numeric indices are used.
        delimiter : str | None
            Explicit delimiter.  Auto-detected if ``None``.
        field_map : dict[str, str] | None
            Custom mapping ``{csv_header: event_field}``.
        """
        stripped = raw.strip()
        if not stripped:
            return None

        delim = delimiter or _detect_delimiter(stripped)

        try:
            reader = csv.reader(io.StringIO(stripped), delimiter=delim)
            row = next(reader)
        except (csv.Error, StopIteration):
            return None

        if len(row) < 2:
            return None

        # Build header list
        if headers is None:
            headers = [str(i) for i in range(len(row))]
        elif len(headers) < len(row):
            headers = headers + [str(i) for i in range(len(headers), len(row))]

        record: dict[str, str] = {}
        for i, val in enumerate(row):
            if i < len(headers):
                record[headers[i]] = val.strip()

        # If custom field_map provided, use it
        if field_map:
            return self._apply_custom_map(record, field_map, raw)

        # Auto-map using header name heuristics
        return self._auto_map(record, headers, raw)

    def _apply_custom_map(
        self, record: dict[str, str], field_map: dict[str, str], raw: str
    ) -> dict[str, Any]:
        mapped: dict[str, Any] = {"raw": raw}
        for csv_key, event_field in field_map.items():
            if csv_key in record:
                mapped[event_field] = record[csv_key]
        mapped.setdefault("source", "csv")
        mapped.setdefault("event_type", "csv.event")
        mapped.setdefault("severity", "low")
        return mapped

    def _auto_map(self, record: dict[str, str], headers: list[str], raw: str) -> dict[str, Any]:
        def _get(candidates: set[str]) -> str | None:
            idx = _find_header(headers, candidates)
            if idx is not None and idx < len(headers):
                key = headers[idx]
                val = record.get(key, "").strip()
                return val if val else None
            return None

        ts_raw = _get(_TS_HEADERS)
        ts = None
        if ts_raw:
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S %z",
            ):
                try:
                    ts = datetime.strptime(ts_raw, fmt)
                    if ts.tzinfo is None:
                        ts = ts.replace(tzinfo=UTC)
                    break
                except ValueError:
                    continue

        severity_raw = _get(_SEVERITY_HEADERS) or "low"

        return {
            "ts": ts or datetime.now(UTC),
            "source": f"csv:{_get(_SOURCE_HEADERS) or 'unknown'}",
            "event_type": _get(_EVENT_TYPE_HEADERS) or "csv.event",
            "severity": _normalize_severity(severity_raw),
            "src_ip": _get(_SRC_IP_HEADERS),
            "dst_ip": _get(_DST_IP_HEADERS),
            "username": _get(_USER_HEADERS),
            "message": _get(_MSG_HEADERS) or raw[:200],
            "raw": raw,
            "_record": record,
        }
