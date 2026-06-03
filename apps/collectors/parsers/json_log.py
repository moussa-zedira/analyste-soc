"""Parser pour logs au format JSON generique."""

from __future__ import annotations

import json

from apps.collectors.normalizer import NormalizedEvent


class JsonLogParser:
    name = "json_log"

    def can_parse(self, line: str) -> bool:
        stripped = line.strip()
        return stripped.startswith("{") and stripped.endswith("}")

    def parse(self, line: str) -> NormalizedEvent | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        if not isinstance(data, dict):
            return None

        # Extract common fields with fallbacks
        source = data.get("source") or data.get("hostname") or data.get("host") or "json"
        event_type = (
            data.get("event_type") or data.get("type") or data.get("action") or "system.info"
        )
        severity = _normalize_severity(
            data.get("severity") or data.get("level") or data.get("priority") or "low"
        )
        src_ip = data.get("src_ip") or data.get("source_ip") or data.get("client_ip")
        dst_ip = data.get("dst_ip") or data.get("dest_ip") or data.get("server_ip")
        username = data.get("username") or data.get("user") or data.get("actor")
        message = data.get("message") or data.get("msg") or data.get("description")

        return NormalizedEvent(
            source=f"json:{source}",
            event_type=str(event_type),
            severity=severity,
            src_ip=str(src_ip) if src_ip else None,
            dst_ip=str(dst_ip) if dst_ip else None,
            username=str(username) if username else None,
            message=str(message) if message else None,
            raw=line,
        )


def _normalize_severity(val: str | int) -> str:
    if isinstance(val, int):
        if val >= 8:
            return "critical"
        if val >= 5:
            return "high"
        if val >= 3:
            return "medium"
        return "low"

    s = str(val).lower()
    if s in ("critical", "fatal", "emergency", "alert"):
        return "critical"
    if s in ("high", "error", "err"):
        return "high"
    if s in ("medium", "warning", "warn"):
        return "medium"
    return "low"
