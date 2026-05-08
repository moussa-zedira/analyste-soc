"""JSON log parser — auto-detects common JSON log formats.

Supported schemas:
- Elastic Common Schema (ECS) / Filebeat
- AWS CloudTrail (JSON records)
- Azure Activity Log
- GCP Audit Log
- Generic key/value JSON
- Nested field extraction via dot-notation (e.g. ``source.ip``)
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser, _normalize_severity

# ---------------------------------------------------------------------------
# Dot-notation helper
# ---------------------------------------------------------------------------

def _deep_get(data: dict, dotpath: str, default: Any = None) -> Any:
    """Retrieve a nested value using ``a.b.c`` notation."""
    keys = dotpath.split(".")
    cur: Any = data
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        elif isinstance(cur, (list, tuple)) and k.isdigit():
            idx = int(k)
            cur = cur[idx] if idx < len(cur) else None
        else:
            return default
        if cur is None:
            return default
    return cur


# ---------------------------------------------------------------------------
# Timestamp normalisation
# ---------------------------------------------------------------------------

_EPOCH_RE = re.compile(r"^\d{10,13}$")

_TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %H:%M:%S",
)


def _parse_ts(raw: Any) -> datetime | None:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        if raw > 1e12:  # millis
            raw = raw / 1000
        return datetime.fromtimestamp(raw, tz=UTC)
    s = str(raw).strip()
    if _EPOCH_RE.match(s):
        v = int(s)
        if v > 1e12:
            v = v / 1000
        return datetime.fromtimestamp(v, tz=UTC)
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Format detection helpers
# ---------------------------------------------------------------------------

def _is_ecs(data: dict) -> bool:
    return "ecs" in data or "ecs.version" in data or "event" in data and isinstance(data.get("event"), dict)


def _is_cloudtrail(data: dict) -> bool:
    return "eventSource" in data and "awsRegion" in data


def _is_azure_activity(data: dict) -> bool:
    return "operationName" in data and ("resourceId" in data or "tenantId" in data)


def _is_gcp_audit(data: dict) -> bool:
    return "protoPayload" in data or ("logName" in data and "resource" in data)


# ---------------------------------------------------------------------------
# Format-specific extractors
# ---------------------------------------------------------------------------

def _extract_ecs(data: dict) -> dict[str, Any]:
    event = data.get("event", {}) if isinstance(data.get("event"), dict) else {}
    source_obj = data.get("source", {}) if isinstance(data.get("source"), dict) else {}
    dest_obj = data.get("destination", {}) if isinstance(data.get("destination"), dict) else {}
    user_obj = data.get("user", {}) if isinstance(data.get("user"), dict) else {}

    return {
        "ts": _parse_ts(
            _deep_get(data, "@timestamp")
            or _deep_get(data, "event.created")
            or _deep_get(data, "timestamp")
        ),
        "source": _deep_get(data, "agent.name") or _deep_get(data, "host.name") or "ecs",
        "event_type": event.get("action") or event.get("category") or event.get("kind") or "ecs.event",
        "severity": event.get("severity") or event.get("risk_score") or "low",
        "src_ip": source_obj.get("ip") or _deep_get(data, "source.ip") or _deep_get(data, "client.ip"),
        "dst_ip": dest_obj.get("ip") or _deep_get(data, "destination.ip") or _deep_get(data, "server.ip"),
        "username": user_obj.get("name") or _deep_get(data, "user.name"),
        "message": data.get("message") or event.get("original"),
    }


def _extract_cloudtrail(data: dict) -> dict[str, Any]:
    user_identity = data.get("userIdentity", {})
    return {
        "ts": _parse_ts(data.get("eventTime")),
        "source": f"cloudtrail:{data.get('eventSource', 'aws')}",
        "event_type": f"aws.{data.get('eventName', 'unknown')}",
        "severity": "high" if data.get("errorCode") else "low",
        "src_ip": data.get("sourceIPAddress"),
        "dst_ip": None,
        "username": user_identity.get("userName") or user_identity.get("arn"),
        "message": data.get("eventName"),
    }


def _extract_azure(data: dict) -> dict[str, Any]:
    return {
        "ts": _parse_ts(data.get("time") or data.get("eventTimestamp")),
        "source": f"azure:{data.get('resourceProviderName', {}).get('value', 'azure') if isinstance(data.get('resourceProviderName'), dict) else data.get('resourceProviderName', 'azure')}",
        "event_type": f"azure.{data.get('operationName', 'unknown')}",
        "severity": _normalize_severity(data.get("level", "low")),
        "src_ip": _deep_get(data, "httpRequest.clientIpAddress") or _deep_get(data, "callerIpAddress"),
        "dst_ip": None,
        "username": _deep_get(data, "caller") or _deep_get(data, "identity.claims.name"),
        "message": _deep_get(data, "properties.message") or data.get("operationName"),
    }


def _extract_gcp(data: dict) -> dict[str, Any]:
    proto = data.get("protoPayload", {})
    return {
        "ts": _parse_ts(data.get("timestamp") or _deep_get(data, "receiveTimestamp")),
        "source": f"gcp:{_deep_get(data, 'resource.type') or 'gcp'}",
        "event_type": f"gcp.{proto.get('methodName', 'unknown')}",
        "severity": _normalize_severity(data.get("severity", "low")),
        "src_ip": _deep_get(proto, "requestMetadata.callerIp"),
        "dst_ip": None,
        "username": _deep_get(proto, "authenticationInfo.principalEmail"),
        "message": _deep_get(proto, "status.message") or proto.get("methodName"),
    }


def _extract_generic(data: dict) -> dict[str, Any]:
    ts_raw = (
        data.get("timestamp") or data.get("ts") or data.get("time")
        or data.get("@timestamp") or data.get("datetime") or data.get("date")
    )
    source = (
        data.get("source") or data.get("hostname") or data.get("host")
        or data.get("log_source") or "json"
    )
    if isinstance(source, dict):
        source = source.get("name") or source.get("ip") or "json"
    event_type = (
        data.get("event_type") or data.get("type") or data.get("action")
        or data.get("eventType") or data.get("event") or "system.info"
    )
    severity = (
        data.get("severity") or data.get("level") or data.get("priority")
        or data.get("risk") or "low"
    )
    src_ip = (
        data.get("src_ip") or data.get("source_ip") or data.get("client_ip")
        or data.get("srcip") or data.get("remote_addr") or _deep_get(data, "source.ip")
    )
    dst_ip = (
        data.get("dst_ip") or data.get("dest_ip") or data.get("server_ip")
        or data.get("dstip") or _deep_get(data, "destination.ip")
    )
    username = (
        data.get("username") or data.get("user") or data.get("actor")
        or data.get("userName") or _deep_get(data, "user.name")
    )
    message = (
        data.get("message") or data.get("msg") or data.get("description")
        or data.get("summary") or data.get("text")
    )
    return {
        "ts": _parse_ts(ts_raw),
        "source": f"json:{source}",
        "event_type": str(event_type),
        "severity": severity,
        "src_ip": str(src_ip) if src_ip else None,
        "dst_ip": str(dst_ip) if dst_ip else None,
        "username": str(username) if username else None,
        "message": str(message) if message else None,
    }


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class JSONLogParser(BaseParser):
    name = "json_log"
    formats = ["JSON", "ECS", "CloudTrail", "Azure Activity", "GCP Audit"]
    priority = 70  # generic — try after specific parsers

    def can_parse(self, raw: str) -> bool:
        stripped = raw.strip()
        return stripped.startswith("{") and stripped.endswith("}")

    def parse(self, raw: str) -> dict[str, Any] | None:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None

        # Detect known formats
        if _is_cloudtrail(data):
            result = _extract_cloudtrail(data)
        elif _is_azure_activity(data):
            result = _extract_azure(data)
        elif _is_gcp_audit(data):
            result = _extract_gcp(data)
        elif _is_ecs(data):
            result = _extract_ecs(data)
        else:
            result = _extract_generic(data)

        result["raw"] = raw
        result["_json_data"] = data
        return result
