"""Firewall log parser — multi-vendor support.

Supported formats:
- Palo Alto PAN-OS (CSV traffic/threat logs)
- Cisco ASA syslog
- iptables / nftables kernel log
- pfSense filterlog (CSV-based)
- Generic firewall (key=value)
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser

# ---------------------------------------------------------------------------
# Cisco ASA
# ---------------------------------------------------------------------------

# %ASA-LEVEL-MSGID: message
_ASA_RE = re.compile(
    r"(?:<\d{1,3}>)?.*?"
    r"%ASA-(\d)-(\d{6}):\s+(.*)",
    re.DOTALL,
)

_ASA_LEVEL_MAP = {
    "0": "critical", "1": "critical", "2": "critical", "3": "high",
    "4": "medium", "5": "low", "6": "low", "7": "low",
}

# Common ASA message IDs
_ASA_MSG_MAP = {
    "106001": "network.allowed",     # Inbound TCP connection permitted
    "106006": "network.blocked",     # Deny inbound UDP
    "106007": "network.blocked",     # Deny inbound UDP (DNS)
    "106014": "network.blocked",     # Deny inbound icmp
    "106015": "network.blocked",     # Deny inbound TCP (no connection)
    "106023": "network.blocked",     # Deny by access-group
    "106100": "network.acl",         # ACL permitted/denied
    "302013": "network.connection",  # Built inbound TCP connection
    "302014": "network.teardown",    # Teardown TCP connection
    "302015": "network.connection",  # Built inbound UDP connection
    "302016": "network.teardown",    # Teardown UDP connection
    "305011": "network.nat",         # NAT translation
    "313001": "network.blocked",     # Denied ICMP
    "710003": "auth.fail",           # AAA authentication failed
    "113004": "auth.success",        # AAA authentication successful
    "113005": "auth.fail",           # AAA authentication rejected
}

_ASA_IP_RE = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/(\d+))?")


def _parse_asa(raw: str) -> dict[str, Any] | None:
    m = _ASA_RE.search(raw)
    if not m:
        return None

    level = m.group(1)
    msg_id = m.group(2)
    message = m.group(3)

    ips = _ASA_IP_RE.findall(message)
    src_ip = ips[0][0] if ips else None
    dst_ip = ips[1][0] if len(ips) > 1 else None

    event_type = _ASA_MSG_MAP.get(msg_id, "firewall.event")
    if "deny" in message.lower() or "denied" in message.lower():
        event_type = "network.blocked"
    elif "permit" in message.lower() or "built" in message.lower():
        event_type = "network.allowed"

    user_m = re.search(r"user '?(\S+?)'?(?:\s|$)", message, re.I)

    return {
        "ts": datetime.now(UTC),
        "source": "firewall:cisco_asa",
        "event_type": event_type,
        "severity": _ASA_LEVEL_MAP.get(level, "low"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": user_m.group(1) if user_m else None,
        "message": message.strip(),
        "raw": raw,
        "_fw_type": "cisco_asa",
        "_msg_id": msg_id,
    }


# ---------------------------------------------------------------------------
# iptables / nftables
# ---------------------------------------------------------------------------

_IPTABLES_RE = re.compile(
    r"(?:<\d{1,3}>)?.*?"
    r"(?:kernel:|iptables|nftables|netfilter)\s*:?\s*(.*)",
    re.I,
)

_IPT_KV_RE = re.compile(r"(\w+)=(\S+)")


def _parse_iptables(raw: str) -> dict[str, Any] | None:
    m = _IPTABLES_RE.search(raw)
    if not m:
        return None
    msg = m.group(1)

    fields: dict[str, str] = {}
    for kv in _IPT_KV_RE.finditer(msg):
        fields[kv.group(1)] = kv.group(2)

    if not fields.get("SRC") and not fields.get("PROTO"):
        return None  # Not really iptables

    action_prefix = ""
    for marker in ("DROP", "REJECT", "BLOCK", "DENY"):
        if marker in raw.upper():
            action_prefix = "blocked"
            break
    if not action_prefix:
        for marker in ("ACCEPT", "ALLOW"):
            if marker in raw.upper():
                action_prefix = "allowed"
                break
    if not action_prefix:
        action_prefix = "event"

    return {
        "ts": datetime.now(UTC),
        "source": "firewall:iptables",
        "event_type": f"network.{action_prefix}",
        "severity": "medium" if action_prefix == "blocked" else "low",
        "src_ip": fields.get("SRC"),
        "dst_ip": fields.get("DST"),
        "username": None,
        "message": msg.strip(),
        "raw": raw,
        "_fw_type": "iptables",
        "_proto": fields.get("PROTO"),
        "_spt": fields.get("SPT"),
        "_dpt": fields.get("DPT"),
        "_in": fields.get("IN"),
        "_out": fields.get("OUT"),
        "_mac": fields.get("MAC"),
        "_fields": fields,
    }


# ---------------------------------------------------------------------------
# Palo Alto PAN-OS (CSV traffic log)
# ---------------------------------------------------------------------------

# PAN traffic log has many fields; we pick the important ones by position
# Field positions (0-indexed) for TRAFFIC type:
#   1=receive_time, 3=type, 4=subtype, 7=src_ip, 8=dst_ip,
#   14=src_port, 15=dst_port, 29=action, 31=bytes_sent, 32=bytes_received
#   6=src_zone, 7=dst_zone

_PAN_TYPE_RE = re.compile(r"^(?:\d+,){2}\d{4}/\d{2}/\d{2}", re.M)


def _parse_panos(raw: str) -> dict[str, Any] | None:
    parts = raw.split(",")
    if len(parts) < 30:
        return None

    # Validate it looks like PAN-OS
    log_type = parts[3].strip() if len(parts) > 3 else ""
    if log_type not in ("TRAFFIC", "THREAT", "SYSTEM", "CONFIG", "HIP-MATCH", "URL"):
        return None

    try:
        ts_str = parts[1].strip()
        ts = None
        for fmt in ("%Y/%m/%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                ts = datetime.strptime(ts_str, fmt).replace(tzinfo=UTC)
                break
            except ValueError:
                continue
    except (IndexError, ValueError):
        ts = None

    src_ip = parts[7].strip() if len(parts) > 7 else None
    dst_ip = parts[8].strip() if len(parts) > 8 else None
    action = parts[29].strip().lower() if len(parts) > 29 else ""

    if "deny" in action or "drop" in action or "block" in action or "reset" in action:
        event_type = "network.blocked"
        severity = "medium"
    elif "allow" in action:
        event_type = "network.allowed"
        severity = "low"
    elif log_type == "THREAT":
        event_type = "ids.alert"
        severity = "high"
    else:
        event_type = f"firewall.{log_type.lower()}"
        severity = "low"

    subtype = parts[4].strip() if len(parts) > 4 else ""

    return {
        "ts": ts or datetime.now(UTC),
        "source": "firewall:paloalto",
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": parts[12].strip() if len(parts) > 12 and parts[12].strip() else None,
        "message": f"PAN-OS {log_type}/{subtype} action={action}",
        "raw": raw,
        "_fw_type": "paloalto",
        "_log_type": log_type,
        "_subtype": subtype,
        "_action": action,
    }


# ---------------------------------------------------------------------------
# pfSense filterlog (comma-separated)
# ---------------------------------------------------------------------------

_PFSENSE_RE = re.compile(r"filterlog\[\d+\]:\s*(.*)")


def _parse_pfsense(raw: str) -> dict[str, Any] | None:
    m = _PFSENSE_RE.search(raw)
    if not m:
        return None
    csv_part = m.group(1)
    parts = csv_part.split(",")
    if len(parts) < 20:
        return None

    # pfSense filterlog CSV:
    # rulenum,subrulenum,anchor,tracker,interface,reason,action,direction,ipversion,...
    action = parts[6].strip().lower() if len(parts) > 6 else ""
    direction = parts[7].strip() if len(parts) > 7 else ""
    ip_version = parts[8].strip() if len(parts) > 8 else "4"

    if ip_version == "4" and len(parts) > 19:
        proto = parts[16].strip()
        src_ip = parts[18].strip()
        dst_ip = parts[19].strip()
    elif ip_version == "6" and len(parts) > 19:
        proto = parts[12].strip()
        src_ip = parts[15].strip()
        dst_ip = parts[16].strip()
    else:
        proto = ""
        src_ip = None
        dst_ip = None

    if "block" in action or "reject" in action:
        event_type = "network.blocked"
        severity = "medium"
    else:
        event_type = "network.allowed"
        severity = "low"

    return {
        "ts": datetime.now(UTC),
        "source": "firewall:pfsense",
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": None,
        "message": f"pfSense {action} {direction} {proto}",
        "raw": raw,
        "_fw_type": "pfsense",
        "_action": action,
        "_direction": direction,
        "_proto": proto,
    }


# ---------------------------------------------------------------------------
# Generic firewall (key=value patterns)
# ---------------------------------------------------------------------------

_GENERIC_FW_KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _parse_generic_fw(raw: str) -> dict[str, Any] | None:
    fields: dict[str, str] = {}
    for m in _GENERIC_FW_KV_RE.finditer(raw):
        key = m.group(1)
        val = m.group(2).strip('"')
        fields[key] = val

    # Must have some network-related keys
    network_keys = {"src", "dst", "srcip", "dstip", "action", "proto",
                    "src_ip", "dst_ip", "srcaddr", "dstaddr", "sport", "dport"}
    if len({k.lower() for k in fields} & network_keys) < 2:
        return None

    src_ip = fields.get("src") or fields.get("srcip") or fields.get("src_ip") or fields.get("srcaddr")
    dst_ip = fields.get("dst") or fields.get("dstip") or fields.get("dst_ip") or fields.get("dstaddr")
    action = (fields.get("action") or fields.get("act") or "").lower()

    if any(w in action for w in ("deny", "drop", "block", "reject")):
        event_type = "network.blocked"
        severity = "medium"
    elif any(w in action for w in ("allow", "permit", "accept")):
        event_type = "network.allowed"
        severity = "low"
    else:
        event_type = "firewall.event"
        severity = "low"

    username = fields.get("user") or fields.get("srcuser") or fields.get("username")

    return {
        "ts": datetime.now(UTC),
        "source": "firewall:generic",
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": username,
        "message": action or raw[:200],
        "raw": raw,
        "_fw_type": "generic",
        "_fields": fields,
    }


# ---------------------------------------------------------------------------
# Main parser — tries each sub-parser in order
# ---------------------------------------------------------------------------

class FirewallParser(BaseParser):
    name = "firewall"
    formats = ["Cisco ASA", "Palo Alto PAN-OS", "iptables/nftables", "pfSense", "Generic firewall"]
    priority = 25

    def can_parse(self, raw: str) -> bool:
        if "%ASA-" in raw:
            return True
        if "filterlog[" in raw:
            return True
        if any(kw in raw for kw in ("iptables", "nftables", "netfilter")):
            return True
        if any(kw in raw.upper() for kw in ("IN=", "OUT=", "SRC=", "DST=")):
            if "PROTO=" in raw.upper():
                return True
        # PAN-OS CSV heuristic
        parts = raw.split(",")
        return bool(len(parts) > 30 and parts[3].strip() in ("TRAFFIC", "THREAT", "SYSTEM", "URL"))

    def parse(self, raw: str) -> dict[str, Any] | None:
        if "%ASA-" in raw:
            return _parse_asa(raw)

        if "filterlog[" in raw:
            return _parse_pfsense(raw)

        # iptables check
        if any(kw in raw.lower() for kw in ("iptables", "nftables", "netfilter")) or (
            "SRC=" in raw and "DST=" in raw and "PROTO=" in raw
        ):
            result = _parse_iptables(raw)
            if result:
                return result

        # PAN-OS
        parts = raw.split(",")
        if len(parts) > 30:
            result = _parse_panos(raw)
            if result:
                return result

        # Generic firewall (key=value)
        return _parse_generic_fw(raw)
