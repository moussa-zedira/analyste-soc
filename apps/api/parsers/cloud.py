"""Cloud log parser — AWS, Azure, GCP.

Handles non-JSON cloud log formats:
- AWS VPC Flow Logs (space-delimited, v2–v5)
- AWS CloudTrail digest / non-JSON summary lines
- Azure NSG Flow Logs
- GCP VPC Flow Logs

Note: JSON-based cloud logs (CloudTrail JSON, Azure Activity JSON, GCP Audit JSON)
are handled by the json_log parser which auto-detects the schema.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser

# ---------------------------------------------------------------------------
# AWS VPC Flow Logs
# ---------------------------------------------------------------------------

# v2 default: version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
_VPC_FLOW_RE = re.compile(
    r"^(\d+)\s+"  # version
    r"(\S+)\s+"  # account-id
    r"(\S+)\s+"  # interface-id
    r"(\S+)\s+"  # srcaddr
    r"(\S+)\s+"  # dstaddr
    r"(\d+)\s+"  # srcport
    r"(\d+)\s+"  # dstport
    r"(\d+)\s+"  # protocol
    r"(\d+)\s+"  # packets
    r"(\d+)\s+"  # bytes
    r"(\d+)\s+"  # start (epoch)
    r"(\d+)\s+"  # end (epoch)
    r"(\w+)\s+"  # action (ACCEPT/REJECT)
    r"(\S+)"  # log-status
)

# Protocol numbers
_PROTO_MAP = {
    "1": "ICMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "132": "SCTP",
}


def _parse_vpc_flow(raw: str) -> dict[str, Any] | None:
    # Skip header line
    if raw.strip().startswith("version account-id") or raw.strip().startswith("version"):
        parts = raw.strip().split()
        if "srcaddr" in parts:
            return None

    m = _VPC_FLOW_RE.match(raw.strip())
    if not m:
        return None

    m.group(1)
    account_id = m.group(2)
    eni = m.group(3)
    src_addr = m.group(4)
    dst_addr = m.group(5)
    src_port = m.group(6)
    dst_port = m.group(7)
    protocol = m.group(8)
    packets = m.group(9)
    bytes_count = m.group(10)
    start_epoch = int(m.group(11))
    int(m.group(12))
    action = m.group(13)
    log_status = m.group(14)

    proto_name = _PROTO_MAP.get(protocol, protocol)
    ts = datetime.fromtimestamp(start_epoch, tz=UTC)

    if action == "REJECT":
        event_type = "network.blocked"
        severity = "medium"
    else:
        event_type = "network.allowed"
        severity = "low"

    # High-severity if traffic on sensitive ports is rejected
    sensitive_ports = {"22", "3389", "445", "139", "23", "1433", "3306", "5432"}
    if action == "REJECT" and (dst_port in sensitive_ports or src_port in sensitive_ports):
        severity = "high"

    return {
        "ts": ts,
        "source": f"aws:vpc:{account_id}/{eni}",
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_addr if src_addr != "-" else None,
        "dst_ip": dst_addr if dst_addr != "-" else None,
        "username": None,
        "message": f"VPC Flow {action} {proto_name} {src_addr}:{src_port} -> {dst_addr}:{dst_port} ({packets} pkts, {bytes_count} bytes)",
        "raw": raw,
        "_cloud": "aws",
        "_log_type": "vpc_flow",
        "_account_id": account_id,
        "_eni": eni,
        "_src_port": src_port,
        "_dst_port": dst_port,
        "_protocol": proto_name,
        "_packets": packets,
        "_bytes": bytes_count,
        "_action": action,
        "_log_status": log_status,
    }


# ---------------------------------------------------------------------------
# Azure NSG Flow Logs
# ---------------------------------------------------------------------------

# Format: rule_name,MAC,src_ip,dst_ip,src_port,dst_port,protocol,direction,action,(flow_state,pkts_s,bytes_s,pkts_d,bytes_d)
_AZURE_NSG_RE = re.compile(
    r"^(\S+),"  # rule name
    r"([0-9A-Fa-f]+),"  # MAC
    r"(\S+),"  # src_ip
    r"(\S+),"  # dst_ip
    r"(\d+),"  # src_port
    r"(\d+),"  # dst_port
    r"(\w),"  # protocol (T/U)
    r"(\w),"  # direction (I/O)
    r"(\w)"  # action (A/D)
)


def _parse_azure_nsg(raw: str) -> dict[str, Any] | None:
    m = _AZURE_NSG_RE.match(raw.strip())
    if not m:
        return None

    rule = m.group(1)
    src_ip = m.group(3)
    dst_ip = m.group(4)
    src_port = m.group(5)
    dst_port = m.group(6)
    protocol = "TCP" if m.group(7) == "T" else "UDP"
    direction = "Inbound" if m.group(8) == "I" else "Outbound"
    action = m.group(9)

    if action == "D":
        event_type = "network.blocked"
        severity = "medium"
    else:
        event_type = "network.allowed"
        severity = "low"

    return {
        "ts": datetime.now(UTC),
        "source": "azure:nsg",
        "event_type": event_type,
        "severity": severity,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": None,
        "message": f"NSG {rule} {action} {direction} {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
        "raw": raw,
        "_cloud": "azure",
        "_log_type": "nsg_flow",
        "_rule": rule,
        "_direction": direction,
        "_protocol": protocol,
        "_action": "Allow" if action == "A" else "Deny",
    }


# ---------------------------------------------------------------------------
# GCP VPC Flow Logs (text format, space-separated)
# ---------------------------------------------------------------------------

# connection.src_ip connection.src_port connection.dest_ip connection.dest_port connection.protocol ...
_GCP_FLOW_KV_RE = re.compile(r"(\w+(?:\.\w+)*)=(\S+)")


def _parse_gcp_flow(raw: str) -> dict[str, Any] | None:
    fields: dict[str, str] = {}
    for m in _GCP_FLOW_KV_RE.finditer(raw):
        fields[m.group(1)] = m.group(2)

    src_ip = fields.get("connection.src_ip") or fields.get("src_ip")
    dst_ip = fields.get("connection.dest_ip") or fields.get("dest_ip")
    if not src_ip and not dst_ip:
        return None

    # Must look like a GCP flow log
    if not any(k.startswith("connection.") for k in fields):
        return None

    src_port = fields.get("connection.src_port", "")
    dst_port = fields.get("connection.dest_port", "")
    protocol = fields.get("connection.protocol", "")

    return {
        "ts": datetime.now(UTC),
        "source": "gcp:vpc_flow",
        "event_type": "network.flow",
        "severity": "low",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "username": None,
        "message": f"GCP Flow {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
        "raw": raw,
        "_cloud": "gcp",
        "_log_type": "vpc_flow",
        "_fields": fields,
    }


# ---------------------------------------------------------------------------
# Main parser
# ---------------------------------------------------------------------------


class CloudLogParser(BaseParser):
    name = "cloud"
    formats = ["AWS VPC Flow Logs", "Azure NSG Flow Logs", "GCP VPC Flow Logs"]
    priority = 35

    def can_parse(self, raw: str) -> bool:
        stripped = raw.strip()
        # VPC Flow Logs
        if _VPC_FLOW_RE.match(stripped):
            return True
        # Azure NSG
        if _AZURE_NSG_RE.match(stripped):
            return True
        # GCP flow (key=value with connection.* keys)
        return bool("connection.src_ip=" in stripped or "connection.dest_ip=" in stripped)

    def parse(self, raw: str) -> dict[str, Any] | None:
        stripped = raw.strip()

        result = _parse_vpc_flow(stripped)
        if result:
            return result

        result = _parse_azure_nsg(stripped)
        if result:
            return result

        result = _parse_gcp_flow(stripped)
        if result:
            return result

        return None
