"""Windows Event Log parser — EVTX XML format.

Features:
- Full EVTX XML parsing (namespaced and non-namespaced)
- Comprehensive event ID mapping with MITRE ATT&CK technique references
- Security / System / Application / PowerShell log support
- PowerShell script block logging (event 4104)
- Logon type decoding (event 4624/4625)
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from typing import Any

from apps.api.parsers import BaseParser

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

# ---------------------------------------------------------------------------
# Event ID → (event_type, default_severity, description, mitre_technique)
# ---------------------------------------------------------------------------

_EVENT_ID_MAP: dict[str, tuple[str, str, str, str | None]] = {
    # Authentication / Logon
    "4624": ("auth.success", "low", "Successful logon", "T1078"),
    "4625": ("auth.fail", "medium", "Failed logon", "T1110"),
    "4634": ("auth.logoff", "low", "Logoff", None),
    "4647": ("auth.logoff", "low", "User-initiated logoff", None),
    "4648": ("auth.explicit", "medium", "Logon with explicit credentials", "T1078"),
    "4768": ("auth.kerberos_tgt", "low", "Kerberos TGT requested", None),
    "4769": ("auth.kerberos_svc", "low", "Kerberos service ticket requested", "T1558"),
    "4771": ("auth.kerberos_fail", "medium", "Kerberos pre-auth failed", "T1110"),
    "4776": ("auth.ntlm", "low", "NTLM authentication", "T1110"),
    # Account management
    "4720": ("account.created", "medium", "User account created", "T1136"),
    "4722": ("account.enabled", "medium", "User account enabled", None),
    "4723": ("account.password_change", "low", "Password change attempted", None),
    "4724": ("account.password_reset", "medium", "Password reset attempted", "T1098"),
    "4725": ("account.disabled", "medium", "User account disabled", None),
    "4726": ("account.deleted", "medium", "User account deleted", None),
    "4738": ("account.modified", "medium", "User account changed", "T1098"),
    "4740": ("account.locked", "medium", "Account locked out", "T1110"),
    # Group management
    "4728": ("group.member_added", "medium", "Member added to global group", "T1098"),
    "4732": ("group.member_added", "medium", "Member added to local group", "T1098"),
    "4756": ("group.member_added", "medium", "Member added to universal group", "T1098"),
    "4729": ("group.member_removed", "medium", "Member removed from global group", None),
    "4733": ("group.member_removed", "medium", "Member removed from local group", None),
    # Privilege
    "4672": ("priv.escalation", "high", "Special privileges assigned", "T1078"),
    "4673": ("priv.service_call", "medium", "Privileged service called", None),
    # Process
    "4688": ("process.created", "low", "New process created", "T1059"),
    "4689": ("process.terminated", "low", "Process exited", None),
    # Service
    "7045": ("service.installed", "medium", "New service installed", "T1543.003"),
    "4697": ("service.installed", "medium", "Service installed", "T1543.003"),
    "7036": ("service.state_change", "low", "Service state changed", None),
    "7040": ("service.config_change", "medium", "Service start type changed", "T1543.003"),
    # Audit
    "1102": ("audit.log_cleared", "high", "Audit log cleared", "T1070.001"),
    "4719": ("audit.policy_changed", "high", "Audit policy changed", "T1562.002"),
    # Scheduled tasks
    "4698": ("task.created", "medium", "Scheduled task created", "T1053.005"),
    "4699": ("task.deleted", "low", "Scheduled task deleted", None),
    "4702": ("task.updated", "medium", "Scheduled task updated", "T1053.005"),
    # Registry
    "4657": ("registry.modified", "medium", "Registry value modified", "T1112"),
    # File / share
    "5140": ("share.accessed", "low", "Network share accessed", "T1021.002"),
    "5145": ("share.file_accessed", "low", "Shared file accessed", "T1021.002"),
    # Firewall
    "5152": ("network.blocked", "medium", "Windows Filtering Platform blocked", None),
    "5156": ("network.allowed", "low", "Windows Filtering Platform allowed", None),
    "5157": ("network.blocked", "medium", "WFP connection blocked", None),
    # PowerShell
    "4104": ("powershell.script_block", "high", "PowerShell script block", "T1059.001"),
    "4103": ("powershell.module_log", "medium", "PowerShell module logging", "T1059.001"),
    "400": ("powershell.engine_start", "low", "PowerShell engine started", None),
    "403": ("powershell.engine_stop", "low", "PowerShell engine stopped", None),
    # WMI
    "5861": ("wmi.subscription", "high", "WMI event subscription", "T1546.003"),
    # Remote access
    "4778": ("rdp.session_reconnect", "low", "RDP session reconnected", "T1021.001"),
    "4779": ("rdp.session_disconnect", "low", "RDP session disconnected", None),
    # Object access
    "4663": ("object.accessed", "low", "Object access attempted", "T1005"),
    "4656": ("object.handle_requested", "low", "Handle to object requested", None),
    # DNS
    "770": ("dns.query", "low", "DNS query", None),
    # Defender
    "1116": ("defender.detected", "high", "Defender detected malware", "T1059"),
    "1117": ("defender.action", "high", "Defender took action", None),
}

# Logon types
_LOGON_TYPE_MAP = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
    "12": "CachedRemoteInteractive",
    "13": "CachedUnlock",
}

_LEVEL_MAP = {
    "1": "critical",
    "2": "high",
    "3": "medium",
    "4": "low",
    "5": "low",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find(el: ET.Element | None, tag: str) -> ET.Element | None:
    if el is None:
        return None
    return el.find(f"e:{tag}", _NS) or el.find(tag)


def _find_text(el: ET.Element | None, tag: str, default: str = "") -> str:
    child = _find(el, tag)
    return child.text if child is not None and child.text else default


def _extract_event_data(root: ET.Element) -> dict[str, str]:
    """Extract Data elements from EventData or UserData."""
    fields: dict[str, str] = {}
    for section_tag in ("EventData", "UserData"):
        section = root.find(f"e:{section_tag}", _NS) or root.find(section_tag)
        if section is None:
            continue
        for el in section.iter():
            name = el.get("Name", "")
            if name and el.text:
                fields[name] = el.text
            elif el.tag.split("}")[-1] not in (section_tag,) and el.text:
                fields[el.tag.split("}")[-1]] = el.text
    return fields


def _parse_xml_timestamp(ts_str: str) -> datetime | None:
    if not ts_str:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class WindowsEventParser(BaseParser):
    name = "windows_event"
    formats = ["EVTX XML", "Windows Event Log"]
    priority = 15

    def can_parse(self, raw: str) -> bool:
        return "<Event " in raw or "<Event>" in raw

    def parse(self, raw: str) -> dict[str, Any] | None:
        try:
            root = ET.fromstring(raw.strip())
        except ET.ParseError:
            return None

        system = root.find("e:System", _NS) or root.find("System")
        if system is None:
            return None

        event_id = _find_text(system, "EventID", "0")
        level = _find_text(system, "Level", "4")
        computer = _find_text(system, "Computer", "unknown")
        channel = _find_text(system, "Channel", "System")
        provider_el = _find(system, "Provider")
        provider = provider_el.get("Name", "") if provider_el is not None else ""

        # Timestamp
        time_el = _find(system, "TimeCreated")
        ts_str = time_el.get("SystemTime", "") if time_el is not None else ""
        ts = _parse_xml_timestamp(ts_str) or datetime.now(UTC)

        # Event data
        fields = _extract_event_data(root)

        # Map event ID
        if event_id in _EVENT_ID_MAP:
            event_type, severity, description, mitre = _EVENT_ID_MAP[event_id]
        else:
            event_type = f"winlog.{event_id}"
            severity = _LEVEL_MAP.get(level, "low")
            description = f"Windows Event {event_id}"
            mitre = None

        # Enrich specific events
        src_ip = fields.get("IpAddress") or fields.get("SourceAddress")
        dst_ip = fields.get("DestAddress") or fields.get("DestinationAddress")
        username = fields.get("TargetUserName") or fields.get("SubjectUserName")
        domain = fields.get("TargetDomainName") or fields.get("SubjectDomainName")

        # Build enriched message
        msg_parts = [description]
        if username:
            full_user = f"{domain}\\{username}" if domain and domain != "-" else username
            msg_parts.append(f"user={full_user}")
        logon_type = fields.get("LogonType")
        if logon_type and event_id in ("4624", "4625"):
            lt_name = _LOGON_TYPE_MAP.get(logon_type, logon_type)
            msg_parts.append(f"logon_type={lt_name}")

        # PowerShell script block
        script_block = fields.get("ScriptBlockText")
        if script_block and event_id == "4104":
            msg_parts.append(f"script_block={script_block[:500]}")

        # Process creation
        process_name = fields.get("NewProcessName") or fields.get("ProcessName")
        cmd_line = fields.get("CommandLine")
        if process_name:
            msg_parts.append(f"process={process_name}")
        if cmd_line:
            msg_parts.append(f"cmdline={cmd_line[:300]}")

        message = " | ".join(msg_parts)

        return {
            "ts": ts,
            "source": f"winlog:{computer}/{channel}",
            "event_type": event_type,
            "severity": severity,
            "src_ip": src_ip if src_ip and src_ip != "-" else None,
            "dst_ip": dst_ip if dst_ip and dst_ip != "-" else None,
            "username": username if username and username != "-" else None,
            "message": message,
            "raw": raw,
            "_event_id": event_id,
            "_channel": channel,
            "_computer": computer,
            "_provider": provider,
            "_mitre": mitre,
            "_logon_type": _LOGON_TYPE_MAP.get(logon_type or "", logon_type),
            "_fields": fields,
        }
