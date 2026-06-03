"""Parser Windows Event Log XML."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from apps.collectors.normalizer import NormalizedEvent

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

_LEVEL_MAP = {
    "1": "critical",  # Critical
    "2": "high",  # Error
    "3": "medium",  # Warning
    "4": "low",  # Information
    "5": "low",  # Verbose
}

_EVENT_ID_MAP = {
    "4625": ("auth.fail", "medium"),
    "4624": ("auth.success", "low"),
    "4672": ("priv.escalation", "high"),
    "4648": ("auth.explicit", "medium"),
    "4720": ("account.created", "medium"),
    "4726": ("account.deleted", "medium"),
    "4732": ("group.member_added", "medium"),
    "4733": ("group.member_removed", "medium"),
    "1102": ("audit.log_cleared", "high"),
    "7045": ("service.installed", "medium"),
    "4688": ("process.created", "low"),
    "4697": ("service.installed", "medium"),
}


class WindowsXmlParser:
    name = "windows_xml"

    def can_parse(self, line: str) -> bool:
        return "<Event " in line or "<Event>" in line

    def parse(self, line: str) -> NormalizedEvent | None:
        try:
            root = ET.fromstring(line.strip())
        except ET.ParseError:
            return None

        # Handle namespaced or non-namespaced
        system = root.find("e:System", _NS) or root.find("System")
        if system is None:
            return None

        event_id_el = system.find("e:EventID", _NS) or system.find("EventID")
        event_id = event_id_el.text if event_id_el is not None else "0"

        level_el = system.find("e:Level", _NS) or system.find("Level")
        level = level_el.text if level_el is not None else "4"

        computer_el = system.find("e:Computer", _NS) or system.find("Computer")
        computer = computer_el.text if computer_el is not None else "unknown"

        channel_el = system.find("e:Channel", _NS) or system.find("Channel")
        channel = channel_el.text if channel_el is not None else "System"

        # Get event type and severity from mapping
        if event_id in _EVENT_ID_MAP:
            event_type, severity = _EVENT_ID_MAP[event_id]
        else:
            event_type = f"winlog.{event_id}"
            severity = _LEVEL_MAP.get(level, "low")

        # Extract data from EventData
        event_data = root.find("e:EventData", _NS) or root.find("EventData")
        fields: dict[str, str] = {}
        if event_data is not None:
            for data_el in event_data:
                name = data_el.get("Name", "")
                if name and data_el.text:
                    fields[name] = data_el.text

        src_ip = fields.get("IpAddress") or fields.get("SourceAddress")
        username = fields.get("TargetUserName") or fields.get("SubjectUserName")
        message = fields.get("Message") or f"Windows Event {event_id}"

        return NormalizedEvent(
            source=f"winlog:{computer}/{channel}",
            event_type=event_type,
            severity=severity,
            src_ip=src_ip if src_ip and src_ip != "-" else None,
            username=username if username and username != "-" else None,
            message=message,
            raw=line,
        )
