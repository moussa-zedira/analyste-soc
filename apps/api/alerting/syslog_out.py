"""Syslog forwarding — RFC 5424 + CEF format over TCP/UDP."""

from __future__ import annotations

import logging
import socket
import time
from typing import Any

logger = logging.getLogger(__name__)

# CEF severity mapping (0-10 scale)
_CEF_SEVERITY = {
    "low": 3,
    "medium": 5,
    "high": 7,
    "critical": 10,
}

# Syslog facility: local0 = 16, severity mapping for PRI calculation
_SYSLOG_SEVERITY = {
    "critical": 2,  # critical
    "high": 3,  # error
    "medium": 4,  # warning
    "low": 6,  # informational
}

FACILITY_LOCAL0 = 16


def _build_cef(incident: dict[str, Any]) -> str:
    """Build a CEF (Common Event Format) string.

    Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extensions
    """
    severity = incident.get("severity", "medium")
    cef_sev = _CEF_SEVERITY.get(severity, 5)

    # Escape CEF special chars in values
    def _esc(val: str) -> str:
        return str(val).replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=")

    extensions = " ".join(
        [
            f"src={_esc(incident.get('entity_key', 'N/A'))}",
            f"msg={_esc(incident.get('description', 'N/A')[:512])}",
            f"cs1={_esc(incident.get('rule_id', 'N/A'))}",
            "cs1Label=RuleID",
            f"cn1={incident.get('threat_score', 0)}",
            "cn1Label=ThreatScore",
            f"externalId={_esc(incident.get('id', 'N/A'))}",
        ]
    )

    return (
        f"CEF:0|CyberDef|SIEM|1.0"
        f"|{_esc(incident.get('rule_id', 'ALERT'))}|{_esc(incident.get('title', 'Security Alert'))}"
        f"|{cef_sev}|{extensions}"
    )


def _build_rfc5424(incident: dict[str, Any], hostname: str = "cyberdef-siem") -> str:
    """Build an RFC 5424 syslog message wrapping CEF content."""
    severity = incident.get("severity", "medium")
    syslog_sev = _SYSLOG_SEVERITY.get(severity, 6)
    pri = FACILITY_LOCAL0 * 8 + syslog_sev
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    app_name = "cyberdef-siem"
    proc_id = "-"
    msg_id = incident.get("id", "-") or "-"

    cef = _build_cef(incident)

    # RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
    return f"<{pri}>1 {timestamp} {hostname} {app_name} {proc_id} {msg_id} - {cef}"


async def send_alert(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Send a syslog message (CEF format) via TCP or UDP.

    Config keys:
        host: str — Syslog server hostname/IP
        port: int — Syslog server port (default 514)
        protocol: str — 'tcp' or 'udp' (default 'udp')
        hostname: str — Source hostname for syslog header (default: cyberdef-siem)
    """
    host = config.get("host", "")
    if not host:
        raise ValueError("No syslog host configured")

    port = int(config.get("port", 514))
    protocol = config.get("protocol", "udp").lower()
    hostname = config.get("hostname", "cyberdef-siem")

    message = _build_rfc5424(incident, hostname)
    encoded = message.encode("utf-8")

    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            if protocol == "tcp":
                # TCP: append newline delimiter
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                try:
                    sock.connect((host, port))
                    sock.sendall(encoded + b"\n")
                finally:
                    sock.close()
            else:
                # UDP
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(10)
                try:
                    sock.sendto(encoded, (host, port))
                finally:
                    sock.close()

            logger.info("Syslog alert sent to %s:%d via %s", host, port, protocol)
            return
        except Exception as exc:
            last_exc = exc
            logger.warning("Syslog attempt %d failed: %s", attempt + 1, exc)

    raise RuntimeError(f"Syslog send failed after 3 attempts: {last_exc}")
