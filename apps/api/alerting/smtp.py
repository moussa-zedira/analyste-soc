"""Email alerts via SMTP — HTML templates, TLS/SSL, attachments."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from apps.api.config import get_settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTML email templates
# ---------------------------------------------------------------------------

_SEVERITY_BADGE = {
    "critical": "#EF4444",
    "high": "#F97316",
    "medium": "#EAB308",
    "low": "#3B82F6",
}

_BASE_TEMPLATE = """\
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;background:#f4f4f7;margin:0;padding:20px;">
<div style="max-width:600px;margin:auto;background:#ffffff;border-radius:8px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">
  <div style="background:{header_color};padding:20px 24px;">
    <h1 style="color:#fff;margin:0;font-size:18px;">{header_icon} {title}</h1>
  </div>
  <div style="padding:24px;">
    {body}
    <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
    <table style="width:100%;font-size:13px;color:#555;">
      <tr><td><strong>Severity:</strong></td><td><span style="background:{severity_color};color:#fff;padding:2px 10px;border-radius:3px;">{severity}</span></td></tr>
      <tr><td><strong>Rule:</strong></td><td>{rule_id}</td></tr>
      <tr><td><strong>Entity:</strong></td><td>{entity_key}</td></tr>
      <tr><td><strong>Incident ID:</strong></td><td>{incident_id}</td></tr>
      <tr><td><strong>Threat Score:</strong></td><td>{threat_score}</td></tr>
      <tr><td><strong>Timestamp:</strong></td><td>{timestamp}</td></tr>
    </table>
    {actions_html}
  </div>
  <div style="background:#f9fafb;padding:12px 24px;font-size:11px;color:#999;text-align:center;">
    Sent by CyberDef SIEM Alerting System
  </div>
</div>
</body>
</html>
"""

_INCIDENT_BODY = """\
<p style="color:#333;font-size:14px;">{description}</p>
"""

_THREAT_BODY = """\
<p style="color:#333;font-size:14px;">A threat has been detected that requires your attention.</p>
<p style="color:#333;font-size:14px;">{description}</p>
"""

_ANOMALY_BODY = """\
<p style="color:#333;font-size:14px;">An anomalous pattern has been identified in your environment.</p>
<p style="color:#333;font-size:14px;">{description}</p>
"""

_TEMPLATE_MAP = {
    "incident": ("Security Incident", _INCIDENT_BODY),
    "threat": ("Threat Detected", _THREAT_BODY),
    "anomaly": ("Anomaly Detected", _ANOMALY_BODY),
}


def _build_html(incident: dict[str, Any]) -> str:
    severity = incident.get("severity", "medium")
    sev_color = _SEVERITY_BADGE.get(severity, "#808080")
    alert_type = incident.get("alert_type", "incident")
    header_title, body_tpl = _TEMPLATE_MAP.get(alert_type, _TEMPLATE_MAP["incident"])

    actions = incident.get("recommended_actions", [])
    actions_html = ""
    if actions:
        items = "".join(f"<li>{a}</li>" for a in actions)
        actions_html = (
            '<div style="margin-top:16px;"><strong>Recommended Actions:</strong>'
            f'<ul style="color:#333;">{items}</ul></div>'
        )

    icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}

    return _BASE_TEMPLATE.format(
        header_color=sev_color,
        header_icon=icons.get(severity, "⚪"),
        title=incident.get("title", header_title),
        body=body_tpl.format(description=incident.get("description", "N/A")),
        severity_color=sev_color,
        severity=severity.upper(),
        rule_id=incident.get("rule_id", "N/A"),
        entity_key=incident.get("entity_key", "N/A"),
        incident_id=incident.get("id", "N/A"),
        threat_score=incident.get("threat_score", "N/A"),
        timestamp=incident.get("timestamp", "N/A"),
        actions_html=actions_html,
    )


async def send_alert(config: dict[str, Any], incident: dict[str, Any]) -> None:
    """Send an email alert via SMTP.

    Config keys:
        to: str or list[str]  — recipient address(es)
        smtp_host, smtp_port, smtp_user, smtp_password, smtp_from: optional overrides
        use_ssl: bool — use SMTP_SSL instead of STARTTLS (default False)
        attachments: list[str] — file paths to attach (e.g. PDF reports)
    """
    settings = get_settings()
    host = config.get("smtp_host") or settings.SMTP_HOST
    if not host:
        raise ValueError("No SMTP host configured")

    port = int(config.get("smtp_port") or settings.SMTP_PORT)
    user = config.get("smtp_user") or settings.SMTP_USER
    password = config.get("smtp_password") or settings.SMTP_PASSWORD
    from_addr = config.get("smtp_from") or settings.SMTP_FROM
    use_ssl = config.get("use_ssl", False)

    recipients = config.get("to", "")
    if isinstance(recipients, str):
        recipients = [r.strip() for r in recipients.split(",") if r.strip()]
    if not recipients:
        raise ValueError("No recipient address configured")

    severity = incident.get("severity", "unknown")
    subject = f"[SIEM {severity.upper()}] {incident.get('title', 'Security Alert')}"

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = ", ".join(recipients)

    html_part = MIMEText(_build_html(incident), "html", "utf-8")
    msg.attach(html_part)

    # Attachments (PDF reports, etc.)
    attachment_paths = config.get("attachments", [])
    for fpath in attachment_paths:
        p = Path(fpath)
        if p.exists() and p.is_file():
            with open(p, "rb") as f:
                part = MIMEApplication(f.read(), Name=p.name)
            part["Content-Disposition"] = f'attachment; filename="{p.name}"'
            msg.attach(part)

    # Send with retry
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as server:
                    if user:
                        server.login(user, password)
                    server.sendmail(from_addr, recipients, msg.as_string())
            else:
                with smtplib.SMTP(host, port, timeout=15) as server:
                    server.ehlo()
                    if user:
                        ctx = ssl.create_default_context()
                        server.starttls(context=ctx)
                        server.login(user, password)
                    server.sendmail(from_addr, recipients, msg.as_string())
            logger.info("Email alert sent to %s", recipients)
            return
        except Exception as exc:
            last_exc = exc
            logger.warning("SMTP attempt %d failed: %s", attempt + 1, exc)

    raise RuntimeError(f"SMTP send failed after 3 attempts: {last_exc}")
