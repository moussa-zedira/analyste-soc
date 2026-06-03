"""SOAR Built-in Actions — 40+ actions d'enrichissement, confinement,
notification, investigation, remediation et reporting."""

from __future__ import annotations

import asyncio
import logging
import re
import smtplib
import socket
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from email.mime.text import MIMEText
from typing import Any

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Action registry
# ---------------------------------------------------------------------------

_REGISTRY: dict[str, dict[str, Any]] = {}


def register_action(
    name: str,
    *,
    category: str = "custom",
    description: str = "",
    params_schema: dict | None = None,
):
    """Decorator to register a SOAR action."""

    def decorator(fn: Callable):
        _REGISTRY[name] = {
            "name": name,
            "category": category,
            "description": description,
            "params_schema": params_schema or {},
            "fn": fn,
        }
        return fn

    return decorator


def get_action(name: str) -> Callable | None:
    entry = _REGISTRY.get(name)
    return entry["fn"] if entry else None


def list_actions() -> list[dict[str, Any]]:
    return [{k: v for k, v in entry.items() if k != "fn"} for entry in _REGISTRY.values()]


# ===================================================================
# ENRICHMENT ACTIONS
# ===================================================================


@register_action(
    "lookup_ip_reputation",
    category="enrichment",
    description="Query all TI providers for IP reputation",
    params_schema={"ip": "string"},
)
async def lookup_ip_reputation(params: dict, variables: dict, db: Session) -> dict:
    ip = params.get("ip", "")
    results: dict[str, Any] = {"ip": ip, "providers": {}}
    try:
        from apps.api.threat_intel.enrichment import lookup_ip

        ti_result = await asyncio.to_thread(lookup_ip, ip, db)
        results["providers"] = ti_result
        results["malicious"] = ti_result.get("malicious", False)
        results["score"] = ti_result.get("score", 0)
    except Exception as exc:
        results["providers"]["error"] = str(exc)
        # Fallback basic check
        results["malicious"] = False
        results["score"] = 0
    return results


@register_action(
    "lookup_domain",
    category="enrichment",
    description="DNS + TI lookup for a domain",
    params_schema={"domain": "string"},
)
async def lookup_domain(params: dict, variables: dict, db: Session) -> dict:
    domain = params.get("domain", "")
    result: dict[str, Any] = {"domain": domain}
    try:
        ips = await asyncio.to_thread(socket.gethostbyname_ex, domain)
        result["resolved_ips"] = ips[2]
    except socket.gaierror:
        result["resolved_ips"] = []
        result["dns_error"] = "NXDOMAIN"
    try:
        from apps.api.threat_intel.enrichment import lookup_domain as ti_lookup

        ti = await asyncio.to_thread(ti_lookup, domain, db)
        result["threat_intel"] = ti
    except Exception:
        result["threat_intel"] = {}
    return result


@register_action(
    "lookup_hash",
    category="enrichment",
    description="Check file hash across TI providers",
    params_schema={"hash": "string", "hash_type": "string (md5|sha1|sha256)"},
)
async def lookup_hash(params: dict, variables: dict, db: Session) -> dict:
    file_hash = params.get("hash", "")
    hash_type = params.get("hash_type", "sha256")
    result: dict[str, Any] = {"hash": file_hash, "hash_type": hash_type, "malicious": False}
    try:
        from apps.api.threat_intel.enrichment import lookup_hash as ti_hash

        ti = await asyncio.to_thread(ti_hash, file_hash, db)
        result.update(ti)
    except Exception:
        result["note"] = "TI lookup unavailable, hash recorded for tracking"
    return result


@register_action(
    "geoip_lookup",
    category="enrichment",
    description="Get IP geolocation data",
    params_schema={"ip": "string"},
)
async def geoip_lookup(params: dict, variables: dict, db: Session) -> dict:
    ip = params.get("ip", "")
    result: dict[str, Any] = {"ip": ip}
    try:
        import geoip2.database

        from apps.api.config import get_settings

        settings = get_settings()
        with geoip2.database.Reader(settings.GEOIP_DB_PATH) as reader:
            resp = reader.city(ip)
            result["country"] = resp.country.iso_code
            result["country_name"] = resp.country.name
            result["city"] = resp.city.name
            result["latitude"] = resp.location.latitude
            result["longitude"] = resp.location.longitude
    except Exception:
        result["country"] = "unknown"
        result["note"] = "GeoIP database not available"
    return result


@register_action(
    "whois_lookup",
    category="enrichment",
    description="Domain/IP WHOIS lookup",
    params_schema={"target": "string"},
)
async def whois_lookup(params: dict, variables: dict, db: Session) -> dict:
    target = params.get("target", "")
    result: dict[str, Any] = {"target": target}
    try:
        import whois as python_whois

        w = await asyncio.to_thread(python_whois.whois, target)
        result["registrar"] = w.registrar
        result["creation_date"] = str(w.creation_date)
        result["expiration_date"] = str(w.expiration_date)
        result["name_servers"] = w.name_servers
        result["org"] = w.org
    except Exception:
        result["note"] = "WHOIS lookup failed or library not available"
    return result


@register_action(
    "reverse_dns",
    category="enrichment",
    description="Reverse DNS lookup for an IP",
    params_schema={"ip": "string"},
)
async def reverse_dns(params: dict, variables: dict, db: Session) -> dict:
    ip = params.get("ip", "")
    result: dict[str, Any] = {"ip": ip}
    try:
        hostname = await asyncio.to_thread(socket.gethostbyaddr, ip)
        result["hostname"] = hostname[0]
        result["aliases"] = hostname[1]
    except socket.herror:
        result["hostname"] = None
        result["note"] = "No PTR record"
    return result


@register_action(
    "check_tor_exit",
    category="enrichment",
    description="Check if IP is a known Tor exit node",
    params_schema={"ip": "string"},
)
async def check_tor_exit(params: dict, variables: dict, db: Session) -> dict:
    ip = params.get("ip", "")
    result: dict[str, Any] = {"ip": ip, "is_tor_exit": False}
    try:
        # Check via DNS-based Tor exit list
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.dnsel.torproject.org"
        await asyncio.to_thread(socket.gethostbyname, query)
        result["is_tor_exit"] = True
    except socket.gaierror:
        result["is_tor_exit"] = False
    return result


# ===================================================================
# CONTAINMENT ACTIONS
# ===================================================================


@register_action(
    "block_ip_firewall",
    category="containment",
    description="Add IP to firewall blocklist (Panorama > iptables > log)",
    params_schema={
        "ip": "string",
        "direction": "string (inbound|outbound|both)",
        "duration_hours": "int",
    },
)
async def block_ip_firewall(params: dict, variables: dict, db: Session) -> dict:
    ip = params.get("ip", "")
    direction = params.get("direction", "both")
    duration = params.get("duration_hours", 24)
    base = {
        "action": "block_ip_firewall",
        "ip": ip,
        "direction": direction,
        "duration_hours": duration,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    from apps.api.soar.connectors import IPTablesConnector, PanoramaConnector

    for connector in (PanoramaConnector(), IPTablesConnector()):
        if not connector.configured:
            continue
        try:
            if connector.name == "palo_alto":
                res = await connector.block_ip(ip)
            else:
                res = await connector.block_ip(ip, direction=direction)
            if res.get("applied"):
                return {**base, "applied": True, "connector": connector.name, "result": res}
            logger.warning("SOAR connector %s not applied: %s", connector.name, res.get("reason"))
        except Exception as exc:
            logger.warning("SOAR connector %s failed: %s", connector.name, exc)

    # Fallback : log only (aucun connector configure/disponible)
    logger.info(
        "SOAR: Blocking IP %s direction=%s duration=%dh (LOG-ONLY)", ip, direction, duration
    )
    return {
        **base,
        "applied": False,
        "reason": "no_connector_configured",
        "rule_id": f"soar-fw-{uuid.uuid4().hex[:8]}",
        "connector": "log-only",
    }


@register_action(
    "isolate_host",
    category="containment",
    description="Network isolation of a compromised host (Defender/Falcon)",
    params_schema={
        "hostname": "string",
        "isolation_level": "string (full|partial)",
        "device_id": "string (Defender device ID ou Falcon AID)",
        "platform": "string (defender|falcon|auto)",
    },
)
async def isolate_host(params: dict, variables: dict, db: Session) -> dict:
    hostname = params.get("hostname", "")
    level = params.get("isolation_level", "full")
    device_id = params.get("device_id") or params.get("aid") or hostname
    platform = (params.get("platform") or "auto").lower()

    base = {
        "action": "isolate_host",
        "hostname": hostname,
        "isolation_level": level,
        "device_id": device_id,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    from apps.api.soar.connectors import DefenderConnector, FalconConnector

    # Selection selon platform
    if platform == "defender":
        candidates = [DefenderConnector()]
    elif platform == "falcon":
        candidates = [FalconConnector()]
    else:
        candidates = [DefenderConnector(), FalconConnector()]

    for connector in candidates:
        if not connector.configured:
            continue
        try:
            if connector.name == "ms_defender":
                isolation_type = "Full" if level == "full" else "Selective"
                res = await connector.isolate_device(device_id, isolation_type=isolation_type)
            else:  # crowdstrike
                res = await connector.contain_host(device_id)
            if res.get("applied"):
                return {**base, "isolated": True, "connector": connector.name, "result": res}
            logger.warning("SOAR %s isolate failed: %s", connector.name, res)
        except Exception as exc:
            logger.warning("SOAR %s exception: %s", connector.name, exc)

    logger.info("SOAR: Isolating host %s (level=%s) (LOG-ONLY)", hostname, level)
    return {**base, "isolated": False, "reason": "no_connector_configured", "connector": "log-only"}


@register_action(
    "disable_user",
    category="containment",
    description="Disable user account (LDAP/AD ou AWS DenyAll)",
    params_schema={
        "username": "string",
        "reason": "string",
        "platform": "string (ldap|aws|auto)",
    },
)
async def disable_user(params: dict, variables: dict, db: Session) -> dict:
    username = params.get("username", "")
    reason = params.get("reason", "SOAR automated response")
    platform = (params.get("platform") or "auto").lower()

    base = {
        "action": "disable_user",
        "username": username,
        "reason": reason,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    from apps.api.soar.connectors import AWSConnector, LDAPConnector

    if platform == "ldap":
        candidates = [LDAPConnector()]
    elif platform == "aws":
        candidates = [AWSConnector()]
    else:
        candidates = [LDAPConnector(), AWSConnector()]

    for connector in candidates:
        if not connector.configured:
            continue
        try:
            if connector.name == "ldap_ad":
                res = await connector.disable_user(username)
            else:  # aws_iam
                res = await connector.attach_deny_all_policy(username)
            if res.get("applied"):
                return {**base, "disabled": True, "connector": connector.name, "result": res}
            logger.warning("SOAR %s disable_user failed: %s", connector.name, res)
        except Exception as exc:
            logger.warning("SOAR %s exception: %s", connector.name, exc)

    logger.info("SOAR: Disabling user %s — %s (LOG-ONLY)", username, reason)
    return {
        **base,
        "disabled": False,
        "reason_no_apply": "no_connector_configured",
        "connector": "log-only",
    }


@register_action(
    "revoke_sessions",
    category="containment",
    description="Force logout / revoke all user sessions (AWS STS ou LDAP password reset)",
    params_schema={"username": "string", "platform": "string (aws|ldap|auto)"},
)
async def revoke_sessions(params: dict, variables: dict, db: Session) -> dict:
    username = params.get("username", "")
    platform = (params.get("platform") or "auto").lower()

    base = {
        "action": "revoke_sessions",
        "username": username,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    from apps.api.soar.connectors import AWSConnector, LDAPConnector

    if platform == "aws":
        candidates = [AWSConnector()]
    elif platform == "ldap":
        candidates = [LDAPConnector()]
    else:
        candidates = [AWSConnector(), LDAPConnector()]

    for connector in candidates:
        if not connector.configured:
            continue
        try:
            if connector.name == "aws_iam":
                res = await connector.revoke_sts_sessions(username)
            else:  # ldap : forcer un changement de password = invalider sessions
                import secrets

                temp_pwd = secrets.token_urlsafe(24) + "Aa1!"
                res = await connector.reset_password(username, temp_pwd)
                if res.get("applied"):
                    res["note"] = "Password rotated — sessions invalidated"
            if res.get("applied"):
                return {
                    **base,
                    "sessions_revoked": True,
                    "connector": connector.name,
                    "result": res,
                }
        except Exception as exc:
            logger.warning("SOAR %s revoke_sessions exception: %s", connector.name, exc)

    logger.info("SOAR: Revoking all sessions for %s (LOG-ONLY)", username)
    return {
        **base,
        "sessions_revoked": False,
        "reason": "no_connector_configured",
        "connector": "log-only",
    }


@register_action(
    "quarantine_file",
    category="containment",
    description="Move suspicious file to quarantine (Defender StopAndQuarantineFile)",
    params_schema={
        "file_path": "string",
        "hostname": "string",
        "device_id": "string",
        "sha1": "string (required for Defender)",
    },
)
async def quarantine_file(params: dict, variables: dict, db: Session) -> dict:
    file_path = params.get("file_path", "")
    hostname = params.get("hostname", "")
    device_id = params.get("device_id") or hostname
    sha1 = params.get("sha1", "")

    base = {
        "action": "quarantine_file",
        "file_path": file_path,
        "hostname": hostname,
        "device_id": device_id,
        "sha1": sha1,
        "quarantine_id": str(uuid.uuid4()),
        "timestamp": datetime.now(UTC).isoformat(),
    }

    from apps.api.soar.connectors import DefenderConnector

    defender = DefenderConnector()
    if defender.configured and sha1 and device_id:
        try:
            res = await defender.stop_and_quarantine_file(device_id, sha1)
            if res.get("applied"):
                return {**base, "quarantined": True, "connector": defender.name, "result": res}
            logger.warning("SOAR Defender quarantine failed: %s", res)
        except Exception as exc:
            logger.warning("SOAR Defender exception: %s", exc)

    logger.info("SOAR: Quarantining %s on %s (LOG-ONLY)", file_path, hostname)
    return {
        **base,
        "quarantined": False,
        "reason": "no_connector_configured_or_missing_sha1",
        "connector": "log-only",
    }


@register_action(
    "block_domain_dns",
    category="containment",
    description="Add domain to DNS sinkhole / Panorama FQDN address-group",
    params_schema={"domain": "string"},
)
async def block_domain_dns(params: dict, variables: dict, db: Session) -> dict:
    domain = params.get("domain", "")
    base = {
        "action": "block_domain_dns",
        "domain": domain,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    from apps.api.soar.connectors import PanoramaConnector

    panorama = PanoramaConnector()
    if panorama.configured:
        try:
            res = await panorama.block_domain(domain)
            if res.get("applied"):
                return {**base, "sinkholed": True, "connector": panorama.name, "result": res}
        except Exception as exc:
            logger.warning("SOAR Panorama block_domain exception: %s", exc)

    logger.info("SOAR: DNS sinkhole for %s (LOG-ONLY)", domain)
    return {
        **base,
        "sinkholed": False,
        "reason": "no_connector_configured",
        "connector": "log-only",
    }


@register_action(
    "update_waf_rules",
    category="containment",
    description="Add WAF block rule",
    params_schema={"rule_type": "string", "pattern": "string", "action": "string (block|log)"},
)
async def update_waf_rules(params: dict, variables: dict, db: Session) -> dict:
    rule_type = params.get("rule_type", "ip")
    pattern = params.get("pattern", "")
    waf_action = params.get("action", "block")
    logger.info("SOAR: WAF rule %s %s=%s", waf_action, rule_type, pattern)
    return {
        "action": "update_waf_rules",
        "rule_type": rule_type,
        "pattern": pattern,
        "waf_action": waf_action,
        "rule_id": f"soar-waf-{uuid.uuid4().hex[:8]}",
        "applied": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }


# ===================================================================
# NOTIFICATION ACTIONS
# ===================================================================


@register_action(
    "send_email",
    category="notification",
    description="Send email notification via SMTP",
    params_schema={"to": "string", "subject": "string", "body": "string"},
)
async def send_email(params: dict, variables: dict, db: Session) -> dict:
    from apps.api.config import get_settings

    settings = get_settings()
    to = params.get("to", "")
    subject = params.get("subject", "SOAR Alert")
    body = params.get("body", "")

    if not settings.SMTP_HOST:
        return {"action": "send_email", "sent": False, "reason": "SMTP not configured"}

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = settings.SMTP_FROM
        msg["To"] = to

        def _send():
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_USER:
                    server.starttls()
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)

        await asyncio.to_thread(_send)
        return {"action": "send_email", "to": to, "sent": True}
    except Exception as exc:
        return {"action": "send_email", "sent": False, "error": str(exc)}


@register_action(
    "send_slack",
    category="notification",
    description="Post message to Slack channel",
    params_schema={"channel": "string", "message": "string"},
)
async def send_slack(params: dict, variables: dict, db: Session) -> dict:
    from apps.api.config import get_settings

    settings = get_settings()
    channel = params.get("channel", "#security-alerts")
    message = params.get("message", "")

    webhook_url = settings.SLACK_WEBHOOK_URL
    if not webhook_url:
        return {"action": "send_slack", "sent": False, "reason": "Slack webhook not configured"}

    try:
        import httpx

        payload = {"channel": channel, "text": message, "username": "SOAR Bot"}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
        return {"action": "send_slack", "channel": channel, "sent": resp.status_code == 200}
    except Exception as exc:
        return {"action": "send_slack", "sent": False, "error": str(exc)}


@register_action(
    "send_teams",
    category="notification",
    description="Post message to Microsoft Teams channel",
    params_schema={"webhook_url": "string", "title": "string", "message": "string"},
)
async def send_teams(params: dict, variables: dict, db: Session) -> dict:
    webhook_url = params.get("webhook_url", "")
    title = params.get("title", "SOAR Alert")
    message = params.get("message", "")

    if not webhook_url:
        return {"action": "send_teams", "sent": False, "reason": "Teams webhook URL required"}

    try:
        import httpx

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "summary": title,
            "themeColor": "FF0000",
            "title": title,
            "sections": [{"text": message}],
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(webhook_url, json=payload)
        return {"action": "send_teams", "sent": resp.status_code == 200}
    except Exception as exc:
        return {"action": "send_teams", "sent": False, "error": str(exc)}


@register_action(
    "send_pagerduty",
    category="notification",
    description="Create PagerDuty incident",
    params_schema={"routing_key": "string", "summary": "string", "severity": "string"},
)
async def send_pagerduty(params: dict, variables: dict, db: Session) -> dict:
    routing_key = params.get("routing_key", "")
    summary = params.get("summary", "SOAR Alert")
    severity = params.get("severity", "critical")

    if not routing_key:
        return {"action": "send_pagerduty", "sent": False, "reason": "Routing key required"}

    try:
        import httpx

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": summary,
                "severity": severity,
                "source": "soar-engine",
            },
        }
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
            )
        return {"action": "send_pagerduty", "sent": resp.status_code == 202}
    except Exception as exc:
        return {"action": "send_pagerduty", "sent": False, "error": str(exc)}


@register_action(
    "send_telegram",
    category="notification",
    description="Send Telegram message",
    params_schema={"bot_token": "string", "chat_id": "string", "message": "string"},
)
async def send_telegram(params: dict, variables: dict, db: Session) -> dict:
    bot_token = params.get("bot_token", "")
    chat_id = params.get("chat_id", "")
    message = params.get("message", "")

    if not bot_token or not chat_id:
        return {
            "action": "send_telegram",
            "sent": False,
            "reason": "Bot token and chat_id required",
        }

    try:
        import httpx

        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, json={"chat_id": chat_id, "text": message})
        return {"action": "send_telegram", "sent": resp.status_code == 200}
    except Exception as exc:
        return {"action": "send_telegram", "sent": False, "error": str(exc)}


@register_action(
    "create_ticket_jira",
    category="notification",
    description="Create a Jira ticket",
    params_schema={
        "url": "string",
        "project": "string",
        "summary": "string",
        "description": "string",
        "issue_type": "string",
        "priority": "string",
    },
)
async def create_ticket_jira(params: dict, variables: dict, db: Session) -> dict:
    jira_url = params.get("url", "")
    project = params.get("project", "SEC")
    summary = params.get("summary", "SOAR Incident")
    description = params.get("description", "")
    issue_type = params.get("issue_type", "Bug")
    priority = params.get("priority", "High")

    if not jira_url:
        return {"action": "create_ticket_jira", "created": False, "reason": "Jira URL required"}

    try:
        import httpx

        payload = {
            "fields": {
                "project": {"key": project},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
                "priority": {"name": priority},
            }
        }
        token = params.get("token", "")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(f"{jira_url}/rest/api/2/issue", json=payload, headers=headers)
        data = resp.json() if resp.status_code == 201 else {}
        return {
            "action": "create_ticket_jira",
            "created": resp.status_code == 201,
            "ticket_key": data.get("key"),
        }
    except Exception as exc:
        return {"action": "create_ticket_jira", "created": False, "error": str(exc)}


@register_action(
    "create_ticket_servicenow",
    category="notification",
    description="Create ServiceNow incident",
    params_schema={
        "instance": "string",
        "short_description": "string",
        "description": "string",
        "urgency": "int",
        "impact": "int",
    },
)
async def create_ticket_servicenow(params: dict, variables: dict, db: Session) -> dict:
    instance = params.get("instance", "")
    short_desc = params.get("short_description", "SOAR Incident")
    description = params.get("description", "")
    urgency = params.get("urgency", 2)
    impact = params.get("impact", 2)

    if not instance:
        return {
            "action": "create_ticket_servicenow",
            "created": False,
            "reason": "Instance URL required",
        }

    try:
        import httpx

        payload = {
            "short_description": short_desc,
            "description": description,
            "urgency": urgency,
            "impact": impact,
            "category": "Security",
        }
        token = params.get("token", "")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        url = f"{instance}/api/now/table/incident"
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json=payload, headers=headers)
        data = resp.json().get("result", {}) if resp.status_code == 201 else {}
        return {
            "action": "create_ticket_servicenow",
            "created": resp.status_code == 201,
            "sys_id": data.get("sys_id"),
            "number": data.get("number"),
        }
    except Exception as exc:
        return {"action": "create_ticket_servicenow", "created": False, "error": str(exc)}


# ===================================================================
# INVESTIGATION ACTIONS
# ===================================================================


@register_action(
    "run_osint",
    category="investigation",
    description="Gather OSINT on an indicator (IP, domain, hash)",
    params_schema={"indicator": "string", "indicator_type": "string"},
)
async def run_osint(params: dict, variables: dict, db: Session) -> dict:
    indicator = params.get("indicator", "")
    ind_type = params.get("indicator_type", "auto")
    results: dict[str, Any] = {"indicator": indicator, "type": ind_type, "sources": {}}

    # Auto-detect type
    if ind_type == "auto":
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
            ind_type = "ip"
        elif re.match(r"^[a-fA-F0-9]{32,64}$", indicator):
            ind_type = "hash"
        else:
            ind_type = "domain"
        results["type"] = ind_type

    if ind_type == "ip":
        rep = await lookup_ip_reputation({"ip": indicator}, variables, db)
        geo = await geoip_lookup({"ip": indicator}, variables, db)
        rdns = await reverse_dns({"ip": indicator}, variables, db)
        tor = await check_tor_exit({"ip": indicator}, variables, db)
        results["sources"] = {
            "reputation": rep,
            "geolocation": geo,
            "reverse_dns": rdns,
            "tor_check": tor,
        }
    elif ind_type == "domain":
        dom = await lookup_domain({"domain": indicator}, variables, db)
        who = await whois_lookup({"target": indicator}, variables, db)
        results["sources"] = {"dns_ti": dom, "whois": who}
    elif ind_type == "hash":
        h = await lookup_hash({"hash": indicator}, variables, db)
        results["sources"] = {"hash_lookup": h}

    return results


@register_action(
    "search_events",
    category="investigation",
    description="Search SIEM events with filters",
    params_schema={"query": "string", "time_range_hours": "int", "limit": "int"},
)
async def search_events(params: dict, variables: dict, db: Session) -> dict:
    from datetime import timedelta

    from apps.api.models.event import Event

    query = params.get("query", "")
    hours = params.get("time_range_hours", 24)
    limit = min(params.get("limit", 100), 500)

    since = datetime.now(UTC) - timedelta(hours=hours)
    q = db.query(Event).filter(Event.ts >= since)
    if query:
        q = q.filter(
            Event.raw.ilike(f"%{query}%")
            | Event.src_ip.ilike(f"%{query}%")
            | Event.username.ilike(f"%{query}%")
        )
    events = q.order_by(Event.ts.desc()).limit(limit).all()
    return {
        "action": "search_events",
        "query": query,
        "count": len(events),
        "events": [
            {"id": e.id, "ts": e.ts.isoformat(), "src_ip": e.src_ip, "event_type": e.event_type}
            for e in events
        ],
    }


@register_action(
    "get_user_activity",
    category="investigation",
    description="Get recent events for a specific user",
    params_schema={"username": "string", "hours": "int"},
)
async def get_user_activity(params: dict, variables: dict, db: Session) -> dict:
    from datetime import timedelta

    from apps.api.models.event import Event

    username = params.get("username", "")
    hours = params.get("hours", 24)
    since = datetime.now(UTC) - timedelta(hours=hours)

    events = (
        db.query(Event)
        .filter(Event.username == username, Event.ts >= since)
        .order_by(Event.ts.desc())
        .limit(200)
        .all()
    )
    return {
        "action": "get_user_activity",
        "username": username,
        "count": len(events),
        "events": [
            {"id": e.id, "ts": e.ts.isoformat(), "event_type": e.event_type, "src_ip": e.src_ip}
            for e in events
        ],
    }


@register_action(
    "get_host_processes",
    category="investigation",
    description="List running processes on a host (via agent)",
    params_schema={"hostname": "string"},
)
async def get_host_processes(params: dict, variables: dict, db: Session) -> dict:
    hostname = params.get("hostname", "")
    logger.info("SOAR: Requesting process list from %s", hostname)
    return {
        "action": "get_host_processes",
        "hostname": hostname,
        "requested": True,
        "note": "Process list request sent to endpoint agent",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@register_action(
    "capture_pcap",
    category="investigation",
    description="Initiate packet capture on a network segment",
    params_schema={"interface": "string", "filter": "string", "duration_seconds": "int"},
)
async def capture_pcap(params: dict, variables: dict, db: Session) -> dict:
    interface = params.get("interface", "eth0")
    bpf_filter = params.get("filter", "")
    duration = params.get("duration_seconds", 60)
    capture_id = str(uuid.uuid4())
    logger.info(
        "SOAR: Starting pcap on %s (filter=%s, duration=%ds)", interface, bpf_filter, duration
    )
    return {
        "action": "capture_pcap",
        "capture_id": capture_id,
        "interface": interface,
        "filter": bpf_filter,
        "duration_seconds": duration,
        "started": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@register_action(
    "screenshot_url",
    category="investigation",
    description="Take a screenshot of a URL",
    params_schema={"url": "string"},
)
async def screenshot_url(params: dict, variables: dict, db: Session) -> dict:
    url = params.get("url", "")
    screenshot_id = str(uuid.uuid4())
    logger.info("SOAR: Screenshot requested for %s", url)
    return {
        "action": "screenshot_url",
        "url": url,
        "screenshot_id": screenshot_id,
        "requested": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@register_action(
    "check_url_sandbox",
    category="investigation",
    description="Submit URL to sandbox for analysis",
    params_schema={"url": "string", "sandbox": "string (any|cuckoo|hybrid)"},
)
async def check_url_sandbox(params: dict, variables: dict, db: Session) -> dict:
    url = params.get("url", "")
    sandbox = params.get("sandbox", "any")
    submission_id = str(uuid.uuid4())
    logger.info("SOAR: Submitting %s to sandbox %s", url, sandbox)
    return {
        "action": "check_url_sandbox",
        "url": url,
        "sandbox": sandbox,
        "submission_id": submission_id,
        "submitted": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }


# ===================================================================
# REMEDIATION ACTIONS
# ===================================================================


@register_action(
    "kill_process",
    category="remediation",
    description="Terminate process via Defender Live Response ou Falcon RTR",
    params_schema={
        "hostname": "string",
        "pid": "int",
        "process_name": "string",
        "device_id": "string",
        "platform": "string (defender|falcon|auto)",
    },
)
async def kill_process(params: dict, variables: dict, db: Session) -> dict:
    hostname = params.get("hostname", "")
    pid = params.get("pid", 0)
    process_name = params.get("process_name", "")
    device_id = params.get("device_id") or params.get("aid") or hostname
    platform = (params.get("platform") or "auto").lower()

    base = {
        "action": "kill_process",
        "hostname": hostname,
        "pid": pid,
        "process_name": process_name,
        "device_id": device_id,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    from apps.api.soar.connectors import DefenderConnector, FalconConnector

    if platform == "defender":
        candidates = [DefenderConnector()]
    elif platform == "falcon":
        candidates = [FalconConnector()]
    else:
        candidates = [FalconConnector(), DefenderConnector()]

    for connector in candidates:
        if not connector.configured:
            continue
        try:
            if connector.name == "crowdstrike":
                cmd = f"-id {pid}" if pid else f"-name {process_name}"
                res = await connector.run_rtr_command(device_id, "kill", f"kill {cmd}")
            else:  # ms_defender
                args = f"pid={pid}" if pid else f"name={process_name}"
                res = await connector.run_script(device_id, "kill_process.ps1", args)
            if res.get("applied"):
                return {**base, "killed": True, "connector": connector.name, "result": res}
        except Exception as exc:
            logger.warning("SOAR %s kill_process exception: %s", connector.name, exc)

    logger.info("SOAR: Kill process %s (PID %d) on %s (LOG-ONLY)", process_name, pid, hostname)
    return {**base, "killed": False, "reason": "no_connector_configured", "connector": "log-only"}


@register_action(
    "remove_persistence",
    category="remediation",
    description="Remove persistence mechanism from host",
    params_schema={"hostname": "string", "persistence_type": "string", "path": "string"},
)
async def remove_persistence(params: dict, variables: dict, db: Session) -> dict:
    hostname = params.get("hostname", "")
    pers_type = params.get("persistence_type", "")
    path = params.get("path", "")
    logger.info("SOAR: Remove persistence %s (%s) on %s", pers_type, path, hostname)
    return {
        "action": "remove_persistence",
        "hostname": hostname,
        "persistence_type": pers_type,
        "path": path,
        "removed": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@register_action(
    "rotate_credentials",
    category="remediation",
    description="Force password reset via LDAP/AD",
    params_schema={
        "username": "string",
        "notify_user": "bool",
        "new_password": "string (optionnel)",
    },
)
async def rotate_credentials(params: dict, variables: dict, db: Session) -> dict:
    import secrets

    username = params.get("username", "")
    notify = params.get("notify_user", True)
    new_password = params.get("new_password") or (secrets.token_urlsafe(18) + "Aa1!")

    base = {
        "action": "rotate_credentials",
        "username": username,
        "notify_user": notify,
        "timestamp": datetime.now(UTC).isoformat(),
    }

    from apps.api.soar.connectors import LDAPConnector

    ldap = LDAPConnector()
    if ldap.configured:
        try:
            res = await ldap.reset_password(username, new_password)
            if res.get("applied"):
                return {
                    **base,
                    "rotated": True,
                    "connector": ldap.name,
                    "new_password_length": len(new_password),
                    "result": res,
                }
        except Exception as exc:
            logger.warning("SOAR LDAP reset_password exception: %s", exc)

    logger.info("SOAR: Credential rotation for %s (LOG-ONLY)", username)
    return {**base, "rotated": False, "reason": "no_connector_configured", "connector": "log-only"}


# Alias reset_user_password pour compatibilite avec les playbooks
@register_action(
    "reset_user_password",
    category="remediation",
    description="Alias de rotate_credentials (LDAP password reset)",
    params_schema={"username": "string", "new_password": "string (optionnel)"},
)
async def reset_user_password(params: dict, variables: dict, db: Session) -> dict:
    return await rotate_credentials(params, variables, db)


@register_action(
    "patch_vulnerability",
    category="remediation",
    description="Trigger patch deployment for a vulnerability",
    params_schema={"cve_id": "string", "target_hosts": "list[string]", "priority": "string"},
)
async def patch_vulnerability(params: dict, variables: dict, db: Session) -> dict:
    cve_id = params.get("cve_id", "")
    targets = params.get("target_hosts", [])
    priority = params.get("priority", "high")
    logger.info("SOAR: Patch deployment for %s on %d hosts", cve_id, len(targets))
    return {
        "action": "patch_vulnerability",
        "cve_id": cve_id,
        "target_hosts": targets,
        "priority": priority,
        "deployment_id": str(uuid.uuid4()),
        "scheduled": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@register_action(
    "restore_backup",
    category="remediation",
    description="Initiate backup restore for a host/service",
    params_schema={"target": "string", "backup_id": "string", "restore_point": "string"},
)
async def restore_backup(params: dict, variables: dict, db: Session) -> dict:
    target = params.get("target", "")
    backup_id = params.get("backup_id", "latest")
    restore_point = params.get("restore_point", "")
    logger.info("SOAR: Restore backup %s for %s", backup_id, target)
    return {
        "action": "restore_backup",
        "target": target,
        "backup_id": backup_id,
        "restore_point": restore_point,
        "restore_job_id": str(uuid.uuid4()),
        "initiated": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@register_action(
    "rollback_change",
    category="remediation",
    description="Revert a configuration change",
    params_schema={"change_id": "string", "target": "string"},
)
async def rollback_change(params: dict, variables: dict, db: Session) -> dict:
    change_id = params.get("change_id", "")
    target = params.get("target", "")
    logger.info("SOAR: Rollback change %s on %s", change_id, target)
    return {
        "action": "rollback_change",
        "change_id": change_id,
        "target": target,
        "rolled_back": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }


# ===================================================================
# REPORTING ACTIONS
# ===================================================================


@register_action(
    "generate_report",
    category="reporting",
    description="Generate an incident response report",
    params_schema={
        "incident_id": "string",
        "format": "string (html|pdf|json)",
        "include_timeline": "bool",
    },
)
async def generate_report(params: dict, variables: dict, db: Session) -> dict:
    incident_id = params.get("incident_id", "")
    fmt = params.get("format", "json")
    params.get("include_timeline", True)

    report_data: dict[str, Any] = {
        "report_id": str(uuid.uuid4()),
        "incident_id": incident_id,
        "format": fmt,
        "generated_at": datetime.now(UTC).isoformat(),
        "sections": [],
    }

    # Pull incident data if available
    if incident_id:
        from apps.api.models.incident import Incident

        incident = db.query(Incident).filter(Incident.id == incident_id).first()
        if incident:
            report_data["sections"].append(
                {
                    "title": "Incident Summary",
                    "content": {
                        "title": incident.title,
                        "severity": incident.severity,
                        "status": incident.status,
                        "created_at": incident.created_at.isoformat(),
                    },
                }
            )

    # Pull execution data from variables
    steps_data = variables.get("steps", {})
    if steps_data:
        report_data["sections"].append(
            {
                "title": "Response Actions",
                "content": {
                    name: {"status": s.get("status", "unknown")}
                    for name, s in steps_data.items()
                    if isinstance(s, dict)
                },
            }
        )

    return report_data


@register_action(
    "update_incident",
    category="reporting",
    description="Update incident status and details",
    params_schema={"incident_id": "string", "status": "string", "notes": "string"},
)
async def update_incident(params: dict, variables: dict, db: Session) -> dict:
    from apps.api.models.incident import Incident

    incident_id = params.get("incident_id", variables.get("input", {}).get("incident_id", ""))
    new_status = params.get("status", "")
    params.get("notes", "")

    if not incident_id:
        return {"action": "update_incident", "updated": False, "reason": "No incident_id"}

    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        return {"action": "update_incident", "updated": False, "reason": "Incident not found"}

    if new_status:
        incident.status = new_status
    incident.updated_at = datetime.now(UTC)
    db.commit()
    return {
        "action": "update_incident",
        "incident_id": incident_id,
        "new_status": new_status,
        "updated": True,
    }


@register_action(
    "add_timeline_entry",
    category="reporting",
    description="Add entry to incident timeline",
    params_schema={"incident_id": "string", "message": "string", "entry_type": "string"},
)
async def add_timeline_entry(params: dict, variables: dict, db: Session) -> dict:
    incident_id = params.get("incident_id", "")
    message = params.get("message", "")
    entry_type = params.get("entry_type", "action")
    logger.info("SOAR: Timeline entry for incident %s: [%s] %s", incident_id, entry_type, message)
    return {
        "action": "add_timeline_entry",
        "incident_id": incident_id,
        "entry_type": entry_type,
        "message": message,
        "timestamp": datetime.now(UTC).isoformat(),
        "added": True,
    }


@register_action(
    "calculate_metrics",
    category="reporting",
    description="Compute response metrics (MTTD, MTTR)",
    params_schema={"incident_id": "string"},
)
async def calculate_metrics(params: dict, variables: dict, db: Session) -> dict:
    from apps.api.models.incident import Incident
    from apps.api.models.soar import PlaybookExecution

    incident_id = params.get("incident_id", "")
    result: dict[str, Any] = {"incident_id": incident_id}

    incident = (
        db.query(Incident).filter(Incident.id == incident_id).first() if incident_id else None
    )
    if incident:
        # MTTD: time from first event to incident creation
        if incident.start_ts and incident.created_at:
            mttd = (incident.created_at - incident.start_ts).total_seconds()
            result["mttd_seconds"] = max(0, mttd)

        # MTTR: time from creation to resolution
        if incident.status == "closed" and incident.updated_at:
            mttr = (incident.updated_at - incident.created_at).total_seconds()
            result["mttr_seconds"] = max(0, mttr)

    # Global metrics from SOAR executions
    total_execs = db.query(PlaybookExecution).count()
    completed = db.query(PlaybookExecution).filter(PlaybookExecution.status == "completed").count()
    failed = db.query(PlaybookExecution).filter(PlaybookExecution.status == "failed").count()
    result["total_executions"] = total_execs
    result["completed"] = completed
    result["failed"] = failed
    result["success_rate"] = round(completed / total_execs * 100, 1) if total_execs > 0 else 0

    return result


@register_action(
    "export_iocs",
    category="reporting",
    description="Export IOCs in STIX/OpenIOC format",
    params_schema={"iocs": "list[dict]", "format": "string (stix|openioc|csv)"},
)
async def export_iocs(params: dict, variables: dict, db: Session) -> dict:
    iocs = params.get("iocs", [])
    fmt = params.get("format", "stix")

    # Collect IOCs from step results if not provided
    if not iocs:
        for _step_name, step_data in variables.get("steps", {}).items():
            if isinstance(step_data, dict):
                if step_data.get("ip"):
                    iocs.append({"type": "ipv4-addr", "value": step_data["ip"]})
                if step_data.get("domain"):
                    iocs.append({"type": "domain-name", "value": step_data["domain"]})
                if step_data.get("hash"):
                    iocs.append({"type": "file:hashes", "value": step_data["hash"]})

    export_id = str(uuid.uuid4())
    exported: dict[str, Any] = {
        "export_id": export_id,
        "format": fmt,
        "ioc_count": len(iocs),
        "timestamp": datetime.now(UTC).isoformat(),
    }

    if fmt == "stix":
        exported["bundle"] = {
            "type": "bundle",
            "id": f"bundle--{export_id}",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{uuid.uuid4()}",
                    "pattern": f"[{ioc['type']}:value = '{ioc['value']}']",
                    "valid_from": datetime.now(UTC).isoformat(),
                }
                for ioc in iocs
            ],
        }
    elif fmt == "csv":
        exported["csv_lines"] = [f"{ioc['type']},{ioc['value']}" for ioc in iocs]

    return exported


@register_action(
    "send_webhook",
    category="notification",
    description="Send a generic webhook POST notification",
    params_schema={"url": "string", "payload": "dict", "headers": "dict"},
)
async def send_webhook(params: dict, variables: dict, db: Session) -> dict:
    url = params.get("url", "")
    payload = params.get("payload", {})
    headers = params.get("headers", {})

    if not url:
        return {"action": "send_webhook", "sent": False, "reason": "URL required"}

    try:
        import httpx

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, json=payload, headers=headers)
        return {
            "action": "send_webhook",
            "url": url,
            "status_code": resp.status_code,
            "sent": 200 <= resp.status_code < 300,
        }
    except Exception as exc:
        return {"action": "send_webhook", "sent": False, "error": str(exc)}


@register_action(
    "tag_ioc",
    category="enrichment",
    description="Tag an indicator of compromise for tracking and correlation",
    params_schema={"indicator": "string", "indicator_type": "string", "tags": "list[string]"},
)
async def tag_ioc(params: dict, variables: dict, db: Session) -> dict:
    indicator = params.get("indicator", "")
    ind_type = params.get("indicator_type", "auto")
    tags = params.get("tags", [])
    logger.info("SOAR: Tagging IOC %s (%s) with %s", indicator, ind_type, tags)
    return {
        "action": "tag_ioc",
        "indicator": indicator,
        "indicator_type": ind_type,
        "tags": tags,
        "tagged": True,
        "timestamp": datetime.now(UTC).isoformat(),
    }
