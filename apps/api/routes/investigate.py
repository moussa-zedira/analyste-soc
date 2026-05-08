"""API Investigation — OSINT lookup complet pour IP ou domaine."""

from __future__ import annotations

import ipaddress
import logging
import socket
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.models.threat_score import ThreatScore
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])
logger = logging.getLogger(__name__)


class InvestigateResponse(BaseModel):
    target: str
    target_type: str  # "ip" or "domain"
    resolved_ip: str | None = None

    # GeoIP
    geo: dict | None = None

    # DNS
    dns: dict | None = None

    # WHOIS
    whois: dict | None = None

    # Threat Intelligence
    threat_intel: dict | None = None

    # SIEM data
    event_count: int = 0
    recent_events: list[dict] = []
    event_types: list[dict] = []
    incident_count: int = 0
    recent_incidents: list[dict] = []
    threat_score: dict | None = None

    # Reverse DNS
    reverse_dns: str | None = None

    # Related users
    related_users: list[dict] = []

    # Timeline (events per hour last 24h)
    timeline: list[dict] = []


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _resolve_domain(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _reverse_dns(ip: str) -> str | None:
    try:
        result = socket.gethostbyaddr(ip)
        return result[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _get_dns_records(domain: str) -> dict:
    """Recupere les enregistrements DNS basiques."""
    records: dict = {}
    try:
        import dns.resolver

        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
    except ImportError:
        # dnspython not available, basic lookup only
        try:
            ips = socket.getaddrinfo(domain, None)
            records["A"] = list({addr[4][0] for addr in ips if addr[0] == socket.AF_INET})
            records["AAAA"] = list({addr[4][0] for addr in ips if addr[0] == socket.AF_INET6})
        except socket.gaierror:
            pass
    except Exception:
        logger.debug("investigate: ignored exception", exc_info=True)
    return records


def _get_whois_info(target: str) -> dict | None:
    """Recupere les infos WHOIS."""
    try:
        import whois
        w = whois.whois(target)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date) if w.creation_date else None,
            "expiration_date": str(w.expiration_date) if w.expiration_date else None,
            "name_servers": w.name_servers if isinstance(w.name_servers, list) else [w.name_servers] if w.name_servers else [],
            "org": w.org,
            "country": w.country,
        }
    except Exception:
        return None


def _get_geo(ip: str) -> dict | None:
    """Recupere les donnees de geolocalisation."""
    try:
        from apps.api.geoip import lookup
        return lookup(ip)
    except Exception:
        return None


async def _get_threat_intel(ip: str, db: Session) -> dict | None:
    """Recupere les donnees TI."""
    try:
        from apps.api.threat_intel.enrichment import lookup_ip_manual
        return await lookup_ip_manual(ip, db)
    except Exception:
        return None


def _get_siem_data(ip: str, db: Session) -> dict:
    """Recupere les donnees SIEM liees a cette IP."""
    cutoff_24h = datetime.now(UTC) - timedelta(hours=24)
    datetime.now(UTC) - timedelta(days=7)

    # Event count
    event_count = (
        db.query(func.count(Event.id))
        .filter(Event.src_ip == ip)
        .scalar() or 0
    )

    # Recent events (last 20)
    recent = (
        db.query(Event)
        .filter(Event.src_ip == ip)
        .order_by(Event.ts.desc())
        .limit(20)
        .all()
    )
    recent_events = [
        {
            "id": e.id,
            "ts": e.ts.isoformat(),
            "event_type": e.event_type,
            "severity": e.severity,
            "message": e.message,
            "username": e.username,
        }
        for e in recent
    ]

    # Event types breakdown
    type_rows = (
        db.query(Event.event_type, func.count(Event.id))
        .filter(Event.src_ip == ip)
        .group_by(Event.event_type)
        .order_by(func.count(Event.id).desc())
        .all()
    )
    event_types = [{"type": t, "count": c} for t, c in type_rows]

    # Related incidents
    incident_ids = (
        db.query(IncidentEvent.incident_id)
        .join(Event, Event.id == IncidentEvent.event_id)
        .filter(Event.src_ip == ip)
        .distinct()
        .all()
    )
    incident_id_list = [i[0] for i in incident_ids]

    incidents = []
    if incident_id_list:
        inc_rows = (
            db.query(Incident)
            .filter(Incident.id.in_(incident_id_list))
            .order_by(Incident.created_at.desc())
            .limit(10)
            .all()
        )
        incidents = [
            {
                "id": i.id,
                "title": i.title,
                "severity": i.severity,
                "status": i.status,
                "created_at": i.created_at.isoformat(),
                "rule_id": i.rule_id,
            }
            for i in inc_rows
        ]

    # Threat score
    ts_row = db.get(ThreatScore, ip)
    threat_score = None
    if ts_row:
        import json
        threat_score = {
            "score": ts_row.score,
            "factors": json.loads(ts_row.factors_json) if ts_row.factors_json else {},
            "updated_at": ts_row.updated_at.isoformat(),
        }

    # Related users
    user_rows = (
        db.query(Event.username, func.count(Event.id))
        .filter(Event.src_ip == ip, Event.username.isnot(None))
        .group_by(Event.username)
        .order_by(func.count(Event.id).desc())
        .limit(10)
        .all()
    )
    related_users = [{"username": u, "event_count": c} for u, c in user_rows]

    # Timeline (events per hour last 24h)
    timeline_events = (
        db.query(Event.ts)
        .filter(Event.src_ip == ip, Event.ts >= cutoff_24h)
        .all()
    )
    hour_buckets: dict[str, int] = {}
    for (ts,) in timeline_events:
        key = ts.strftime("%Y-%m-%dT%H:00:00Z")
        hour_buckets[key] = hour_buckets.get(key, 0) + 1

    now = datetime.now(UTC)
    timeline = []
    for i in range(24):
        t = cutoff_24h + timedelta(hours=i)
        if t > now:
            break
        key = t.strftime("%Y-%m-%dT%H:00:00Z")
        timeline.append({"hour": key, "count": hour_buckets.get(key, 0)})

    return {
        "event_count": event_count,
        "recent_events": recent_events,
        "event_types": event_types,
        "incident_count": len(incident_id_list),
        "recent_incidents": incidents,
        "threat_score": threat_score,
        "related_users": related_users,
        "timeline": timeline,
    }


@router.get("/{target}", response_model=InvestigateResponse)
async def investigate(
    target: str,
    db: Session = Depends(get_db),
) -> dict:
    """Investigation complete d'une IP ou d'un domaine."""
    target = target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target required")

    is_ip = _is_ip(target)
    target_type = "ip" if is_ip else "domain"

    # Resolve domain to IP if needed
    resolved_ip = target if is_ip else _resolve_domain(target)

    result: dict = {
        "target": target,
        "target_type": target_type,
        "resolved_ip": resolved_ip,
    }

    # DNS records (for domains)
    if not is_ip:
        result["dns"] = _get_dns_records(target)

    # Reverse DNS (for IPs)
    if resolved_ip:
        result["reverse_dns"] = _reverse_dns(resolved_ip)

    # GeoIP
    if resolved_ip:
        result["geo"] = _get_geo(resolved_ip)

    # WHOIS
    result["whois"] = _get_whois_info(target)

    # Threat Intelligence
    if resolved_ip:
        result["threat_intel"] = await _get_threat_intel(resolved_ip, db)

    # SIEM data
    if resolved_ip:
        siem = _get_siem_data(resolved_ip, db)
        result.update(siem)

    return result
