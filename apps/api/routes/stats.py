"""API Statistiques — points de terminaison d'agregation pour les visualisations du tableau de bord."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.cache import get_cache, set_cache
from apps.api.db.session import get_db
from apps.api.detection.mitre import (
    RULE_MITRE_MAP,
    TACTIC_ORDER,
    get_all_mapped_techniques,
)
from apps.api.geoip import lookup_batch
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class EventsPerMinuteBucket(BaseModel):
    """Seau d'evenements par minute pour les graphiques."""

    minute: str
    count: int


class HeatmapCell(BaseModel):
    """Cellule de la carte de chaleur des attaques."""

    day_of_week: int
    hour: int
    count: int


class GeoEvent(BaseModel):
    """Evenement geolocalise par IP source."""

    src_ip: str
    lat: float
    lon: float
    country: str
    city: str
    event_count: int
    max_severity: str


class GraphNode(BaseModel):
    """Noeud du graphe de relations."""

    id: str
    type: str
    label: str
    severity: str | None = None
    event_count: int | None = None


class GraphEdge(BaseModel):
    """Arete du graphe de relations."""

    source: str
    target: str
    weight: int


class GraphData(BaseModel):
    """Donnees du graphe de relations (noeuds et aretes)."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]


# ---------------------------------------------------------------------------
# Schemas — KPIs
# ---------------------------------------------------------------------------


class KpiResponse(BaseModel):
    """Indicateurs cles de performance du tableau de bord."""

    total_events_24h: int
    open_incidents: int
    high_incidents_24h: int


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/kpis", response_model=KpiResponse)
def kpis(db: Session = Depends(get_db)) -> dict:
    """Retourner les indicateurs cles de performance calcules cote serveur."""
    cached = get_cache("stats:kpis")
    if cached is not None:
        return cached

    cutoff = datetime.now(UTC) - timedelta(hours=24)

    total_events_24h = (
        db.query(func.count(Event.id)).filter(Event.ts >= cutoff).scalar() or 0
    )
    open_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.status == "open")
        .scalar()
        or 0
    )
    high_incidents_24h = (
        db.query(func.count(Incident.id))
        .filter(Incident.severity == "high", Incident.created_at >= cutoff)
        .scalar()
        or 0
    )

    result = {
        "total_events_24h": total_events_24h,
        "open_incidents": open_incidents,
        "high_incidents_24h": high_incidents_24h,
    }
    set_cache("stats:kpis", result, ttl=30)
    return result


@router.get("/events-per-minute", response_model=list[EventsPerMinuteBucket])
def events_per_minute(
    minutes: int = 60,
    db: Session = Depends(get_db),
) -> list[dict]:
    """Retourner le nombre d'evenements par minute sur la periode demandee."""
    cached = get_cache(f"stats:epm:{minutes}")
    if cached is not None:
        return cached

    cutoff = datetime.now(UTC) - timedelta(minutes=minutes)

    rows = db.query(Event).filter(Event.ts >= cutoff).order_by(Event.ts).all()

    buckets: dict[str, int] = defaultdict(int)
    for event in rows:
        key = event.ts.strftime("%Y-%m-%dT%H:%M:00Z")
        buckets[key] += 1

    now = datetime.now(UTC)
    result = []
    for i in range(minutes):
        t = cutoff + timedelta(minutes=i)
        if t > now:
            break
        key = t.strftime("%Y-%m-%dT%H:%M:00Z")
        result.append({"minute": key, "count": buckets.get(key, 0)})

    set_cache(f"stats:epm:{minutes}", result, ttl=15)
    return result


@router.get("/attack-heatmap", response_model=list[HeatmapCell])
def attack_heatmap(
    days: int = 28,
    db: Session = Depends(get_db),
) -> list[dict]:
    """Retourner la carte de chaleur des attaques par jour et heure."""
    cached = get_cache(f"stats:heatmap:{days}")
    if cached is not None:
        return cached

    cutoff = datetime.now(UTC) - timedelta(days=days)

    events = db.query(Event).filter(Event.ts >= cutoff).all()

    grid: dict[tuple[int, int], int] = defaultdict(int)
    for ev in events:
        grid[(ev.ts.weekday(), ev.ts.hour)] += 1

    result = [
        {"day_of_week": dow, "hour": hour, "count": grid.get((dow, hour), 0)}
        for dow in range(7)
        for hour in range(24)
    ]
    set_cache(f"stats:heatmap:{days}", result, ttl=60)
    return result


@router.get("/geo-events", response_model=list[GeoEvent])
def geo_events(
    limit: int = 100,
    db: Session = Depends(get_db),
) -> list[dict]:
    """Retourner les evenements geolocalises par IP source."""
    cached = get_cache(f"stats:geo:{limit}")
    if cached is not None:
        return cached

    rows = (
        db.query(Event.src_ip, func.count(Event.id).label("event_count"))
        .filter(Event.src_ip.isnot(None))
        .group_by(Event.src_ip)
        .order_by(func.count(Event.id).desc())
        .limit(limit)
        .all()
    )

    if not rows:
        return []

    ips = [r[0] for r in rows]
    ip_counts = {r[0]: r[1] for r in rows}

    # Max severity per IP
    sev_rows = (
        db.query(Event.src_ip, Event.severity)
        .filter(Event.src_ip.in_(ips))
        .all()
    )
    ip_max_sev: dict[str, str] = {}
    for ip, sev in sev_rows:
        cur = ip_max_sev.get(ip, "low")
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(cur, 0):
            ip_max_sev[ip] = sev

    # GeoIP lookup (MaxMind local DB with ip-api.com fallback)
    geo_data = lookup_batch(ips)

    results = []
    for ip, geo in geo_data.items():
        results.append({
            "src_ip": ip,
            "lat": geo.get("lat", 0),
            "lon": geo.get("lon", 0),
            "country": geo.get("country", "Unknown"),
            "city": geo.get("city", "Unknown"),
            "event_count": ip_counts.get(ip, 0),
            "max_severity": ip_max_sev.get(ip, "low"),
        })

    set_cache(f"stats:geo:{limit}", results, ttl=300)
    return results


@router.get("/graph", response_model=GraphData)
def relationship_graph(
    limit: int = 200,
    db: Session = Depends(get_db),
) -> dict:
    """Retourner le graphe de relations entre IPs, utilisateurs et incidents."""
    events = db.query(Event).order_by(Event.ts.desc()).limit(limit).all()

    nodes: dict[str, dict] = {}
    edge_counter: dict[tuple[str, str], int] = defaultdict(int)

    for ev in events:
        if ev.src_ip:
            ip_id = f"ip:{ev.src_ip}"
            if ip_id not in nodes:
                nodes[ip_id] = {
                    "id": ip_id, "type": "ip",
                    "label": ev.src_ip, "severity": None, "event_count": 0,
                }
            nodes[ip_id]["event_count"] += 1

        if ev.username:
            user_id = f"user:{ev.username}"
            if user_id not in nodes:
                nodes[user_id] = {
                    "id": user_id, "type": "user",
                    "label": ev.username, "severity": None, "event_count": 0,
                }
            nodes[user_id]["event_count"] += 1

        if ev.src_ip and ev.username:
            pair = tuple(sorted([f"ip:{ev.src_ip}", f"user:{ev.username}"]))
            edge_counter[pair] += 1

    # Add incident nodes and edges
    incident_events = (
        db.query(IncidentEvent, Incident)
        .join(Incident, IncidentEvent.incident_id == Incident.id)
        .all()
    )

    event_cache: dict[str, Event] = {ev.id: ev for ev in events}

    for ie, inc in incident_events:
        inc_id = f"incident:{inc.id}"
        if inc_id not in nodes:
            nodes[inc_id] = {
                "id": inc_id, "type": "incident",
                "label": inc.title, "severity": inc.severity,
                "event_count": None,
            }

        event = event_cache.get(ie.event_id) or db.get(Event, ie.event_id)
        if event:
            if event.src_ip:
                pair = tuple(sorted([inc_id, f"ip:{event.src_ip}"]))
                edge_counter[pair] += 1
            if event.username:
                pair = tuple(sorted([inc_id, f"user:{event.username}"]))
                edge_counter[pair] += 1

    edges = [
        {"source": pair[0], "target": pair[1], "weight": count}
        for pair, count in edge_counter.items()
    ]

    return {"nodes": list(nodes.values()), "edges": edges}




# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------


class MitreTechniqueInfo(BaseModel):
    """Informations d'une technique MITRE ATT&CK avec compteurs d'incidents."""

    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    url: str
    rule_ids: list[str]
    incident_count: int


class MitreStatsResponse(BaseModel):
    """Reponse des statistiques de couverture MITRE ATT&CK."""

    tactics: list[dict]
    techniques: list[MitreTechniqueInfo]
    total_mapped_incidents: int


@router.get("/mitre", response_model=MitreStatsResponse)
def mitre_stats(db: Session = Depends(get_db)) -> dict:
    """Retourner la couverture MITRE ATT&CK avec le nombre d'incidents par technique."""
    rule_counts = dict(
        db.query(Incident.rule_id, func.count(Incident.id))
        .group_by(Incident.rule_id)
        .all()
    )

    techniques_out: list[dict] = []
    total = 0

    for tech in get_all_mapped_techniques():
        mapped_rules = [
            rid for rid, techs in RULE_MITRE_MAP.items()
            if any(t.id == tech.id for t in techs)
        ]
        count = sum(rule_counts.get(rid, 0) for rid in mapped_rules)
        total += count

        techniques_out.append({
            "technique_id": tech.id,
            "technique_name": tech.name,
            "tactic_id": tech.tactic_id,
            "tactic_name": tech.tactic_name,
            "url": tech.url,
            "rule_ids": mapped_rules,
            "incident_count": count,
        })

    return {
        "tactics": TACTIC_ORDER,
        "techniques": techniques_out,
        "total_mapped_incidents": total,
    }
