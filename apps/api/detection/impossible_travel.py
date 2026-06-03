"""Détection de voyage impossible (impossible-travel.v2) avec géolocalisation réelle.

Algorithme :
- Pour chaque utilisateur, récupère ses événements ``auth.success`` des dernières 24 h.
- Trie par ``ts`` croissant.
- Pour chaque paire (ev_n, ev_n+1) avec IPs distinctes :
    * géolocalise les 2 IPs via ``GeoIPLookup`` (MaxMind GeoLite2-City).
    * calcule la distance Haversine en kilomètres.
    * calcule la vitesse implicite ``km / heures_entre_events``.
    * si vitesse > 900 km/h → flag "impossible travel".
- Sévérité : >1500 → critical, [900-1500] → high.

Stratégie de déduplication : sha256(rule_id | username | bucket_minute_end).
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from apps.api.broadcast import broadcaster
from apps.api.geoip import get_geoip_lookup
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.notifications.webhook import notify_incident_created

logger = logging.getLogger(__name__)

RULE_ID = "impossible-travel.v2"
LOOKBACK = timedelta(hours=24)
SPEED_THRESHOLD_KMH = 900.0  # vitesse avion commercial
SPEED_CRITICAL_KMH = 1500.0  # > avion supersonique → critical
MIN_DISTANCE_KM = 50.0  # ignore les sauts < 50 km (même métropole)


def _compute_dedup_hash(username: str, end_ts: datetime) -> str:
    """Calcule le hash de déduplication pour un utilisateur et un horodatage donnés."""
    bucket = end_ts.strftime("%Y-%m-%dT%H:%M")
    raw = f"{RULE_ID}|user:{username}|{bucket}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _severity_for(speed_kmh: float) -> str:
    """Mappe la vitesse implicite vers une sévérité."""
    if speed_kmh > SPEED_CRITICAL_KMH:
        return "critical"
    return "high"


def run_impossible_travel(db: Session, events: list[Event]) -> int:
    """Exécute la détection de voyage impossible sur les événements pré-chargés.

    Retourne le nombre d'incidents créés.
    """
    cutoff = datetime.now(UTC) - LOOKBACK
    candidates = [
        e
        for e in events
        if e.event_type == "auth.success" and e.username and e.src_ip and e.ts >= cutoff
    ]
    if not candidates:
        return 0

    by_user: dict[str, list[Event]] = defaultdict(list)
    for ev in candidates:
        by_user[ev.username].append(ev)  # type: ignore[arg-type]

    geo = get_geoip_lookup()
    if not geo.available:
        logger.debug("Impossible-travel: GeoIP DB unavailable, skipping detection")
        return 0

    created = 0
    for username, user_events in by_user.items():
        user_events.sort(key=lambda e: e.ts)
        created += _detect_for_user(db, username, user_events, geo)

    return created


def _detect_for_user(
    db: Session,
    username: str,
    events: list[Event],
    geo,
) -> int:
    """Compare paires consécutives d'événements pour un utilisateur."""
    created = 0

    for i in range(len(events) - 1):
        ev1 = events[i]
        ev2 = events[i + 1]

        if ev1.src_ip == ev2.src_ip:
            continue

        geo1 = geo.lookup(ev1.src_ip)
        geo2 = geo.lookup(ev2.src_ip)
        if geo1 is None or geo2 is None:
            continue

        distance_km = geo.haversine_km(
            geo1["lat"],
            geo1["lon"],
            geo2["lat"],
            geo2["lon"],
        )
        if distance_km < MIN_DISTANCE_KM:
            continue

        time_delta = ev2.ts - ev1.ts
        hours = time_delta.total_seconds() / 3600.0
        if hours <= 0:
            # événements simultanés sur 2 IPs distantes → vitesse infinie → critical
            implied_kmh = float("inf")
        else:
            implied_kmh = distance_km / hours

        if implied_kmh <= SPEED_THRESHOLD_KMH:
            continue

        severity = _severity_for(implied_kmh)
        end_ts = ev2.ts
        dedup_hash = _compute_dedup_hash(username, end_ts)

        if db.query(Incident.id).filter(Incident.dedup_hash == dedup_hash).first():
            continue

        incident_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        title = f"Impossible travel: {username} {geo1['city']}->{geo2['city']}"
        speed_str = "infinite" if implied_kmh == float("inf") else f"{implied_kmh:.0f}"
        description = (
            f"User '{username}' authenticated from {ev1.src_ip} ({geo1['city']}, "
            f"{geo1['country']}) then from {ev2.src_ip} ({geo2['city']}, "
            f"{geo2['country']}) — distance {distance_km:.0f} km in "
            f"{time_delta.total_seconds():.0f} s, implied speed {speed_str} km/h."
        )

        incident = Incident(
            id=incident_id,
            created_at=now,
            updated_at=now,
            status="open",
            severity=severity,
            title=title,
            description=description,
            rule_id=RULE_ID,
            entity_key=f"user:{username}",
            start_ts=ev1.ts,
            end_ts=ev2.ts,
            dedup_hash=dedup_hash,
        )
        db.add(incident)
        db.flush()

        db.add(IncidentEvent(incident_id=incident_id, event_id=ev1.id))
        db.add(IncidentEvent(incident_id=incident_id, event_id=ev2.id))

        notify_incident_created(
            incident_id=incident_id,
            title=title,
            severity=severity,
            description=description,
            rule_id=RULE_ID,
            entity_key=f"user:{username}",
            status="open",
            created_at=now.isoformat(),
        )

        broadcaster.publish(
            {
                "type": "new_incident",
                "payload": {
                    "id": incident_id,
                    "title": title,
                    "severity": severity,
                    "rule_id": RULE_ID,
                    "entity_key": f"user:{username}",
                    "status": "open",
                    "created_at": now.isoformat(),
                    "src_ip": ev1.src_ip,
                    "dst_ip": ev2.src_ip,
                    "src_country": geo1["country"],
                    "dst_country": geo2["country"],
                    "distance_km": round(distance_km, 1),
                    "time_delta_s": int(time_delta.total_seconds()),
                    "implied_kmh": None if implied_kmh == float("inf") else round(implied_kmh, 1),
                },
            }
        )

        logger.info(
            "Impossible travel for %s: %s->%s, %.0f km / %.0f s = %s km/h (%s)",
            username,
            geo1["city"],
            geo2["city"],
            distance_km,
            time_delta.total_seconds(),
            speed_str,
            severity,
        )
        created += 1

    return created


# Alias for backward compatibility (anciens callers utilisent ``run``)
run = run_impossible_travel
