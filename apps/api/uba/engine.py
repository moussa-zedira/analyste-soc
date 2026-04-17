"""UBA engine : update baselines depuis les evenements + calcul du score.

Approche : Naive Bayes simplifie. Pour chaque evenement recent (lookback),
on calcule p(feature_value | profile) = count[bucket] / total_events. Un
evenement avec features tres rares (faible probabilite) eleve le score.

Score final ∈ [0, 100] :
  100 = activite totalement inhabituelle (compte potentiellement compromis)
  0   = activite parfaitement conforme au baseline historique
"""

from __future__ import annotations

import hashlib
import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from sqlalchemy.orm import Session

from apps.api.models.event import Event
from apps.api.models.uba import UserBaseline

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------

LOOKBACK_MIN = 10
SMOOTHING_ALPHA = 0.5  # Laplace smoothing
TOP_N_KEEP = 100       # Cap sur src_ips/user_agents pour eviter la croissance
HIGH_RISK_THRESHOLD = 70.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ua_hash(ua: str | None) -> str:
    if not ua:
        return "_none_"
    return hashlib.md5(ua.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _hour_bucket(ts: datetime) -> str:
    return str(ts.astimezone(timezone.utc).hour)


def _bump(d: dict[str, int], key: str, by: int = 1, cap: int | None = None) -> None:
    d[key] = d.get(key, 0) + by
    if cap and len(d) > cap:
        # Drop la cle la moins vue
        worst = min(d, key=d.get)
        if worst != key:
            d.pop(worst, None)


def _entity_key(event: Event) -> tuple[str, str] | None:
    """Retourne (entity_type, entity_key) pour un evenement.

    Priorite : user_id (si present dans details) -> src_ip -> host.
    """
    raw = event.raw or {}
    user = raw.get("user") or raw.get("username") or raw.get("user_id")
    if user:
        return "user", str(user)
    if event.src_ip:
        return "ip", event.src_ip
    if event.host:
        return "host", event.host
    return None


def _surprise(observed: int, total: int, distinct_buckets: int) -> float:
    """Surprise (=info content) en bits d'un evenement observe.

    p = (observed + alpha) / (total + alpha * (distinct + 1))
    Plus c'est rare, plus surprise est grand.
    """
    p = (observed + SMOOTHING_ALPHA) / max(total + SMOOTHING_ALPHA * (distinct_buckets + 1), 1.0)
    p = max(min(p, 1.0), 1e-9)
    return -math.log2(p)


# ---------------------------------------------------------------------------
# Update baseline
# ---------------------------------------------------------------------------


def update_baselines(db: Session, since: datetime | None = None) -> dict[str, int]:
    """Avale les evenements depuis `since` et met a jour les baselines.

    Retourne un dict {entities_updated, events_consumed, high_risk_count}.
    """
    if since is None:
        since = datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MIN)

    events = (
        db.query(Event)
        .filter(Event.ts >= since)
        .order_by(Event.ts.asc())
        .limit(5000)
        .all()
    )

    # Group by entity
    by_entity: dict[tuple[str, str], list[Event]] = {}
    for ev in events:
        key = _entity_key(ev)
        if not key:
            continue
        by_entity.setdefault(key, []).append(ev)

    updated = 0
    high_risk = 0
    for (etype, ekey), evs in by_entity.items():
        baseline = (
            db.query(UserBaseline)
            .filter(
                UserBaseline.entity_type == etype,
                UserBaseline.entity_key == ekey,
            )
            .first()
        )
        now = datetime.now(timezone.utc)
        if baseline is None:
            baseline = UserBaseline(
                id=str(uuid.uuid4()),
                entity_type=etype,
                entity_key=ekey,
                total_events=0,
                hours={}, event_types={}, geos={}, src_ips={}, user_agents={},
                current_score=0.0, score_reasons={},
                first_seen=evs[0].ts or now,
                last_seen=evs[-1].ts or now,
                updated_at=now,
            )
            db.add(baseline)

        # Score AVANT incorporation : on mesure la surprise des evenements
        # par rapport au profil HISTORIQUE.
        score_total = 0.0
        score_per_dim: dict[str, float] = {}
        for ev in evs:
            raw = ev.raw or {}
            score_total += _score_event(baseline, ev, raw, score_per_dim)

        avg = score_total / max(len(evs), 1)
        # Normalise vers [0, 100]. Surprise > 10 bits ≈ tres rare.
        baseline.current_score = round(min(max(avg * 10.0, 0.0), 100.0), 2)
        baseline.score_reasons = {
            k: round(v / max(len(evs), 1), 2) for k, v in score_per_dim.items()
        }
        if baseline.current_score >= HIGH_RISK_THRESHOLD:
            high_risk += 1

        # Ensuite on incorpore au profil
        for ev in evs:
            raw = ev.raw or {}
            _ingest_event(baseline, ev, raw)

        baseline.last_seen = evs[-1].ts or now
        baseline.updated_at = now
        updated += 1

    db.commit()
    return {
        "entities_updated": updated,
        "events_consumed": len(events),
        "high_risk_count": high_risk,
    }


def _ingest_event(baseline: UserBaseline, ev: Event, raw: dict[str, Any]) -> None:
    baseline.total_events += 1
    if ev.ts:
        _bump(baseline.hours, _hour_bucket(ev.ts))
    _bump(baseline.event_types, ev.event_type or "_unknown_")
    geo = raw.get("country") or raw.get("geo_country") or raw.get("asn")
    if geo:
        _bump(baseline.geos, str(geo))
    if ev.src_ip:
        _bump(baseline.src_ips, ev.src_ip, cap=TOP_N_KEEP)
    ua = raw.get("user_agent") or raw.get("ua")
    if ua:
        _bump(baseline.user_agents, _ua_hash(ua), cap=TOP_N_KEEP)


def _score_event(
    baseline: UserBaseline,
    ev: Event,
    raw: dict[str, Any],
    accum: dict[str, float],
) -> float:
    total = max(baseline.total_events, 1)
    score = 0.0
    if ev.ts:
        bk = _hour_bucket(ev.ts)
        s = _surprise(baseline.hours.get(bk, 0), total, max(len(baseline.hours), 1))
        score += s
        accum["hour"] = accum.get("hour", 0.0) + s
    if ev.event_type:
        s = _surprise(
            baseline.event_types.get(ev.event_type, 0),
            total,
            max(len(baseline.event_types), 1),
        )
        score += s
        accum["event_type"] = accum.get("event_type", 0.0) + s
    geo = raw.get("country") or raw.get("geo_country") or raw.get("asn")
    if geo:
        s = _surprise(baseline.geos.get(str(geo), 0), total, max(len(baseline.geos), 1))
        score += s
        accum["geo"] = accum.get("geo", 0.0) + s
    if ev.src_ip:
        s = _surprise(
            baseline.src_ips.get(ev.src_ip, 0),
            total,
            max(len(baseline.src_ips), 1),
        )
        score += s
        accum["src_ip"] = accum.get("src_ip", 0.0) + s
    ua = raw.get("user_agent") or raw.get("ua")
    if ua:
        s = _surprise(
            baseline.user_agents.get(_ua_hash(ua), 0),
            total,
            max(len(baseline.user_agents), 1),
        )
        score += s
        accum["user_agent"] = accum.get("user_agent", 0.0) + s
    # Moyenne sur le nombre de dimensions observees
    n_dims = sum(1 for k in ("hour", "event_type", "geo", "src_ip", "user_agent")
                 if k in accum and accum[k] > 0)
    return score / max(n_dims, 1)


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def list_baselines(
    db: Session, *, min_score: float = 0.0, limit: int = 50,
) -> list[dict[str, Any]]:
    q = (
        db.query(UserBaseline)
        .filter(UserBaseline.current_score >= min_score)
        .order_by(UserBaseline.current_score.desc())
        .limit(limit)
    )
    return [_baseline_to_dict(b) for b in q.all()]


def get_baseline(db: Session, entity_type: str, entity_key: str) -> dict[str, Any] | None:
    b = (
        db.query(UserBaseline)
        .filter(UserBaseline.entity_type == entity_type, UserBaseline.entity_key == entity_key)
        .first()
    )
    return _baseline_to_dict(b) if b else None


def _baseline_to_dict(b: UserBaseline) -> dict[str, Any]:
    return {
        "id": b.id,
        "entity_type": b.entity_type,
        "entity_key": b.entity_key,
        "total_events": b.total_events,
        "current_score": b.current_score,
        "score_reasons": b.score_reasons or {},
        "high_risk": b.current_score >= HIGH_RISK_THRESHOLD,
        "first_seen": b.first_seen.isoformat() if b.first_seen else None,
        "last_seen": b.last_seen.isoformat() if b.last_seen else None,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None,
        # Top buckets per dimension (dicts so the JSON shape is stable)
        "hours_top": _top_n(b.hours, 8),
        "event_types_top": _top_n(b.event_types, 8),
        "geos_top": _top_n(b.geos, 8),
        "src_ips_top": _top_n(b.src_ips, 8),
        "user_agents_top": _top_n(b.user_agents, 8),
    }


def _top_n(d: dict[str, int] | None, n: int) -> dict[str, int]:
    if not d:
        return {}
    return dict(sorted(d.items(), key=lambda kv: kv[1], reverse=True)[:n])
