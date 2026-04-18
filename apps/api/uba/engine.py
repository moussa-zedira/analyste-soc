"""UBA engine : update baselines depuis les evenements + calcul du score.

Approche : Naive Bayes simplifie. Pour chaque evenement recent (lookback),
on calcule p(feature_value | profile) = count[bucket] / total_events. Un
evenement avec features tres rares (faible probabilite) eleve le score.

Score final ∈ [0, 100] :
  100 = activite totalement inhabituelle (compte potentiellement compromis)
  0   = activite parfaitement conforme au baseline historique

Ameliorations v3.1 :
  - Bootstrap window : pondere le score pour les entites < BOOTSTRAP_MIN events
  - Dimension weights : geo et user_agent ponderent davantage que hour
  - Day-of-week buckets : capture la saisonnalite hebdomadaire
  - Score history : conserve les 168 derniers points (1 semaine horaire)
  - Peer deviation : score relatif a la cohorte (z-score)
"""

from __future__ import annotations

import hashlib
import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

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

# Pondere chaque dimension : geo et user_agent sont les plus discriminants,
# day_bucket capture la saisonnalite hebdo, hour est le plus bruite.
DIMENSION_WEIGHTS: dict[str, float] = {
    "hour": 0.6,
    "day_bucket": 0.8,
    "event_type": 1.0,
    "geo": 1.6,
    "src_ip": 1.2,
    "user_agent": 1.4,
}

# Bootstrap : sous ce seuil de total_events on attenue le score (confiance basse)
BOOTSTRAP_MIN = 50

# History : on garde 168 points (1 semaine x 24h) pour calcul vitesse / trend
SCORE_HISTORY_MAX = 168

# Buckets day-of-week (0=lundi .. 6=dimanche, on collapse sam/dim en weekend)
DAY_BUCKETS: dict[int, str] = {
    0: "weekday", 1: "weekday", 2: "weekday", 3: "weekday", 4: "weekday",
    5: "weekend", 6: "weekend",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ua_hash(ua: str | None) -> str:
    if not ua:
        return "_none_"
    return hashlib.md5(ua.encode("utf-8", errors="ignore")).hexdigest()[:12]


def _hour_bucket(ts: datetime) -> str:
    return str(ts.astimezone(timezone.utc).hour)


def _day_bucket(ts: datetime) -> str:
    return DAY_BUCKETS.get(ts.astimezone(timezone.utc).weekday(), "weekday")


def _bump(d: dict[str, int], key: str, by: int = 1, cap: int | None = None) -> None:
    d[key] = d.get(key, 0) + by
    if cap and len(d) > cap:
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


def _bootstrap_weight(total_events: int) -> float:
    """Confiance dans le score : 0.0 a froid, 1.0 quand >= BOOTSTRAP_MIN.

    Evite qu'une entite vue 2 fois deviennent immediatement "high risk".
    """
    if total_events <= 0:
        return 0.0
    return min(total_events / float(BOOTSTRAP_MIN), 1.0)


def _append_history(history: list[dict[str, Any]] | None, score: float, ts: datetime) -> list[dict[str, Any]]:
    h = list(history or [])
    h.append({"ts": ts.isoformat(), "score": round(score, 2)})
    if len(h) > SCORE_HISTORY_MAX:
        h = h[-SCORE_HISTORY_MAX:]
    return h


# ---------------------------------------------------------------------------
# Update baseline
# ---------------------------------------------------------------------------


def update_baselines(db: Session, since: datetime | None = None) -> dict[str, int]:
    """Avale les evenements depuis `since` et met a jour les baselines.

    Retourne un dict {entities_updated, events_consumed, high_risk_count,
    peer_groups}.
    """
    if since is None:
        since = datetime.now(timezone.utc) - timedelta(minutes=LOOKBACK_MIN)

    events = (
        db.query(Event)
        .filter(Event.ts >= since)
        .order_by(Event.ts.asc())
        .limit(20000)
        .all()
    )

    by_entity: dict[tuple[str, str], list[Event]] = {}
    for ev in events:
        key = _entity_key(ev)
        if not key:
            continue
        by_entity.setdefault(key, []).append(ev)

    updated = 0
    high_risk = 0
    touched_baselines: list[UserBaseline] = []
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
                previous_score=None,
                score_history=[],
                peer_group_id=etype,
                peer_deviation=0.0,
                first_seen=evs[0].ts or now,
                last_seen=evs[-1].ts or now,
                updated_at=now,
            )
            db.add(baseline)

        score_total = 0.0
        score_per_dim: dict[str, float] = {}
        for ev in evs:
            raw = ev.raw or {}
            score_total += _score_event(baseline, ev, raw, score_per_dim)

        avg = score_total / max(len(evs), 1)
        raw_score = min(max(avg * 10.0, 0.0), 100.0)
        confidence = _bootstrap_weight(baseline.total_events)
        weighted_score = round(raw_score * confidence, 2)

        baseline.previous_score = baseline.current_score
        baseline.current_score = weighted_score
        baseline.score_reasons = {
            k: round(v / max(len(evs), 1), 2) for k, v in score_per_dim.items()
        }
        baseline.score_history = _append_history(
            baseline.score_history, weighted_score, now
        )
        if weighted_score >= HIGH_RISK_THRESHOLD:
            high_risk += 1

        for ev in evs:
            raw = ev.raw or {}
            _ingest_event(baseline, ev, raw)

        baseline.last_seen = evs[-1].ts or now
        baseline.updated_at = now
        baseline.peer_group_id = baseline.peer_group_id or etype
        touched_baselines.append(baseline)
        updated += 1

    db.flush()

    from apps.api.uba.peer_groups import compute_peer_stats, peer_group_key

    stats = compute_peer_stats(db)
    for b in touched_baselines:
        s = stats.get(peer_group_key(b))
        if s and s["std_score"] > 0:
            b.peer_deviation = round(
                (float(b.current_score or 0.0) - s["mean_score"]) / s["std_score"],
                3,
            )
        else:
            b.peer_deviation = 0.0

    db.commit()
    return {
        "entities_updated": updated,
        "events_consumed": len(events),
        "high_risk_count": high_risk,
        "peer_groups": len(stats),
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
    """Score pondere d'un evenement vs le profil historique de l'entite.

    Chaque dimension contribue selon DIMENSION_WEIGHTS. La saisonnalite
    weekday/weekend est traitee comme une dimension supplementaire derivee
    du timestamp (les `hours` distribuees servent encore pour l'heure brute).
    """
    total = max(baseline.total_events, 1)
    score = 0.0
    weight_sum = 0.0

    if ev.ts:
        bk = _hour_bucket(ev.ts)
        s = _surprise(baseline.hours.get(bk, 0), total, max(len(baseline.hours), 1))
        w = DIMENSION_WEIGHTS["hour"]
        score += s * w
        weight_sum += w
        accum["hour"] = accum.get("hour", 0.0) + s

        # Bucket day-of-week stocke dans le meme dict `hours` sous prefixe "dow_"
        # pour rester retrocompatible (pas de nouveau JSON).
        dbk = "dow_" + _day_bucket(ev.ts)
        s = _surprise(
            baseline.hours.get(dbk, 0),
            total,
            max(len(baseline.hours), 1),
        )
        w = DIMENSION_WEIGHTS["day_bucket"]
        score += s * w
        weight_sum += w
        accum["day_bucket"] = accum.get("day_bucket", 0.0) + s
        # Incremente directement le compteur dow_ pour qu'il soit pris en
        # compte au prochain scoring (sinon la dimension reste sur-surprise).
        _bump(baseline.hours, dbk)

    if ev.event_type:
        s = _surprise(
            baseline.event_types.get(ev.event_type, 0),
            total,
            max(len(baseline.event_types), 1),
        )
        w = DIMENSION_WEIGHTS["event_type"]
        score += s * w
        weight_sum += w
        accum["event_type"] = accum.get("event_type", 0.0) + s

    geo = raw.get("country") or raw.get("geo_country") or raw.get("asn")
    if geo:
        s = _surprise(baseline.geos.get(str(geo), 0), total, max(len(baseline.geos), 1))
        w = DIMENSION_WEIGHTS["geo"]
        score += s * w
        weight_sum += w
        accum["geo"] = accum.get("geo", 0.0) + s

    if ev.src_ip:
        s = _surprise(
            baseline.src_ips.get(ev.src_ip, 0),
            total,
            max(len(baseline.src_ips), 1),
        )
        w = DIMENSION_WEIGHTS["src_ip"]
        score += s * w
        weight_sum += w
        accum["src_ip"] = accum.get("src_ip", 0.0) + s

    ua = raw.get("user_agent") or raw.get("ua")
    if ua:
        s = _surprise(
            baseline.user_agents.get(_ua_hash(ua), 0),
            total,
            max(len(baseline.user_agents), 1),
        )
        w = DIMENSION_WEIGHTS["user_agent"]
        score += s * w
        weight_sum += w
        accum["user_agent"] = accum.get("user_agent", 0.0) + s

    return score / max(weight_sum, 1.0)


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


def get_baseline_history(
    db: Session, entity_type: str, entity_key: str
) -> list[dict[str, Any]] | None:
    b = (
        db.query(UserBaseline)
        .filter(UserBaseline.entity_type == entity_type, UserBaseline.entity_key == entity_key)
        .first()
    )
    if not b:
        return None
    return list(b.score_history or [])


def _baseline_to_dict(b: UserBaseline) -> dict[str, Any]:
    return {
        "id": b.id,
        "entity_type": b.entity_type,
        "entity_key": b.entity_key,
        "total_events": b.total_events,
        "current_score": b.current_score,
        "previous_score": b.previous_score,
        "score_velocity": (
            round((b.current_score or 0.0) - (b.previous_score or 0.0), 2)
            if b.previous_score is not None else 0.0
        ),
        "peer_group_id": b.peer_group_id,
        "peer_deviation": b.peer_deviation,
        "bootstrap_confidence": round(_bootstrap_weight(b.total_events), 2),
        "score_reasons": b.score_reasons or {},
        "high_risk": b.current_score >= HIGH_RISK_THRESHOLD,
        "first_seen": b.first_seen.isoformat() if b.first_seen else None,
        "last_seen": b.last_seen.isoformat() if b.last_seen else None,
        "updated_at": b.updated_at.isoformat() if b.updated_at else None,
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
