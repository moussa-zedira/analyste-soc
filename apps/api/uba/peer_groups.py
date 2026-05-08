"""Peer-group statistics pour UEBA.

Groupe les entites par cle de cohorte (entity_type par defaut) et calcule
les agregats de score (mean, p95, count) qui servent a detecter les
deviations relatives — un user a 60/100 dans un groupe ou la moyenne est
75 est moins suspect qu'un user a 60/100 dans un groupe ou la moyenne est 20.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from typing import Any

from sqlalchemy.orm import Session

from apps.api.models.uba import UserBaseline


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * (pct / 100.0)
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return float(s[int(k)])
    return float(s[lo] + (s[hi] - s[lo]) * (k - lo))


def peer_group_key(baseline: UserBaseline) -> str:
    """Cle de cohorte. Defaut : entity_type.

    Future extension : ajouter un suffixe tag/role lorsque le modele Entity
    portera des tags (ex: "user:admins", "user:devs"). Pour l'instant on
    reste sur entity_type pour eviter de creer des groupes a 1 membre.
    """
    return baseline.entity_type or "_unknown_"


def compute_peer_stats(
    db: Session,
    *,
    baselines: Iterable[UserBaseline] | None = None,
) -> dict[str, dict[str, Any]]:
    """Aggrege les stats par peer-group.

    Si `baselines` n'est pas fourni, charge tous les UserBaseline.
    Retourne {group_key: {members_count, mean_score, p95_score, std_score}}.
    """
    if baselines is None:
        baselines = db.query(UserBaseline).all()

    buckets: dict[str, list[float]] = {}
    for b in baselines:
        key = peer_group_key(b)
        buckets.setdefault(key, []).append(float(b.current_score or 0.0))

    stats: dict[str, dict[str, Any]] = {}
    for key, scores in buckets.items():
        n = len(scores)
        mean = sum(scores) / n if n else 0.0
        var = sum((x - mean) ** 2 for x in scores) / n if n else 0.0
        std = math.sqrt(var)
        stats[key] = {
            "group_id": key,
            "members_count": n,
            "mean_score": round(mean, 2),
            "p95_score": round(_percentile(scores, 95.0), 2),
            "std_score": round(std, 2),
            "max_score": round(max(scores), 2) if scores else 0.0,
            "min_score": round(min(scores), 2) if scores else 0.0,
        }
    return stats


def assign_peer_groups(
    db: Session,
    stats: dict[str, dict[str, Any]] | None = None,
) -> int:
    """Persiste peer_group_id et peer_deviation sur chaque baseline.

    peer_deviation = (current_score - mean) / std (z-score). 0 si std == 0.
    """
    if stats is None:
        stats = compute_peer_stats(db)

    n = 0
    for b in db.query(UserBaseline).all():
        key = peer_group_key(b)
        s = stats.get(key)
        b.peer_group_id = key
        if s and s["std_score"] > 0:
            b.peer_deviation = round(
                (float(b.current_score or 0.0) - s["mean_score"]) / s["std_score"],
                3,
            )
        else:
            b.peer_deviation = 0.0
        n += 1
    db.commit()
    return n
