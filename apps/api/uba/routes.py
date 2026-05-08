"""Routes UEBA."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.uba.engine import (
    HIGH_RISK_THRESHOLD,
    LOOKBACK_MIN,
    get_baseline,
    get_baseline_history,
    list_baselines,
    update_baselines,
)
from apps.api.uba.peer_groups import compute_peer_stats

router = APIRouter(prefix="/uba", tags=["UEBA"])


@router.post("/refresh")
def refresh_baselines(
    lookback_min: int = Query(LOOKBACK_MIN, ge=1, le=1440),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Recalcule les baselines a partir des evenements des N dernieres minutes."""
    since = datetime.now(UTC) - timedelta(minutes=lookback_min)
    return update_baselines(db, since=since)


@router.post("/recompute-all")
def recompute_all(
    lookback_hours: int = Query(24, ge=1, le=720),
) -> dict[str, Any]:
    """Enqueue une recomputation globale des baselines (offline, async)."""
    from apps.api.uba.tasks import recompute_all_baselines_task

    async_result = recompute_all_baselines_task.delay(lookback_hours=lookback_hours)
    return {
        "task_id": async_result.id,
        "lookback_hours": lookback_hours,
        "status": "enqueued",
    }


@router.get("/entities")
def list_entities(
    min_score: float = Query(0.0, ge=0.0, le=100.0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Liste les entites profilees, triees par score de risque decroissant."""
    items = list_baselines(db, min_score=min_score, limit=limit)
    return {
        "entities": items,
        "high_risk_threshold": HIGH_RISK_THRESHOLD,
        "count": len(items),
    }


@router.get("/entities/{entity_type}/{entity_key:path}/history")
def get_entity_history(
    entity_type: str,
    entity_key: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Historique de score d'une entite (jusqu'a 168 points = 1 semaine)."""
    h = get_baseline_history(db, entity_type, entity_key)
    if h is None:
        raise HTTPException(status_code=404, detail="entity not profiled")
    return {
        "entity_type": entity_type,
        "entity_key": entity_key,
        "history": h,
        "points": len(h),
    }


@router.get("/entities/{entity_type}/{entity_key:path}")
def get_entity_profile(
    entity_type: str,
    entity_key: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Profil complet d'une entite specifique."""
    b = get_baseline(db, entity_type, entity_key)
    if not b:
        raise HTTPException(status_code=404, detail="entity not profiled")
    return b


@router.get("/peer-groups")
def list_peer_groups(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Stats agregees par cohorte (pour visualisation et triage)."""
    stats = compute_peer_stats(db)
    groups = sorted(
        stats.values(),
        key=lambda s: s["members_count"],
        reverse=True,
    )
    return {"groups": groups, "count": len(groups)}


@router.get("/summary")
def uba_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Resume top niveau pour le dashboard UEBA."""
    items = list_baselines(db, min_score=0.0, limit=1000)
    high = [e for e in items if e["high_risk"]]
    by_type: dict[str, int] = {}
    for e in items:
        by_type[e["entity_type"]] = by_type.get(e["entity_type"], 0) + 1
    return {
        "total_entities": len(items),
        "high_risk_count": len(high),
        "high_risk_threshold": HIGH_RISK_THRESHOLD,
        "by_type": by_type,
        "top_risky": items[:10],
    }
