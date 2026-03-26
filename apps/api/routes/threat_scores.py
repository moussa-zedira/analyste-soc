"""Threat score API — compute and query per-IP risk scores."""

from __future__ import annotations

import json
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.cache import get_cache, set_cache
from apps.api.db.session import get_db
from apps.api.detection.threat_score import compute_threat_scores
from apps.api.models.threat_score import ThreatScore
from apps.api.security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_key)])


class ThreatScoreRead(BaseModel):
    ip: str
    score: float
    factors: dict
    updated_at: datetime


class ThreatScoreComputeResponse(BaseModel):
    ips_scored: int


@router.get("", response_model=list[ThreatScoreRead])
def list_threat_scores(
    limit: int = 20,
    min_score: float = 0.0,
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return top threat-scored IPs, ordered by score descending."""
    cached = get_cache(f"threat_scores:{limit}:{min_score}")
    if cached is not None:
        return cached

    rows = (
        db.query(ThreatScore)
        .filter(ThreatScore.score >= min_score)
        .order_by(ThreatScore.score.desc())
        .limit(limit)
        .all()
    )
    result = [
        {
            "ip": r.ip,
            "score": r.score,
            "factors": json.loads(r.factors_json),
            "updated_at": r.updated_at,
        }
        for r in rows
    ]
    set_cache(f"threat_scores:{limit}:{min_score}", result, ttl=30)
    return result


@router.get("/{ip}", response_model=ThreatScoreRead)
def get_threat_score(ip: str, db: Session = Depends(get_db)) -> dict:
    """Return the threat score for a single IP."""
    row = db.get(ThreatScore, ip)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No threat score found for IP {ip}",
        )
    return {
        "ip": row.ip,
        "score": row.score,
        "factors": json.loads(row.factors_json),
        "updated_at": row.updated_at,
    }


@router.post("/compute", response_model=ThreatScoreComputeResponse)
def compute_scores(
    lookback_hours: int = 24,
    db: Session = Depends(get_db),
) -> dict:
    if lookback_hours < 1 or lookback_hours > 720:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="lookback_hours must be between 1 and 720 (30 days)",
        )
    """Recompute threat scores for all active IPs."""
    try:
        count = compute_threat_scores(db, lookback_hours=lookback_hours)
        return {"ips_scored": count}
    except Exception:
        logger.exception("Threat score computation failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Threat score computation encountered an error.",
        )
