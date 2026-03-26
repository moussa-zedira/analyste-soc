"""Anomaly detection API — trigger anomaly detection and view baselines."""

from __future__ import annotations

import logging
import math

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.detection.anomaly import run_anomaly_detection
from apps.api.models.anomaly_baseline import AnomalyBaseline
from apps.api.security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_key)])


class AnomalyRunResponse(BaseModel):
    volume_metrics_evaluated: int
    ip_metrics_evaluated: int
    incidents_created: int


class AnomalyBaselineStat(BaseModel):
    metric_type: str
    metric_key: str
    count: int
    mean: float
    stddev: float
    last_value: float


@router.post("/run", response_model=AnomalyRunResponse)
def run_anomaly(db: Session = Depends(get_db)) -> dict:
    """Execute anomaly detection against recent events."""
    try:
        return run_anomaly_detection(db)
    except Exception:
        logger.exception("Anomaly detection failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Anomaly detection encountered an error.",
        )


@router.get("/baselines", response_model=list[AnomalyBaselineStat])
def list_baselines(
    metric_type: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> list[dict]:
    """Return current anomaly baselines."""
    query = db.query(AnomalyBaseline)
    if metric_type:
        query = query.filter(AnomalyBaseline.metric_type == metric_type)

    baselines = query.order_by(AnomalyBaseline.updated_at.desc()).limit(limit).all()

    return [
        {
            "metric_type": b.metric_type,
            "metric_key": b.metric_key,
            "count": b.count,
            "mean": round(b.mean, 2),
            "stddev": round(math.sqrt(b.variance / (b.count - 1)) if b.count >= 2 else 0.0, 2),
            "last_value": b.last_value,
        }
        for b in baselines
    ]
