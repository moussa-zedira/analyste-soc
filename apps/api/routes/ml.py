"""API Machine Learning — detection Isolation Forest et classification NLP."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.detection.ml_anomaly import get_model_info, train_and_detect
from apps.api.detection.ml_classifier import (
    classify_incidents,
    get_classifier_info,
)
from apps.api.security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/ml", dependencies=[Depends(require_api_key)], tags=["ml"])

# ---------------------------------------------------------------------------
# Isolation Forest endpoints
# ---------------------------------------------------------------------------


class MLDetectResponse(BaseModel):
    """Reponse de la detection d'anomalies par ML."""

    anomalies_detected: int
    incidents_created: int
    samples_analyzed: int
    error: str | None = None


class MLModelInfo(BaseModel):
    """Informations sur le modele Isolation Forest."""

    n_samples: int | None = None
    n_features: int | None = None
    last_trained: str | None = None
    contamination: float | None = None
    status: str = "not_trained"


@router.post("/detect", response_model=MLDetectResponse)
def run_ml_detection(db: Session = Depends(get_db)) -> dict:
    """Entrainer l'Isolation Forest sur les donnees recentes et detecter les anomalies."""
    try:
        return train_and_detect(db)
    except Exception:
        logger.exception("ML detection failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="ML detection encountered an error.",
        )


@router.get("/model-info", response_model=MLModelInfo)
def model_info() -> dict:
    """Retourner les informations du modele Isolation Forest actuel."""
    return get_model_info()


# ---------------------------------------------------------------------------
# NLP Classification endpoints
# ---------------------------------------------------------------------------


class ClassifyResponse(BaseModel):
    """Reponse de la classification des incidents."""

    status: str
    incidents_classified: int


class ClassifierInfo(BaseModel):
    """Informations sur le classifieur NLP."""

    status: str = "not_trained"
    n_samples: int | None = None
    last_trained: str | None = None


@router.post("/classify", response_model=ClassifyResponse)
def run_classification(db: Session = Depends(get_db)) -> dict:
    """Entrainer le classifieur et classifier les incidents sans severite suggeree."""
    try:
        return classify_incidents(db)
    except Exception:
        logger.exception("Classification failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Classification encountered an error.",
        )


@router.get("/classifier-info", response_model=ClassifierInfo)
def classifier_info() -> dict:
    """Retourner les informations du classifieur NLP actuel."""
    return get_classifier_info()
