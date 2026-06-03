"""API Triage — CRUD liste blanche et configuration du triage."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.db.session import get_db
from apps.api.detection.triage import (
    DEFAULT_CLASSIFICATION,
    EVENT_CLASSIFICATION,
    SEVERITY_ORDER,
    invalidate_whitelist_cache,
)
from apps.api.models.whitelist import WhitelistEntry
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class WhitelistCreate(BaseModel):
    """Donnees pour creer une entree de liste blanche."""

    entry_type: str  # "ip" | "username" | "ip_range"
    value: str
    reason: str = ""


class WhitelistRead(BaseModel):
    """Schema de lecture d'une entree de liste blanche."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    entry_type: str
    value: str
    reason: str
    created_at: datetime
    enabled: bool


class WhitelistToggle(BaseModel):
    """Donnees pour activer ou desactiver une entree de liste blanche."""

    enabled: bool


class TriageConfigRead(BaseModel):
    """Schema de lecture de la configuration du triage."""

    triage_enabled: bool
    min_severity: str
    severity_order: dict[str, int]


class ClassificationRead(BaseModel):
    """Schema de lecture des classifications d'evenements."""

    classifications: dict[str, str]
    default: str


# ---------------------------------------------------------------------------
# Whitelist endpoints
# ---------------------------------------------------------------------------


@router.get("/whitelist", response_model=list[WhitelistRead])
def list_whitelist(db: Session = Depends(get_db)) -> list[WhitelistEntry]:
    """Lister toutes les entrees de la liste blanche."""
    return db.query(WhitelistEntry).order_by(WhitelistEntry.created_at.desc()).all()


@router.post(
    "/whitelist",
    response_model=WhitelistRead,
    status_code=status.HTTP_201_CREATED,
)
def add_whitelist_entry(
    payload: WhitelistCreate,
    db: Session = Depends(get_db),
) -> WhitelistEntry:
    """Ajouter une nouvelle entree a la liste blanche."""
    if payload.entry_type not in ("ip", "username", "ip_range"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="entry_type must be 'ip', 'username', or 'ip_range'",
        )

    entry = WhitelistEntry(
        id=str(uuid.uuid4()),
        entry_type=payload.entry_type,
        value=payload.value,
        reason=payload.reason,
        created_at=datetime.now(UTC),
        enabled=True,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    invalidate_whitelist_cache()
    return entry


@router.put("/whitelist/{entry_id}", response_model=WhitelistRead)
def toggle_whitelist_entry(
    entry_id: str,
    payload: WhitelistToggle,
    db: Session = Depends(get_db),
) -> WhitelistEntry:
    """Activer ou desactiver une entree de la liste blanche."""
    entry = db.get(WhitelistEntry, entry_id)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Whitelist entry not found",
        )
    entry.enabled = payload.enabled
    db.commit()
    db.refresh(entry)
    invalidate_whitelist_cache()
    return entry


@router.delete(
    "/whitelist/{entry_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_whitelist_entry(
    entry_id: str,
    db: Session = Depends(get_db),
) -> None:
    """Supprimer une entree de la liste blanche."""
    entry = db.get(WhitelistEntry, entry_id)
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Whitelist entry not found",
        )
    db.delete(entry)
    db.commit()
    invalidate_whitelist_cache()


# ---------------------------------------------------------------------------
# Config / classifications endpoints
# ---------------------------------------------------------------------------


@router.get("/config", response_model=TriageConfigRead)
def get_triage_config() -> dict:
    """Retourner la configuration actuelle du triage."""
    settings = get_settings()
    return {
        "triage_enabled": settings.TRIAGE_ENABLED,
        "min_severity": settings.MIN_SEVERITY,
        "severity_order": SEVERITY_ORDER,
    }


@router.get("/classifications", response_model=ClassificationRead)
def get_classifications() -> dict:
    """Retourner les classifications d'evenements et la valeur par defaut."""
    return {
        "classifications": EVENT_CLASSIFICATION,
        "default": DEFAULT_CLASSIFICATION,
    }
