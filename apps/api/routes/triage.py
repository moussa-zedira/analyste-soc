"""Triage API — whitelist CRUD + triage configuration."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.db.session import get_db
from apps.api.detection.triage import (
    EVENT_CLASSIFICATION,
    DEFAULT_CLASSIFICATION,
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
    entry_type: str  # "ip" | "username" | "ip_range"
    value: str
    reason: str = ""


class WhitelistRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    entry_type: str
    value: str
    reason: str
    created_at: datetime
    enabled: bool


class WhitelistToggle(BaseModel):
    enabled: bool


class TriageConfigRead(BaseModel):
    triage_enabled: bool
    min_severity: str
    severity_order: dict[str, int]


class ClassificationRead(BaseModel):
    classifications: dict[str, str]
    default: str


# ---------------------------------------------------------------------------
# Whitelist endpoints
# ---------------------------------------------------------------------------


@router.get("/whitelist", response_model=list[WhitelistRead])
def list_whitelist(db: Session = Depends(get_db)) -> list[WhitelistEntry]:
    return (
        db.query(WhitelistEntry)
        .order_by(WhitelistEntry.created_at.desc())
        .all()
    )


@router.post(
    "/whitelist",
    response_model=WhitelistRead,
    status_code=status.HTTP_201_CREATED,
)
def add_whitelist_entry(
    payload: WhitelistCreate,
    db: Session = Depends(get_db),
) -> WhitelistEntry:
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
        created_at=datetime.now(timezone.utc),
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
    settings = get_settings()
    return {
        "triage_enabled": settings.TRIAGE_ENABLED,
        "min_severity": settings.MIN_SEVERITY,
        "severity_order": SEVERITY_ORDER,
    }


@router.get("/classifications", response_model=ClassificationRead)
def get_classifications() -> dict:
    return {
        "classifications": EVENT_CLASSIFICATION,
        "default": DEFAULT_CLASSIFICATION,
    }
