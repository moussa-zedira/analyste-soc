"""API Alertes — CRUD pour la configuration des canaux d'alerte."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from apps.api.auth import RoleChecker
from apps.api.db.session import get_db
from apps.api.models.alert_config import AlertChannel
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


class AlertChannelCreate(BaseModel):
    """Donnees pour la creation d'un canal d'alerte."""

    channel_type: str  # slack | email | webhook
    name: str
    config_json: str = "{}"
    min_severity: str = "high"


class AlertChannelRead(BaseModel):
    """Schema de lecture d'un canal d'alerte."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    channel_type: str
    name: str
    config_json: str
    enabled: bool
    min_severity: str
    created_at: datetime


class AlertChannelToggle(BaseModel):
    """Donnees pour activer ou desactiver un canal d'alerte."""

    enabled: bool


@router.get("", response_model=list[AlertChannelRead])
def list_channels(db: Session = Depends(get_db)) -> list[AlertChannel]:
    """Lister tous les canaux d'alerte."""
    return db.query(AlertChannel).order_by(AlertChannel.created_at.desc()).all()


@router.post(
    "",
    response_model=AlertChannelRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RoleChecker("admin"))],
)
def create_channel(
    payload: AlertChannelCreate,
    db: Session = Depends(get_db),
) -> AlertChannel:
    """Creer un nouveau canal d'alerte (admin uniquement)."""
    if payload.channel_type not in ("slack", "email", "webhook"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="channel_type must be slack, email, or webhook",
        )

    channel = AlertChannel(
        id=str(uuid.uuid4()),
        channel_type=payload.channel_type,
        name=payload.name,
        config_json=payload.config_json,
        enabled=True,
        min_severity=payload.min_severity,
        created_at=datetime.now(timezone.utc),
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return channel


@router.put(
    "/{channel_id}",
    response_model=AlertChannelRead,
    dependencies=[Depends(RoleChecker("admin"))],
)
def toggle_channel(
    channel_id: str,
    payload: AlertChannelToggle,
    db: Session = Depends(get_db),
) -> AlertChannel:
    """Activer ou desactiver un canal d'alerte (admin uniquement)."""
    channel = db.get(AlertChannel, channel_id)
    if channel is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert channel not found",
        )
    channel.enabled = payload.enabled
    db.commit()
    db.refresh(channel)
    return channel


@router.delete(
    "/{channel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RoleChecker("admin"))],
)
def delete_channel(
    channel_id: str,
    db: Session = Depends(get_db),
) -> None:
    """Supprimer un canal d'alerte (admin uniquement)."""
    channel = db.get(AlertChannel, channel_id)
    if channel is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert channel not found",
        )
    db.delete(channel)
    db.commit()
