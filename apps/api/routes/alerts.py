"""API Alertes — CRUD channels, rules, and test endpoints."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from apps.api.auth import RoleChecker
from apps.api.db.session import get_db
from apps.api.models.alert_config import AlertChannel, AlertRule, VALID_CHANNEL_TYPES
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class AlertChannelCreate(BaseModel):
    """Create a new alert channel."""
    channel_type: str
    name: str
    config_json: str = "{}"
    min_severity: str = "high"


class AlertChannelUpdate(BaseModel):
    """Update an existing alert channel."""
    name: str | None = None
    channel_type: str | None = None
    config_json: str | None = None
    min_severity: str | None = None
    enabled: bool | None = None


class AlertChannelRead(BaseModel):
    """Read schema for alert channels."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    channel_type: str
    name: str
    config_json: str
    enabled: bool
    min_severity: str
    created_at: datetime
    updated_at: datetime | None = None


class AlertChannelToggle(BaseModel):
    """Toggle channel enabled state (backward compat)."""
    enabled: bool


class AlertRuleCreate(BaseModel):
    """Create a condition-to-channel mapping rule."""
    name: str
    description: str = ""
    conditions_json: str = "{}"
    channel_id: str
    priority: int = 0


class AlertRuleUpdate(BaseModel):
    """Update an alert rule."""
    name: str | None = None
    description: str | None = None
    conditions_json: str | None = None
    channel_id: str | None = None
    enabled: bool | None = None
    priority: int | None = None


class AlertRuleRead(BaseModel):
    """Read schema for alert rules."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: str
    conditions_json: str
    channel_id: str
    enabled: bool
    priority: int
    created_at: datetime
    updated_at: datetime | None = None


class TestAlertResult(BaseModel):
    """Result of a test alert."""
    status: str
    channel_type: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Channel endpoints
# ---------------------------------------------------------------------------

@router.get("/channels", response_model=list[AlertChannelRead])
def list_channels(db: Session = Depends(get_db)) -> list[AlertChannel]:
    """List all alert channels."""
    return db.query(AlertChannel).order_by(AlertChannel.created_at.desc()).all()


# Backward compat: GET "" also lists channels
@router.get("", response_model=list[AlertChannelRead])
def list_channels_compat(db: Session = Depends(get_db)) -> list[AlertChannel]:
    """List all alert channels (backward-compatible endpoint)."""
    return db.query(AlertChannel).order_by(AlertChannel.created_at.desc()).all()


@router.post(
    "/channels",
    response_model=AlertChannelRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RoleChecker("admin"))],
)
def create_channel(
    payload: AlertChannelCreate,
    db: Session = Depends(get_db),
) -> AlertChannel:
    """Create a new alert channel (admin only)."""
    if payload.channel_type not in VALID_CHANNEL_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"channel_type must be one of: {', '.join(VALID_CHANNEL_TYPES)}",
        )
    if payload.min_severity not in ("low", "medium", "high", "critical"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="min_severity must be low, medium, high, or critical",
        )
    # Validate config JSON
    try:
        json.loads(payload.config_json)
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="config_json is not valid JSON",
        )

    now = datetime.now(timezone.utc)
    channel = AlertChannel(
        id=str(uuid.uuid4()),
        channel_type=payload.channel_type,
        name=payload.name,
        config_json=payload.config_json,
        enabled=True,
        min_severity=payload.min_severity,
        created_at=now,
        updated_at=now,
    )
    db.add(channel)
    db.commit()
    db.refresh(channel)
    return channel


# Backward compat: POST "" also creates
@router.post(
    "",
    response_model=AlertChannelRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RoleChecker("admin"))],
)
def create_channel_compat(
    payload: AlertChannelCreate,
    db: Session = Depends(get_db),
) -> AlertChannel:
    """Create a new alert channel (backward-compatible endpoint)."""
    return create_channel(payload, db)


@router.put(
    "/channels/{channel_id}",
    response_model=AlertChannelRead,
    dependencies=[Depends(RoleChecker("admin"))],
)
def update_channel(
    channel_id: str,
    payload: AlertChannelUpdate,
    db: Session = Depends(get_db),
) -> AlertChannel:
    """Update an alert channel (admin only)."""
    channel = db.get(AlertChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Alert channel not found")

    if payload.name is not None:
        channel.name = payload.name
    if payload.channel_type is not None:
        if payload.channel_type not in VALID_CHANNEL_TYPES:
            raise HTTPException(
                status_code=400,
                detail=f"channel_type must be one of: {', '.join(VALID_CHANNEL_TYPES)}",
            )
        channel.channel_type = payload.channel_type
    if payload.config_json is not None:
        try:
            json.loads(payload.config_json)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="config_json is not valid JSON")
        channel.config_json = payload.config_json
    if payload.min_severity is not None:
        channel.min_severity = payload.min_severity
    if payload.enabled is not None:
        channel.enabled = payload.enabled

    channel.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(channel)
    return channel


# Backward compat: PUT "/{channel_id}" with toggle schema
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
    """Toggle an alert channel enabled state (backward-compatible)."""
    channel = db.get(AlertChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Alert channel not found")
    channel.enabled = payload.enabled
    channel.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(channel)
    return channel


@router.delete(
    "/channels/{channel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RoleChecker("admin"))],
)
def delete_channel(
    channel_id: str,
    db: Session = Depends(get_db),
) -> None:
    """Delete an alert channel (admin only)."""
    channel = db.get(AlertChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Alert channel not found")
    # Also delete rules referencing this channel
    db.query(AlertRule).filter(AlertRule.channel_id == channel_id).delete()
    db.delete(channel)
    db.commit()


# Backward compat: DELETE "/{channel_id}"
@router.delete(
    "/{channel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RoleChecker("admin"))],
)
def delete_channel_compat(
    channel_id: str,
    db: Session = Depends(get_db),
) -> None:
    """Delete an alert channel (backward-compatible endpoint)."""
    delete_channel(channel_id, db)


@router.post(
    "/channels/{channel_id}/test",
    response_model=TestAlertResult,
    dependencies=[Depends(RoleChecker("admin"))],
)
async def test_channel(
    channel_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Send a test alert through a specific channel."""
    channel = db.get(AlertChannel, channel_id)
    if channel is None:
        raise HTTPException(status_code=404, detail="Alert channel not found")

    from apps.api.alerting import send_test_alert
    result = await send_test_alert(channel)
    return result


# ---------------------------------------------------------------------------
# Alert Rule endpoints
# ---------------------------------------------------------------------------

@router.get("/rules", response_model=list[AlertRuleRead])
def list_rules(db: Session = Depends(get_db)) -> list[AlertRule]:
    """List all alert rules."""
    return db.query(AlertRule).order_by(AlertRule.priority.desc()).all()


@router.post(
    "/rules",
    response_model=AlertRuleRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(RoleChecker("admin"))],
)
def create_rule(
    payload: AlertRuleCreate,
    db: Session = Depends(get_db),
) -> AlertRule:
    """Create an alert rule (condition -> channel mapping)."""
    # Validate channel exists
    channel = db.get(AlertChannel, payload.channel_id)
    if channel is None:
        raise HTTPException(status_code=400, detail="Referenced channel_id does not exist")

    try:
        json.loads(payload.conditions_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="conditions_json is not valid JSON")

    now = datetime.now(timezone.utc)
    rule = AlertRule(
        id=str(uuid.uuid4()),
        name=payload.name,
        description=payload.description,
        conditions_json=payload.conditions_json,
        channel_id=payload.channel_id,
        enabled=True,
        priority=payload.priority,
        created_at=now,
        updated_at=now,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


@router.put(
    "/rules/{rule_id}",
    response_model=AlertRuleRead,
    dependencies=[Depends(RoleChecker("admin"))],
)
def update_rule(
    rule_id: str,
    payload: AlertRuleUpdate,
    db: Session = Depends(get_db),
) -> AlertRule:
    """Update an alert rule."""
    rule = db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    if payload.name is not None:
        rule.name = payload.name
    if payload.description is not None:
        rule.description = payload.description
    if payload.conditions_json is not None:
        try:
            json.loads(payload.conditions_json)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="conditions_json is not valid JSON")
        rule.conditions_json = payload.conditions_json
    if payload.channel_id is not None:
        ch = db.get(AlertChannel, payload.channel_id)
        if ch is None:
            raise HTTPException(status_code=400, detail="Referenced channel_id does not exist")
        rule.channel_id = payload.channel_id
    if payload.enabled is not None:
        rule.enabled = payload.enabled
    if payload.priority is not None:
        rule.priority = payload.priority

    rule.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(rule)
    return rule


@router.delete(
    "/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(RoleChecker("admin"))],
)
def delete_rule(
    rule_id: str,
    db: Session = Depends(get_db),
) -> None:
    """Delete an alert rule."""
    rule = db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    db.delete(rule)
    db.commit()
