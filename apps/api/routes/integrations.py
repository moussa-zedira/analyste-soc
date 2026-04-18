"""Routes for outbound ticketing integrations."""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.integrations.outbound import (
    dispatch_to_integrations,
    get_connector_for,
    list_integration_types,
    sync_ticket_status,
)
from apps.api.models.incident import Incident
from apps.api.models.integrations import (
    VALID_INTEGRATION_TYPES,
    VALID_SEVERITY_MIN,
    IncidentTicket,
    OutboundIntegration,
)
from apps.api.security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_key)])


_SECRET_KEYS = {"token", "password", "api_key", "oauth_token", "secret", "client_secret"}


def _mask(value: Any) -> Any:
    if not isinstance(value, str) or not value:
        return value
    if len(value) <= 4:
        return "***"
    return "***" + value[-4:]


def _mask_config(config: dict[str, Any]) -> dict[str, Any]:
    masked: dict[str, Any] = {}
    for k, v in config.items():
        if k.lower() in _SECRET_KEYS:
            masked[k] = _mask(v)
        else:
            masked[k] = v
    return masked


class IntegrationCreate(BaseModel):
    integration_type: str = Field(..., description=f"One of {VALID_INTEGRATION_TYPES}")
    name: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    severity_min: str = "high"
    auto_sync_status: bool = True


class IntegrationUpdate(BaseModel):
    name: str | None = None
    config: dict[str, Any] | None = None
    enabled: bool | None = None
    severity_min: str | None = None
    auto_sync_status: bool | None = None


class IntegrationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    integration_type: str
    name: str
    config: dict[str, Any]
    enabled: bool
    severity_min: str
    auto_sync_status: bool
    created_at: datetime
    updated_at: datetime | None = None


class TicketRead(BaseModel):
    id: str
    incident_id: str
    integration_id: str
    external_ticket_id: str | None
    external_url: str | None
    ticket_status: str | None
    last_synced_at: datetime | None
    synced_attempts: int
    last_error: str | None
    created_at: datetime


def _to_read(integration: OutboundIntegration) -> IntegrationRead:
    try:
        cfg = json.loads(integration.config_json or "{}")
    except (json.JSONDecodeError, TypeError):
        cfg = {}
    return IntegrationRead(
        id=integration.id,
        integration_type=integration.integration_type,
        name=integration.name,
        config=_mask_config(cfg),
        enabled=integration.enabled,
        severity_min=integration.severity_min,
        auto_sync_status=integration.auto_sync_status,
        created_at=integration.created_at,
        updated_at=integration.updated_at,
    )


def _validate_type(t: str) -> None:
    if t not in VALID_INTEGRATION_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid integration_type. Allowed: {list(VALID_INTEGRATION_TYPES)}",
        )


def _validate_severity(s: str) -> None:
    if s not in VALID_SEVERITY_MIN:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid severity_min. Allowed: {list(VALID_SEVERITY_MIN)}",
        )


@router.get("/integrations/types")
def get_integration_types() -> dict[str, list[str]]:
    return {"types": list_integration_types()}


@router.post("/integrations", response_model=IntegrationRead, status_code=status.HTTP_201_CREATED)
def create_integration(payload: IntegrationCreate, db: Session = Depends(get_db)) -> IntegrationRead:
    _validate_type(payload.integration_type)
    _validate_severity(payload.severity_min)

    now = datetime.now(timezone.utc)
    integ = OutboundIntegration(
        id=str(uuid.uuid4()),
        integration_type=payload.integration_type,
        name=payload.name,
        config_json=json.dumps(payload.config or {}),
        enabled=payload.enabled,
        severity_min=payload.severity_min,
        auto_sync_status=payload.auto_sync_status,
        created_at=now,
        updated_at=now,
    )
    db.add(integ)
    db.commit()
    db.refresh(integ)
    return _to_read(integ)


@router.get("/integrations", response_model=list[IntegrationRead])
def list_integrations(
    integration_type: str | None = None,
    enabled: bool | None = None,
    db: Session = Depends(get_db),
) -> list[IntegrationRead]:
    q = db.query(OutboundIntegration)
    if integration_type is not None:
        q = q.filter(OutboundIntegration.integration_type == integration_type)
    if enabled is not None:
        q = q.filter(OutboundIntegration.enabled.is_(enabled))
    return [_to_read(i) for i in q.order_by(OutboundIntegration.created_at.desc()).all()]


@router.get("/integrations/{integration_id}", response_model=IntegrationRead)
def get_integration(integration_id: str, db: Session = Depends(get_db)) -> IntegrationRead:
    integ = db.get(OutboundIntegration, integration_id)
    if integ is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    return _to_read(integ)


@router.put("/integrations/{integration_id}", response_model=IntegrationRead)
def update_integration(
    integration_id: str, payload: IntegrationUpdate, db: Session = Depends(get_db)
) -> IntegrationRead:
    integ = db.get(OutboundIntegration, integration_id)
    if integ is None:
        raise HTTPException(status_code=404, detail="Integration not found")

    if payload.name is not None:
        integ.name = payload.name
    if payload.enabled is not None:
        integ.enabled = payload.enabled
    if payload.severity_min is not None:
        _validate_severity(payload.severity_min)
        integ.severity_min = payload.severity_min
    if payload.auto_sync_status is not None:
        integ.auto_sync_status = payload.auto_sync_status
    if payload.config is not None:
        try:
            current = json.loads(integ.config_json or "{}")
        except (json.JSONDecodeError, TypeError):
            current = {}
        merged: dict[str, Any] = {**current}
        for k, v in payload.config.items():
            if isinstance(v, str) and v.startswith("***"):
                continue
            merged[k] = v
        integ.config_json = json.dumps(merged)

    integ.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(integ)
    return _to_read(integ)


@router.delete("/integrations/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_integration(integration_id: str, db: Session = Depends(get_db)) -> None:
    integ = db.get(OutboundIntegration, integration_id)
    if integ is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    db.delete(integ)
    db.commit()


@router.post("/integrations/{integration_id}/test")
async def test_integration(integration_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    integ = db.get(OutboundIntegration, integration_id)
    if integ is None:
        raise HTTPException(status_code=404, detail="Integration not found")
    connector = get_connector_for(integ)
    if connector is None or not connector.is_configured():
        return {"status": "error", "error": "connector_not_configured"}

    test_incident = {
        "id": "test-" + str(uuid.uuid4())[:8],
        "title": "[TEST] SOC integration verification",
        "description": "Test ticket emitted from SOC platform — safe to close.",
        "severity": "high",
        "rule_id": "TEST-001",
        "entity_key": "test@cyberdef.local",
        "status": "open",
    }
    try:
        result = await connector.create_ticket(test_incident)
        return {"status": "ok", **result}
    except Exception as exc:
        logger.exception("integration_test_failed id=%s", integration_id)
        return {"status": "error", "error": str(exc)[:500]}


@router.get("/incidents/{incident_id}/tickets", response_model=list[TicketRead])
def list_incident_tickets(incident_id: str, db: Session = Depends(get_db)) -> list[TicketRead]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    rows = (
        db.query(IncidentTicket)
        .filter(IncidentTicket.incident_id == incident_id)
        .order_by(IncidentTicket.created_at.desc())
        .all()
    )
    return [TicketRead(**_row_dict(r)) for r in rows]


@router.post("/incidents/{incident_id}/dispatch-outbound", response_model=list[TicketRead])
async def dispatch_outbound_for_incident(
    incident_id: str, db: Session = Depends(get_db)
) -> list[TicketRead]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    payload = {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "rule_id": incident.rule_id,
        "entity_key": incident.entity_key,
        "status": incident.status,
    }
    results = await dispatch_to_integrations(db, payload)
    return [TicketRead(**r) for r in results]


@router.post("/integrations/sync-all")
def trigger_sync_all(background: BackgroundTasks) -> dict[str, str]:
    try:
        from apps.api.integrations.tasks import sync_all_outbound_tickets_task

        sync_all_outbound_tickets_task.delay()
        return {"status": "enqueued", "via": "celery"}
    except Exception:
        logger.warning("celery_unavailable_running_inline")

    async def _inline() -> None:
        from apps.api.db.session import SessionLocal
        from apps.api.integrations.outbound import sync_all_open_tickets

        db = SessionLocal()
        try:
            await sync_all_open_tickets(db)
        finally:
            db.close()

    background.add_task(_inline)
    return {"status": "enqueued", "via": "background"}


@router.post("/incidents/tickets/{ticket_id}/sync", response_model=TicketRead)
async def sync_single_ticket(ticket_id: str, db: Session = Depends(get_db)) -> TicketRead:
    result = await sync_ticket_status(db, ticket_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return TicketRead(**result)


def _row_dict(t: IncidentTicket) -> dict[str, Any]:
    return {
        "id": t.id,
        "incident_id": t.incident_id,
        "integration_id": t.integration_id,
        "external_ticket_id": t.external_ticket_id,
        "external_url": t.external_url,
        "ticket_status": t.ticket_status,
        "last_synced_at": t.last_synced_at,
        "synced_attempts": t.synced_attempts,
        "last_error": t.last_error,
        "created_at": t.created_at,
    }
