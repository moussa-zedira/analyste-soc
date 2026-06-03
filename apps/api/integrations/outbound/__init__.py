"""Outbound ticketing dispatcher — routes incidents to Jira/ServiceNow/Linear/GitHub."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from apps.api.integrations.outbound.base import SEVERITY_RANK, OutboundConnector
from apps.api.integrations.outbound.github_issues import GitHubIssuesConnector
from apps.api.integrations.outbound.jira import JiraConnector
from apps.api.integrations.outbound.linear import LinearConnector
from apps.api.integrations.outbound.servicenow import ServiceNowConnector
from apps.api.models.integrations import (
    VALID_INTEGRATION_TYPES,
    IncidentTicket,
    OutboundIntegration,
)

logger = logging.getLogger(__name__)


_REGISTRY: dict[str, type[OutboundConnector]] = {
    "jira": JiraConnector,
    "servicenow": ServiceNowConnector,
    "linear": LinearConnector,
    "github_issues": GitHubIssuesConnector,
}


def list_integration_types() -> list[str]:
    return list(VALID_INTEGRATION_TYPES)


def _build_connector(integration: OutboundIntegration) -> OutboundConnector | None:
    cls = _REGISTRY.get(integration.integration_type)
    if cls is None:
        return None
    try:
        config = json.loads(integration.config_json or "{}")
    except (json.JSONDecodeError, TypeError):
        logger.warning("integration_invalid_config_json id=%s", integration.id)
        return None
    return cls(config)


def get_connector_for(integration: OutboundIntegration) -> OutboundConnector | None:
    return _build_connector(integration)


def _ticket_to_dict(t: IncidentTicket) -> dict[str, Any]:
    return {
        "id": t.id,
        "incident_id": t.incident_id,
        "integration_id": t.integration_id,
        "external_ticket_id": t.external_ticket_id,
        "external_url": t.external_url,
        "ticket_status": t.ticket_status,
        "last_synced_at": t.last_synced_at.isoformat() if t.last_synced_at else None,
        "synced_attempts": t.synced_attempts,
        "last_error": t.last_error,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


async def dispatch_to_integrations(db: Session, incident: dict[str, Any]) -> list[dict[str, Any]]:
    """Dispatch an incident to all eligible enabled OutboundIntegrations.

    Returns a list of persisted IncidentTicket dicts (one per integration tried).
    """
    incident_id = incident.get("id")
    if not incident_id:
        logger.warning("dispatch_skipped_missing_incident_id")
        return []

    incident_severity = (incident.get("severity") or "low").lower()
    incident_rank = SEVERITY_RANK.get(incident_severity, 0)

    integrations = db.query(OutboundIntegration).filter(OutboundIntegration.enabled.is_(True)).all()

    eligible: list[tuple[OutboundIntegration, OutboundConnector]] = []
    for integ in integrations:
        min_rank = SEVERITY_RANK.get(integ.severity_min or "high", 2)
        if incident_rank < min_rank:
            continue
        connector = _build_connector(integ)
        if connector is None or not connector.is_configured():
            logger.info(
                "integration_skipped_unconfigured id=%s type=%s", integ.id, integ.integration_type
            )
            continue
        eligible.append((integ, connector))

    if not eligible:
        return []

    async def _run(connector: OutboundConnector) -> tuple[bool, dict[str, Any] | str]:
        try:
            res = await connector.create_ticket(incident)
            return True, res
        except Exception as exc:
            logger.exception("integration_create_failed type=%s", connector.name)
            return False, str(exc)[:500]

    results = await asyncio.gather(*[_run(conn) for _, conn in eligible], return_exceptions=False)

    now = datetime.now(UTC)
    persisted: list[dict[str, Any]] = []
    for (integ, _conn), (ok, payload) in zip(eligible, results, strict=False):
        existing = (
            db.query(IncidentTicket)
            .filter(
                IncidentTicket.incident_id == incident_id,
                IncidentTicket.integration_id == integ.id,
            )
            .first()
        )
        if existing is None:
            ticket = IncidentTicket(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                integration_id=integ.id,
                synced_attempts=0,
                created_at=now,
            )
            db.add(ticket)
        else:
            ticket = existing

        ticket.synced_attempts = (ticket.synced_attempts or 0) + 1

        if ok and isinstance(payload, dict):
            ticket.external_ticket_id = payload.get("external_id")
            ticket.external_url = payload.get("url")
            ticket.ticket_status = payload.get("status")
            ticket.last_synced_at = now
            ticket.last_error = None
        else:
            ticket.last_error = payload if isinstance(payload, str) else "unknown_error"

        try:
            db.commit()
            db.refresh(ticket)
        except Exception:
            logger.exception("ticket_persist_failed integration_id=%s", integ.id)
            db.rollback()
            continue

        persisted.append(_ticket_to_dict(ticket))

    return persisted


async def sync_ticket_status(db: Session, ticket_id: str) -> dict[str, Any] | None:
    """Force a status sync for a single IncidentTicket."""
    ticket = db.get(IncidentTicket, ticket_id)
    if ticket is None:
        return None
    integ = db.get(OutboundIntegration, ticket.integration_id)
    if integ is None:
        return None
    connector = _build_connector(integ)
    if connector is None or not connector.is_configured():
        return _ticket_to_dict(ticket)

    try:
        new_status = await connector.sync_status(_ticket_to_dict(ticket))
        ticket.ticket_status = new_status
        ticket.last_synced_at = datetime.now(UTC)
        ticket.last_error = None
    except Exception as exc:
        ticket.last_error = str(exc)[:500]
        logger.exception("ticket_sync_failed ticket_id=%s", ticket_id)

    try:
        db.commit()
        db.refresh(ticket)
    except Exception:
        db.rollback()

    return _ticket_to_dict(ticket)


async def sync_all_open_tickets(db: Session, max_age_minutes: int = 60) -> dict[str, Any]:
    """Sync all tickets whose last_synced_at is older than max_age_minutes.

    Skips tickets attached to integrations with auto_sync_status=False.
    Returns a summary dict.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=max_age_minutes)

    tickets: list[IncidentTicket] = (
        db.query(IncidentTicket)
        .filter(
            (IncidentTicket.last_synced_at.is_(None)) | (IncidentTicket.last_synced_at < cutoff)
        )
        .all()
    )

    integ_cache: dict[str, OutboundIntegration | None] = {}
    synced = 0
    skipped = 0
    errors = 0

    for ticket in tickets:
        integ = integ_cache.get(ticket.integration_id)
        if ticket.integration_id not in integ_cache:
            integ = db.get(OutboundIntegration, ticket.integration_id)
            integ_cache[ticket.integration_id] = integ
        if integ is None or not integ.enabled or not integ.auto_sync_status:
            skipped += 1
            continue
        connector = _build_connector(integ)
        if connector is None or not connector.is_configured():
            skipped += 1
            continue

        try:
            new_status = await connector.sync_status(_ticket_to_dict(ticket))
            if new_status and new_status != ticket.ticket_status:
                ticket.ticket_status = new_status
            ticket.last_synced_at = datetime.now(UTC)
            ticket.last_error = None
            synced += 1
        except Exception as exc:
            ticket.last_error = str(exc)[:500]
            errors += 1
            logger.exception("sync_all_ticket_failed id=%s", ticket.id)

        try:
            db.commit()
        except Exception:
            db.rollback()

    return {"synced": synced, "skipped": skipped, "errors": errors, "total": len(tickets)}


__all__ = [
    "dispatch_to_integrations",
    "sync_ticket_status",
    "sync_all_open_tickets",
    "list_integration_types",
    "get_connector_for",
]
