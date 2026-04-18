"""Models for outbound ticketing integrations (Jira, ServiceNow, Linear, GitHub Issues)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Text, UniqueConstraint, Index
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


VALID_INTEGRATION_TYPES = (
    "jira",
    "servicenow",
    "linear",
    "github_issues",
)

VALID_SEVERITY_MIN = ("low", "medium", "high", "critical")


class OutboundIntegration(Base):
    """Outbound ticketing integration configuration."""

    __tablename__ = "outbound_integrations"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    integration_type: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    config_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    severity_min: Mapped[str] = mapped_column(Text, nullable=False, default="high")
    auto_sync_status: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_outbound_integrations_type_enabled", "integration_type", "enabled"),
    )


class IncidentTicket(Base):
    """Persisted external ticket created from an Incident."""

    __tablename__ = "incident_tickets"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    incident_id: Mapped[str] = mapped_column(
        Text, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    integration_id: Mapped[str] = mapped_column(
        Text, ForeignKey("outbound_integrations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    external_ticket_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    external_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    ticket_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    synced_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("incident_id", "integration_id", name="uq_incident_integration"),
        Index("ix_incident_tickets_last_synced_at", "last_synced_at"),
    )
