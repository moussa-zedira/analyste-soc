"""Modeles Engagement red team (V4.3b).

Un Engagement encadre une mission : scope, dates, kill switch, RoE,
membres autorises, audit log signe.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    PrimaryKeyConstraint,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class Engagement(Base):
    """Une mission red team encadree (scope + dates + kill switch + RoE)."""

    __tablename__ = "engagements"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    client_name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="draft"
    )  # draft | active | paused | closed
    scope_targets: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    excluded_targets: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    start_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    roe_document_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    kill_switch_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str | None] = mapped_column(
        Text, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mitre_tactics_authorized: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_engagements_status", "status"),
        Index("ix_engagements_client_name", "client_name"),
    )


class EngagementMember(Base):
    """Lien user <-> engagement avec role (lead / operator / observer)."""

    __tablename__ = "engagement_members"

    engagement_id: Mapped[str] = mapped_column(
        Text, ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        Text, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role: Mapped[str] = mapped_column(
        Text, nullable=False, default="operator"
    )  # lead | operator | observer
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        PrimaryKeyConstraint("engagement_id", "user_id", name="pk_engagement_members"),
        Index("ix_engagement_members_user", "user_id"),
    )


class OperatorAuditLog(Base):
    """Log signe HMAC-SHA256 de toutes les actions operateur red team."""

    __tablename__ = "operator_audit_log"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    engagement_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("engagements.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action_type: Mapped[str] = mapped_column(Text, nullable=False)
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    command: Mapped[str] = mapped_column(Text, nullable=False, default="")
    result_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    __table_args__ = (
        Index("ix_audit_engagement_ts", "engagement_id", "timestamp"),
        Index("ix_audit_action_type", "action_type"),
        Index("ix_audit_user", "user_id"),
    )
