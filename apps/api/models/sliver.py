"""Modeles Sliver C2 (V4.3a) : sessions, builds d'implants, commandes.

Persiste localement les metadonnees Sliver pour les correler avec les
engagements (V4.3b) et generer les rapports (V4.3c). La source de
verite reste Sliver server ; ici on miroir ce qui a transite par le
dashboard.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class SliverSession(Base):
    """Une session Sliver active ou recemment vue.

    `id` = session ID Sliver (UUID gRPC). On garde aussi un FK optionnel
    vers un engagement (cf. V4.3b) pour rattacher l'implant a une mission.
    """

    __tablename__ = "sliver_sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    hostname: Mapped[str] = mapped_column(Text, nullable=False, default="")
    username: Mapped[str] = mapped_column(Text, nullable=False, default="")
    os: Mapped[str] = mapped_column(Text, nullable=False, default="")
    arch: Mapped[str] = mapped_column(Text, nullable=False, default="")
    transport: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remote_address: Mapped[str] = mapped_column(Text, nullable=False, default="")
    pid: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    first_contact: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_checkin: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    engagement_id: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # FK soft -> engagements.id (ajoute en 018)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_sliver_sessions_active", "active"),
        Index("ix_sliver_sessions_engagement", "engagement_id"),
    )


class SliverImplantBuild(Base):
    """Trace d'un build d'implant genere via le dashboard."""

    __tablename__ = "sliver_implant_builds"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    os: Mapped[str] = mapped_column(Text, nullable=False)
    arch: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(Text, nullable=False)
    c2_url: Mapped[str] = mapped_column(Text, nullable=False)
    sleep_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    jitter_pct: Mapped[int] = mapped_column(Integer, nullable=False, default=20)
    build_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    engagement_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_by: Mapped[str | None] = mapped_column(
        Text, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    __table_args__ = (
        Index("ix_sliver_builds_created_at", "created_at"),
        Index("ix_sliver_builds_engagement", "engagement_id"),
    )


class SliverCommand(Base):
    """Une commande shell exec via une session Sliver."""

    __tablename__ = "sliver_commands"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    session_id: Mapped[str] = mapped_column(
        Text, ForeignKey("sliver_sessions.id", ondelete="CASCADE"), nullable=False
    )
    engagement_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    executed_by: Mapped[str | None] = mapped_column(
        Text, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    __table_args__ = (
        Index(
            "ix_sliver_commands_session_executed",
            "session_id",
            "executed_at",
        ),
    )
