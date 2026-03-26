"""Modèle Event — stocke les événements de sécurité normalisés."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.db.base import Base


class Event(Base):
    """Événement de sécurité normalisé avec métadonnées réseau."""

    __tablename__ = "events"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(Text)
    event_type: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text)
    src_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    username: Mapped[str | None] = mapped_column(Text, nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw: Mapped[str | None] = mapped_column(Text, nullable=True)

    incidents: Mapped[list["Incident"]] = relationship(
        "Incident",
        secondary="incident_events",
        back_populates="events",
        viewonly=True,
    )

    __table_args__ = (
        Index("ix_events_event_type_ts", "event_type", "ts"),
        Index("ix_events_src_ip_ts", "src_ip", "ts"),
    )
