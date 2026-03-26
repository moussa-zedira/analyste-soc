"""Incident model — aggregated security incidents."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.db.base import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(Text, index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    rule_id: Mapped[str] = mapped_column(Text)
    entity_key: Mapped[str] = mapped_column(Text, index=True)
    start_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    end_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    dedup_hash: Mapped[str] = mapped_column(Text, unique=True)
    suggested_severity: Mapped[str | None] = mapped_column(Text, nullable=True, default=None)

    events: Mapped[list["Event"]] = relationship(
        "Event",
        secondary="incident_events",
        back_populates="incidents",
        viewonly=True,
    )
