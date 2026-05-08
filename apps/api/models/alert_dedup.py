"""Modele de deduplication d'alertes : meme fingerprint = supprime pendant TTL."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class AlertFingerprint(Base):
    """Fingerprint = sha256(rule_id|entity_key|severity)."""

    __tablename__ = "alert_fingerprints"

    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    rule_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    entity_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    count: Mapped[int] = mapped_column(Integer, default=1)
    suppressed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_incident_id: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_alert_fp_last_seen", "last_seen"),
        Index("ix_alert_fp_suppressed_until", "suppressed_until"),
    )
