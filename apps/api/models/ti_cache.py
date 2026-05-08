"""Modele TICache — cache des lookups Threat Intelligence."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class TICache(Base):
    """Cache persistant des resultats de Threat Intelligence."""

    __tablename__ = "ti_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    indicator: Mapped[str] = mapped_column(Text, index=True)
    source: Mapped[str] = mapped_column(Text)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    categories_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    total_reports: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
