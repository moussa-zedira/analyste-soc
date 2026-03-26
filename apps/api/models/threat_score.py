"""ThreatScore model — dynamic risk score per source IP."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class ThreatScore(Base):
    __tablename__ = "threat_scores"

    ip: Mapped[str] = mapped_column(Text, primary_key=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    factors_json: Mapped[str] = mapped_column(Text, default="{}")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
