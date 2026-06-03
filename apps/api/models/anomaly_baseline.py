"""Modèle AnomalyBaseline — statistiques glissantes pour la détection d'anomalies."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class AnomalyBaseline(Base):
    """Ligne de base statistique (moyenne, variance) pour une métrique donnée."""

    __tablename__ = "anomaly_baselines"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    metric_type: Mapped[str] = mapped_column(Text, index=True)
    metric_key: Mapped[str] = mapped_column(Text, index=True)
    count: Mapped[int] = mapped_column(Integer, default=0)
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    variance: Mapped[float] = mapped_column(Float, default=0.0)
    last_value: Mapped[float] = mapped_column(Float, default=0.0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
