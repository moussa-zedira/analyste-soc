"""Modele UserBaseline — profil comportemental par entite (UEBA)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, JSON, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class UserBaseline(Base):
    """Profil comportemental cumulatif d'une entite (user_id, src_ip, ou host).

    Chaque champ JSON est un dict {bucket -> count} pour permettre des
    requetes de probabilite a posteriori (Naive Bayes simplifie : score
    eleve = evenement rare pour ce profil).
    """

    __tablename__ = "uba_baselines"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    entity_type: Mapped[str] = mapped_column(Text, index=True)  # user|ip|host
    entity_key: Mapped[str] = mapped_column(Text, index=True)
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    # Distributions {bucket -> count}
    hours: Mapped[dict] = mapped_column(JSON, default=dict)        # "0".."23" -> count
    event_types: Mapped[dict] = mapped_column(JSON, default=dict)  # event_type -> count
    geos: Mapped[dict] = mapped_column(JSON, default=dict)         # country/asn -> count
    src_ips: Mapped[dict] = mapped_column(JSON, default=dict)      # ip -> count (top 100)
    user_agents: Mapped[dict] = mapped_column(JSON, default=dict)  # ua hash -> count
    # Score courant + meta
    current_score: Mapped[float] = mapped_column(Float, default=0.0)
    score_reasons: Mapped[dict] = mapped_column(JSON, default=dict)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
