"""Modèle RuleCheckpoint — suit le dernier horodatage traité par règle."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class RuleCheckpoint(Base):
    """Point de contrôle enregistrant la progression d'une règle de détection."""

    __tablename__ = "rule_checkpoints"

    rule_id: Mapped[str] = mapped_column(Text, primary_key=True)
    last_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
