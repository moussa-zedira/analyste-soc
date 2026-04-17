"""Modele SigmaRuleCache — cache des regles SIGMA importees depuis SigmaHQ.

Contrairement a `SigmaRule` (regles uploadees par l'utilisateur), ce cache stocke
les regles recuperees en masse depuis le repo SigmaHQ via la route /sigma/sync.
Indexees par `rule_id` (UUID Sigma) pour eviter les doublons.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class SigmaRuleCache(Base):
    """Cache d'une regle SIGMA issue du repo SigmaHQ."""

    __tablename__ = "sigma_rule_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_id: Mapped[str] = mapped_column(Text, unique=True, index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    level: Mapped[str] = mapped_column(Text, default="medium", index=True)
    status: Mapped[str | None] = mapped_column(Text, nullable=True)
    author: Mapped[str | None] = mapped_column(Text, nullable=True)
    logsource_product: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    logsource_category: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    logsource_service: Mapped[str | None] = mapped_column(Text, nullable=True)
    yaml_source: Mapped[str] = mapped_column(Text)
    lucene_query: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    source_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    imported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )

    __table_args__ = (
        Index("ix_sigma_cache_level_enabled", "level", "enabled"),
    )
