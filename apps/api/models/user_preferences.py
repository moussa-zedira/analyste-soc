"""Modèle UserPreferences — préférences UI par utilisateur."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class UserPreferences(Base):
    """Préférences persistantes d'un utilisateur."""

    __tablename__ = "user_preferences"

    user_id: Mapped[str] = mapped_column(
        Text, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    notif_email: Mapped[bool] = mapped_column(Boolean, default=True)
    notif_browser: Mapped[bool] = mapped_column(Boolean, default=True)
    notif_critical_only: Mapped[bool] = mapped_column(Boolean, default=False)
    default_layout: Mapped[str] = mapped_column(Text, default="grid")
    timezone: Mapped[str] = mapped_column(Text, default="UTC")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
