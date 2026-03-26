"""Modèle AuditLog — journal d'audit des actions utilisateur."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class AuditLog(Base):
    """Entrée du journal d'audit traçant les actions utilisateur."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(Text, index=True)  # "scan", "login", "update_user", etc.
    target: Mapped[str | None] = mapped_column(Text, nullable=True)  # cible de l'action
    details: Mapped[str] = mapped_column(Text, default="{}")  # JSON
    ip_address: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
