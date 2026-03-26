"""Modèle ScanHistory — historique des scans réseau."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class ScanHistory(Base):
    """Entrée d'historique d'un scan réseau avec résultats JSON."""

    __tablename__ = "scan_history"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    target: Mapped[str] = mapped_column(Text, index=True)
    target_type: Mapped[str] = mapped_column(Text)  # "domain" | "ip"
    resolved_ip: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    security_score: Mapped[int] = mapped_column(Integer, default=0)
    open_ports_count: Mapped[int] = mapped_column(Integer, default=0)
    scan_duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    scanned_by: Mapped[str | None] = mapped_column(Text, nullable=True)  # user_id
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
