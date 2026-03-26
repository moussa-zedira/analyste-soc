"""Whitelist model — stores IPs and usernames to exclude from detection."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class WhitelistEntry(Base):
    __tablename__ = "whitelist"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    entry_type: Mapped[str] = mapped_column(Text)  # "ip" | "username" | "ip_range"
    value: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
