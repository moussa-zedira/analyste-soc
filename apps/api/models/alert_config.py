"""AlertChannel model — configurable alert destinations."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class AlertChannel(Base):
    __tablename__ = "alert_channels"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    channel_type: Mapped[str] = mapped_column(Text)  # slack | email | webhook
    name: Mapped[str] = mapped_column(Text)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_severity: Mapped[str] = mapped_column(Text, default="high")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
