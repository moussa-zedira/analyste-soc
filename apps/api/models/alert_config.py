"""Models for multi-channel alerting — AlertChannel and AlertRule."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base

# Valid channel types across the alerting system
VALID_CHANNEL_TYPES = (
    "slack",
    "email",
    "smtp",
    "discord",
    "pagerduty",
    "teams",
    "telegram",
    "syslog",
    "webhook",
)


class AlertChannel(Base):
    """Canal d'alerte multi-canal avec configuration JSON."""

    __tablename__ = "alert_channels"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    channel_type: Mapped[str] = mapped_column(Text)  # see VALID_CHANNEL_TYPES
    name: Mapped[str] = mapped_column(Text)
    config_json: Mapped[str] = mapped_column(Text, default="{}")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    min_severity: Mapped[str] = mapped_column(Text, default="high")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AlertRule(Base):
    """Rule mapping conditions to a specific alert channel.

    ``conditions_json`` holds a JSON dict of field->value matchers.
    Example: {"severity": "critical", "rule_id": "BRUTE-FORCE-001"}
    When all conditions match an incident, the alert is sent to ``channel_id``.
    """

    __tablename__ = "alert_rules"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    conditions_json: Mapped[str] = mapped_column(Text, default="{}")
    channel_id: Mapped[str] = mapped_column(Text)  # FK to alert_channels.id
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    priority: Mapped[int] = mapped_column(Integer, default=0)  # higher = evaluated first
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
