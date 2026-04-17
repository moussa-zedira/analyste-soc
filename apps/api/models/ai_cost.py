"""Modele AiCostLog — journal des couts/usages des appels LLM (multi-provider)."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class AiCostLog(Base):
    """Une ligne par appel LLM : provider/modele, tokens, cout USD, latence, success.

    Sert pour : agregation cout journalier, alerting budget, debug perf,
    audit conformite (qui a appele quoi, quand, combien).
    """

    __tablename__ = "ai_cost_log"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    provider: Mapped[str] = mapped_column(Text, index=True)  # anthropic|openai|stub
    model: Mapped[str] = mapped_column(Text, index=True)
    operation: Mapped[str] = mapped_column(Text, index=True)  # triage|rag|rule_gen|raw

    tokens_in: Mapped[int] = mapped_column(Integer, default=0)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0)

    cost_usd_in: Mapped[float] = mapped_column(Float, default=0.0)
    cost_usd_out: Mapped[float] = mapped_column(Float, default=0.0)
    cost_usd_total: Mapped[float] = mapped_column(Float, default=0.0, index=True)

    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    error_msg: Mapped[str | None] = mapped_column(Text, nullable=True)
