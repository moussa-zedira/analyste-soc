"""Modeles de Case Management : Case, CaseEvidence, CaseTimelineEntry."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class Case(Base):
    """Dossier d'investigation lie a un ou plusieurs incidents.

    Wrapper de niveau enquete : assignation, SLA, escalation, statut workflow,
    avec evidence chain attachee separement.
    """

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(Text, default="open", index=True)
    # statuses : open | triaging | investigating | containment | recovery | closed
    priority: Mapped[str] = mapped_column(Text, default="medium", index=True)
    # P1 critical | high | medium | low
    severity: Mapped[str] = mapped_column(Text, default="medium")
    assignee_id: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    assignee_username: Mapped[str | None] = mapped_column(Text, nullable=True)
    # SLA
    sla_response_minutes: Mapped[int] = mapped_column(Integer, default=60)
    sla_resolution_minutes: Mapped[int] = mapped_column(Integer, default=480)  # 8h
    sla_responded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_breached: Mapped[bool] = mapped_column(default=False, index=True)
    # Liens
    incident_ids: Mapped[list] = mapped_column(JSON, default=list)
    related_iocs: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    # Cloture
    resolution: Mapped[str | None] = mapped_column(Text, nullable=True)
    # true_positive | false_positive | benign | duplicate | mitigated
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Audit
    created_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class CaseEvidence(Base):
    """Element de preuve attache a un case (file hash, URL, log, screenshot, note)."""

    __tablename__ = "case_evidence"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    case_id: Mapped[str] = mapped_column(Text, index=True)
    kind: Mapped[str] = mapped_column(Text)
    # kind: file | url | hash | log_excerpt | note | ioc | image | command
    title: Mapped[str] = mapped_column(Text)
    content: Mapped[str] = mapped_column(Text)
    sha256: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    extra: Mapped[dict] = mapped_column(JSON, default=dict)
    # Chain of custody
    collected_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    custody_chain: Mapped[list] = mapped_column(JSON, default=list)
    # Liste de {actor, action, ts, prev_hash, hash}


class CaseTimelineEntry(Base):
    """Entree immuable de l'historique d'un case (creation, transition, comment)."""

    __tablename__ = "case_timeline"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    case_id: Mapped[str] = mapped_column(Text, index=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    actor_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    actor_username: Mapped[str | None] = mapped_column(Text, nullable=True)
    kind: Mapped[str] = mapped_column(Text)
    # kind: created | status_change | assignment | evidence_added | comment | sla_breach | closed
    message: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
