"""Modeles de persistance Compliance : Assessment, Attestation, Remediation."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, DateTime, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class ComplianceAssessment(Base):
    __tablename__ = "compliance_assessments"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    framework_id: Mapped[str] = mapped_column(Text, index=True)
    assessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    coverage_score: Mapped[float] = mapped_column(Float, default=0.0)
    controls_total: Mapped[int] = mapped_column(Integer, default=0)
    by_status: Mapped[dict] = mapped_column(JSON, default=dict)
    snapshot: Mapped[dict] = mapped_column(JSON, default=dict)
    triggered_by: Mapped[str] = mapped_column(Text, default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ComplianceAttestation(Base):
    __tablename__ = "compliance_attestations"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    framework_id: Mapped[str] = mapped_column(Text, index=True)
    control_id: Mapped[str] = mapped_column(Text, index=True)
    status: Mapped[str] = mapped_column(Text, default="manual_ok", index=True)
    attested_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_urls: Mapped[list] = mapped_column(JSON, default=list)
    attested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ComplianceRemediation(Base):
    __tablename__ = "compliance_remediations"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    framework_id: Mapped[str] = mapped_column(Text, index=True)
    control_id: Mapped[str] = mapped_column(Text, index=True)
    severity: Mapped[str] = mapped_column(Text, default="med", index=True)
    title: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text, default="")
    assigned_to: Mapped[str | None] = mapped_column(Text, nullable=True, index=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(Text, default="open", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
