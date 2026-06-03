"""Persistance des assessments, attestations et remediations Compliance."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session

from apps.api.models.compliance import (
    ComplianceAssessment,
    ComplianceAttestation,
    ComplianceRemediation,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _new_id() -> str:
    return uuid.uuid4().hex


def save_assessment(
    db: Session,
    framework_id: str,
    report: dict[str, Any],
    triggered_by: str = "manual",
) -> ComplianceAssessment:
    summary = report.get("summary", {})
    now = _now()
    assessment = ComplianceAssessment(
        id=_new_id(),
        framework_id=framework_id,
        assessed_at=now,
        coverage_score=float(summary.get("coverage_score", 0.0)),
        controls_total=int(summary.get("controls_total", 0)),
        by_status=dict(summary.get("by_status", {})),
        snapshot=report,
        triggered_by=triggered_by,
        created_at=now,
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
    return assessment


def list_assessments(
    db: Session,
    framework_id: str | None = None,
    limit: int = 50,
) -> list[ComplianceAssessment]:
    q = db.query(ComplianceAssessment)
    if framework_id:
        q = q.filter(ComplianceAssessment.framework_id == framework_id)
    q = q.order_by(desc(ComplianceAssessment.assessed_at)).limit(limit)
    return q.all()


def get_assessment(db: Session, assessment_id: str) -> ComplianceAssessment | None:
    return db.get(ComplianceAssessment, assessment_id)


def coverage_trend(
    db: Session,
    framework_id: str,
    days: int = 90,
) -> list[dict[str, Any]]:
    cutoff = _now() - timedelta(days=days)
    rows = (
        db.query(ComplianceAssessment)
        .filter(ComplianceAssessment.framework_id == framework_id)
        .filter(ComplianceAssessment.assessed_at >= cutoff)
        .order_by(ComplianceAssessment.assessed_at.asc())
        .all()
    )
    return [
        {"date": r.assessed_at.isoformat(), "score": r.coverage_score, "id": r.id} for r in rows
    ]


def create_attestation(
    db: Session,
    framework_id: str,
    control_id: str,
    status: str,
    attested_by: str | None,
    notes: str | None = None,
    evidence_urls: list[str] | None = None,
) -> ComplianceAttestation:
    now = _now()
    att = ComplianceAttestation(
        id=_new_id(),
        framework_id=framework_id,
        control_id=control_id,
        status=status,
        attested_by=attested_by,
        notes=notes,
        evidence_urls=list(evidence_urls or []),
        attested_at=now,
        created_at=now,
        updated_at=now,
    )
    db.add(att)
    db.commit()
    db.refresh(att)
    return att


def list_attestations(
    db: Session,
    framework_id: str | None = None,
    control_id: str | None = None,
    limit: int = 200,
) -> list[ComplianceAttestation]:
    q = db.query(ComplianceAttestation)
    if framework_id:
        q = q.filter(ComplianceAttestation.framework_id == framework_id)
    if control_id:
        q = q.filter(ComplianceAttestation.control_id == control_id)
    return q.order_by(desc(ComplianceAttestation.attested_at)).limit(limit).all()


def get_attestation(db: Session, attestation_id: str) -> ComplianceAttestation | None:
    return db.get(ComplianceAttestation, attestation_id)


def update_attestation(
    db: Session,
    attestation_id: str,
    status: str | None = None,
    notes: str | None = None,
    evidence_urls: list[str] | None = None,
    attested_by: str | None = None,
) -> ComplianceAttestation | None:
    att = db.get(ComplianceAttestation, attestation_id)
    if att is None:
        return None
    if status is not None:
        att.status = status
    if notes is not None:
        att.notes = notes
    if evidence_urls is not None:
        att.evidence_urls = list(evidence_urls)
    if attested_by is not None:
        att.attested_by = attested_by
    att.updated_at = _now()
    db.commit()
    db.refresh(att)
    return att


def delete_attestation(db: Session, attestation_id: str) -> bool:
    att = db.get(ComplianceAttestation, attestation_id)
    if att is None:
        return False
    db.delete(att)
    db.commit()
    return True


def create_remediation(
    db: Session,
    framework_id: str,
    control_id: str,
    title: str,
    severity: str = "med",
    description: str = "",
    assigned_to: str | None = None,
    due_date: datetime | None = None,
) -> ComplianceRemediation:
    now = _now()
    rem = ComplianceRemediation(
        id=_new_id(),
        framework_id=framework_id,
        control_id=control_id,
        severity=severity,
        title=title,
        description=description,
        assigned_to=assigned_to,
        due_date=due_date,
        status="open",
        created_at=now,
    )
    db.add(rem)
    db.commit()
    db.refresh(rem)
    return rem


def list_remediations(
    db: Session,
    framework_id: str | None = None,
    control_id: str | None = None,
    status: str | None = None,
    limit: int = 200,
) -> list[ComplianceRemediation]:
    q = db.query(ComplianceRemediation)
    if framework_id:
        q = q.filter(ComplianceRemediation.framework_id == framework_id)
    if control_id:
        q = q.filter(ComplianceRemediation.control_id == control_id)
    if status:
        q = q.filter(ComplianceRemediation.status == status)
    return q.order_by(desc(ComplianceRemediation.created_at)).limit(limit).all()


def get_remediation(db: Session, remediation_id: str) -> ComplianceRemediation | None:
    return db.get(ComplianceRemediation, remediation_id)


def update_remediation(
    db: Session,
    remediation_id: str,
    status: str | None = None,
    severity: str | None = None,
    title: str | None = None,
    description: str | None = None,
    assigned_to: str | None = None,
    due_date: datetime | None = None,
) -> ComplianceRemediation | None:
    rem = db.get(ComplianceRemediation, remediation_id)
    if rem is None:
        return None
    if status is not None:
        rem.status = status
        if status == "resolved" and rem.resolved_at is None:
            rem.resolved_at = _now()
    if severity is not None:
        rem.severity = severity
    if title is not None:
        rem.title = title
    if description is not None:
        rem.description = description
    if assigned_to is not None:
        rem.assigned_to = assigned_to
    if due_date is not None:
        rem.due_date = due_date
    db.commit()
    db.refresh(rem)
    return rem


def delete_remediation(db: Session, remediation_id: str) -> bool:
    rem = db.get(ComplianceRemediation, remediation_id)
    if rem is None:
        return False
    db.delete(rem)
    db.commit()
    return True
