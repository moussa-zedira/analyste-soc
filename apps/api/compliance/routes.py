"""Routes Compliance : frameworks, rapports, persistance, PDF, attestations, remediations."""

from __future__ import annotations

import io
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.compliance import storage
from apps.api.compliance.frameworks import (
    ALL_FRAMEWORKS,
    get_framework,
    list_frameworks,
)
from apps.api.compliance.pdf_export import generate_compliance_pdf
from apps.api.compliance.reporter import (
    evaluate_all,
    evaluate_framework,
)
from apps.api.db.session import get_db
from apps.api.security import require_api_key

router = APIRouter(prefix="/compliance", tags=["Compliance"])


def _principal(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            from apps.api.security import _decode_jwt

            payload = _decode_jwt(auth[7:]) or {}
            return str(payload.get("sub") or payload.get("username") or "user")
        except Exception:
            return "user"
    return "service"


@router.get("/frameworks")
def get_frameworks() -> dict[str, Any]:
    return {"frameworks": list_frameworks(), "count": len(ALL_FRAMEWORKS)}


@router.get("/frameworks/{fid}")
def get_framework_detail(fid: str) -> dict[str, Any]:
    fw = get_framework(fid)
    if fw is None:
        raise HTTPException(status_code=404, detail=f"framework not found: {fid}")
    return {
        "id": fw.id,
        "name": fw.name,
        "version": fw.version,
        "url": fw.url,
        "description": fw.description,
        "controls": [
            {
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "capabilities": c.capabilities,
                "mandatory": c.mandatory,
            }
            for c in fw.controls
        ],
    }


@router.get("/frameworks/{fid}/report")
def get_framework_report(
    fid: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    fw = get_framework(fid)
    if fw is None:
        raise HTTPException(status_code=404, detail=f"framework not found: {fid}")
    return evaluate_framework(fw, db)


@router.get("/report")
def get_global_report(db: Session = Depends(get_db)) -> dict[str, Any]:
    reports = evaluate_all(db)
    summary = []
    for fid, rep in reports.items():
        summary.append(
            {
                "id": fid,
                "name": rep["framework"]["name"],
                "controls_total": rep["summary"]["controls_total"],
                "coverage_score": rep["summary"]["coverage_score"],
                "by_status": rep["summary"]["by_status"],
            }
        )
    return {"summary": summary, "reports": reports}


@router.post(
    "/frameworks/{fid}/report/run",
    dependencies=[Depends(require_api_key)],
)
def run_framework_report(
    fid: str,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    fw = get_framework(fid)
    if fw is None:
        raise HTTPException(status_code=404, detail=f"framework not found: {fid}")
    report = evaluate_framework(fw, db)
    triggered_by = _principal(request)
    assessment = storage.save_assessment(db, fid, report, triggered_by=triggered_by)
    return {
        "assessment_id": assessment.id,
        "framework_id": fid,
        "coverage_score": assessment.coverage_score,
        "controls_total": assessment.controls_total,
        "by_status": assessment.by_status,
        "assessed_at": assessment.assessed_at.isoformat(),
        "triggered_by": triggered_by,
    }


@router.get("/assessments")
def list_assessments_route(
    framework_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = storage.list_assessments(db, framework_id=framework_id, limit=limit)
    return {
        "count": len(rows),
        "items": [
            {
                "id": r.id,
                "framework_id": r.framework_id,
                "assessed_at": r.assessed_at.isoformat(),
                "coverage_score": r.coverage_score,
                "controls_total": r.controls_total,
                "by_status": r.by_status,
                "triggered_by": r.triggered_by,
            }
            for r in rows
        ],
    }


@router.get("/assessments/{assessment_id}")
def get_assessment_route(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    a = storage.get_assessment(db, assessment_id)
    if a is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return {
        "id": a.id,
        "framework_id": a.framework_id,
        "assessed_at": a.assessed_at.isoformat(),
        "coverage_score": a.coverage_score,
        "controls_total": a.controls_total,
        "by_status": a.by_status,
        "snapshot": a.snapshot,
        "triggered_by": a.triggered_by,
    }


@router.get("/assessments/{assessment_id}/pdf")
def get_assessment_pdf(
    assessment_id: str,
    db: Session = Depends(get_db),
) -> StreamingResponse:
    a = storage.get_assessment(db, assessment_id)
    if a is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    fw = get_framework(a.framework_id)
    framework_meta = (
        {"id": fw.id, "name": fw.name, "version": fw.version, "url": fw.url}
        if fw
        else {"id": a.framework_id, "name": a.framework_id}
    )
    rems = storage.list_remediations(db, framework_id=a.framework_id, limit=200)
    rems_dump = [
        {
            "control_id": r.control_id,
            "severity": r.severity,
            "title": r.title,
            "status": r.status,
            "due_date": r.due_date.isoformat() if r.due_date else None,
        }
        for r in rems
    ]
    pdf_bytes = generate_compliance_pdf(
        a.snapshot or {},
        framework_meta=framework_meta,
        remediations=rems_dump,
    )
    filename = f"compliance_{a.framework_id}_{a.id}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/frameworks/{fid}/trend")
def framework_trend(
    fid: str,
    days: int = Query(default=90, ge=1, le=365),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if get_framework(fid) is None:
        raise HTTPException(status_code=404, detail=f"framework not found: {fid}")
    points = storage.coverage_trend(db, fid, days=days)
    return {"framework_id": fid, "days": days, "points": points}


class AttestationCreate(BaseModel):
    framework_id: str
    control_id: str
    status: str = Field(default="manual_ok")
    notes: str | None = None
    evidence_urls: list[str] = Field(default_factory=list)
    attested_by: str | None = None


class AttestationUpdate(BaseModel):
    status: str | None = None
    notes: str | None = None
    evidence_urls: list[str] | None = None
    attested_by: str | None = None


@router.post(
    "/attestations",
    dependencies=[Depends(require_api_key)],
)
def create_attestation_route(
    payload: AttestationCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if get_framework(payload.framework_id) is None:
        raise HTTPException(status_code=404, detail="framework not found")
    user = payload.attested_by or _principal(request)
    att = storage.create_attestation(
        db,
        framework_id=payload.framework_id,
        control_id=payload.control_id,
        status=payload.status,
        attested_by=user,
        notes=payload.notes,
        evidence_urls=payload.evidence_urls,
    )
    return _att_dump(att)


@router.get("/attestations")
def list_attestations_route(
    framework_id: str | None = Query(default=None),
    control_id: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = storage.list_attestations(
        db,
        framework_id=framework_id,
        control_id=control_id,
        limit=limit,
    )
    return {"count": len(rows), "items": [_att_dump(r) for r in rows]}


@router.get("/attestations/{attestation_id}")
def get_attestation_route(
    attestation_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    a = storage.get_attestation(db, attestation_id)
    if a is None:
        raise HTTPException(status_code=404, detail="attestation not found")
    return _att_dump(a)


@router.put(
    "/attestations/{attestation_id}",
    dependencies=[Depends(require_api_key)],
)
def update_attestation_route(
    attestation_id: str,
    payload: AttestationUpdate,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    a = storage.update_attestation(
        db,
        attestation_id=attestation_id,
        status=payload.status,
        notes=payload.notes,
        evidence_urls=payload.evidence_urls,
        attested_by=payload.attested_by,
    )
    if a is None:
        raise HTTPException(status_code=404, detail="attestation not found")
    return _att_dump(a)


@router.delete(
    "/attestations/{attestation_id}",
    dependencies=[Depends(require_api_key)],
)
def delete_attestation_route(
    attestation_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if not storage.delete_attestation(db, attestation_id):
        raise HTTPException(status_code=404, detail="attestation not found")
    return {"deleted": True, "id": attestation_id}


class RemediationCreate(BaseModel):
    framework_id: str
    control_id: str
    title: str
    severity: str = Field(default="med")
    description: str = ""
    assigned_to: str | None = None
    due_date: datetime | None = None


class RemediationUpdate(BaseModel):
    status: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    assigned_to: str | None = None
    due_date: datetime | None = None


@router.post(
    "/remediations",
    dependencies=[Depends(require_api_key)],
)
def create_remediation_route(
    payload: RemediationCreate,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if get_framework(payload.framework_id) is None:
        raise HTTPException(status_code=404, detail="framework not found")
    rem = storage.create_remediation(
        db,
        framework_id=payload.framework_id,
        control_id=payload.control_id,
        title=payload.title,
        severity=payload.severity,
        description=payload.description,
        assigned_to=payload.assigned_to,
        due_date=payload.due_date,
    )
    return _rem_dump(rem)


@router.get("/remediations")
def list_remediations_route(
    framework_id: str | None = Query(default=None),
    control_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    rows = storage.list_remediations(
        db,
        framework_id=framework_id,
        control_id=control_id,
        status=status,
        limit=limit,
    )
    return {"count": len(rows), "items": [_rem_dump(r) for r in rows]}


@router.get("/remediations/{remediation_id}")
def get_remediation_route(
    remediation_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    r = storage.get_remediation(db, remediation_id)
    if r is None:
        raise HTTPException(status_code=404, detail="remediation not found")
    return _rem_dump(r)


@router.put(
    "/remediations/{remediation_id}",
    dependencies=[Depends(require_api_key)],
)
def update_remediation_route(
    remediation_id: str,
    payload: RemediationUpdate,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    r = storage.update_remediation(
        db,
        remediation_id=remediation_id,
        status=payload.status,
        severity=payload.severity,
        title=payload.title,
        description=payload.description,
        assigned_to=payload.assigned_to,
        due_date=payload.due_date,
    )
    if r is None:
        raise HTTPException(status_code=404, detail="remediation not found")
    return _rem_dump(r)


@router.delete(
    "/remediations/{remediation_id}",
    dependencies=[Depends(require_api_key)],
)
def delete_remediation_route(
    remediation_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    if not storage.delete_remediation(db, remediation_id):
        raise HTTPException(status_code=404, detail="remediation not found")
    return {"deleted": True, "id": remediation_id}


def _att_dump(a) -> dict[str, Any]:
    return {
        "id": a.id,
        "framework_id": a.framework_id,
        "control_id": a.control_id,
        "status": a.status,
        "attested_by": a.attested_by,
        "notes": a.notes,
        "evidence_urls": a.evidence_urls,
        "attested_at": a.attested_at.isoformat() if a.attested_at else None,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


def _rem_dump(r) -> dict[str, Any]:
    return {
        "id": r.id,
        "framework_id": r.framework_id,
        "control_id": r.control_id,
        "severity": r.severity,
        "title": r.title,
        "description": r.description,
        "assigned_to": r.assigned_to,
        "due_date": r.due_date.isoformat() if r.due_date else None,
        "status": r.status,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
    }
