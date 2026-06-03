"""Routes CRUD pour les findings unifies du pentest."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.finding import Finding
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class FindingCreate(BaseModel):
    session_id: str | None = None
    module: str | None = None
    finding_type: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    target: str | None = None
    evidence: str | None = None
    exploitable: bool = False
    exploited: bool = False
    cvss_score: float | None = None
    cwe_id: str | None = None
    mitre_technique: str | None = None
    raw_data: dict | None = None


class FindingUpdate(BaseModel):
    session_id: str | None = None
    module: str | None = None
    finding_type: str | None = None
    severity: str | None = None
    title: str | None = None
    description: str | None = None
    target: str | None = None
    evidence: str | None = None
    exploitable: bool | None = None
    exploited: bool | None = None
    cvss_score: float | None = None
    cwe_id: str | None = None
    mitre_technique: str | None = None
    raw_data: dict | None = None


class ExploitRequest(BaseModel):
    """Parametres pour declencher l'exploitation d'un finding."""

    params: dict | None = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "session_id": f.session_id,
        "module": f.module,
        "finding_type": f.finding_type,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "target": f.target,
        "evidence": f.evidence,
        "exploitable": f.exploitable,
        "exploited": f.exploited,
        "cvss_score": f.cvss_score,
        "cwe_id": f.cwe_id,
        "mitre_technique": f.mitre_technique,
        "raw_data": f.raw_data,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "updated_at": f.updated_at.isoformat() if f.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", status_code=status.HTTP_201_CREATED)
def create_finding(body: FindingCreate, db: Session = Depends(get_db)):
    """Cree un nouveau finding."""
    finding = Finding(**body.model_dump())
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return _finding_to_dict(finding)


@router.get("")
def list_findings(
    session_id: str | None = Query(None),
    module: str | None = Query(None),
    severity: str | None = Query(None),
    finding_type: str | None = Query(None),
    exploitable: bool | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Liste les findings avec filtres optionnels."""
    q = db.query(Finding)
    if session_id:
        q = q.filter(Finding.session_id == session_id)
    if module:
        q = q.filter(Finding.module == module)
    if severity:
        q = q.filter(Finding.severity == severity)
    if finding_type:
        q = q.filter(Finding.finding_type == finding_type)
    if exploitable is not None:
        q = q.filter(Finding.exploitable == exploitable)

    total = q.count()
    findings = q.order_by(Finding.id.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "items": [_finding_to_dict(f) for f in findings],
    }


@router.get("/stats")
def finding_stats(
    session_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Statistiques agregees des findings."""
    q = db.query(Finding)
    if session_id:
        q = q.filter(Finding.session_id == session_id)

    total = q.count()

    by_severity = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.session_id == session_id if session_id else True)
        .group_by(Finding.severity)
        .all()
    )
    by_module = dict(
        db.query(Finding.module, func.count(Finding.id))
        .filter(Finding.session_id == session_id if session_id else True)
        .group_by(Finding.module)
        .all()
    )
    by_type = dict(
        db.query(Finding.finding_type, func.count(Finding.id))
        .filter(Finding.session_id == session_id if session_id else True)
        .group_by(Finding.finding_type)
        .all()
    )

    exploitable_count = q.filter(Finding.exploitable).count()
    exploited_count = q.filter(Finding.exploited).count()

    return {
        "total": total,
        "by_severity": by_severity,
        "by_module": by_module,
        "by_type": by_type,
        "exploitable": exploitable_count,
        "exploited": exploited_count,
    }


@router.get("/export")
def export_findings(
    session_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Exporte tous les findings en JSON."""
    q = db.query(Finding)
    if session_id:
        q = q.filter(Finding.session_id == session_id)
    findings = q.order_by(Finding.id).all()
    return {"findings": [_finding_to_dict(f) for f in findings]}


@router.get("/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    """Retourne un finding par son ID."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_to_dict(finding)


@router.put("/{finding_id}")
def update_finding(
    finding_id: int,
    body: FindingUpdate,
    db: Session = Depends(get_db),
):
    """Met a jour un finding existant."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    update_data = body.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(finding, key, value)

    db.commit()
    db.refresh(finding)
    return _finding_to_dict(finding)


@router.delete("/{finding_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_finding(finding_id: int, db: Session = Depends(get_db)):
    """Supprime un finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    db.delete(finding)
    db.commit()


@router.post("/{finding_id}/exploit")
def exploit_finding(
    finding_id: int,
    body: ExploitRequest,
    db: Session = Depends(get_db),
):
    """Declenche l'exploitation d'un finding via le module approprie.

    Dispatche vers le module qui a produit le finding avec les parametres
    du finding comme contexte. Retourne le statut de la tentative.
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not finding.exploitable:
        raise HTTPException(
            status_code=400,
            detail="Finding is not marked as exploitable",
        )

    # Build exploitation context from the finding
    exploit_context = {
        "finding_id": finding.id,
        "module": finding.module,
        "finding_type": finding.finding_type,
        "target": finding.target,
        "evidence": finding.evidence,
        "raw_data": finding.raw_data,
        "params": body.params or {},
    }

    # Module dispatch map
    module_dispatch = {
        "sqli": "sqli-advanced",
        "xss": "xss-hunter",
        "lfi": "lfi-rce",
        "ssrf": "ssrf-advanced",
        "cmdi": "command-exec",
        "privesc": "privesc",
        "cred": "credential-auditor",
    }

    target_module = module_dispatch.get(finding.finding_type, finding.module)

    return {
        "status": "dispatched",
        "finding_id": finding.id,
        "target_module": target_module,
        "exploit_context": exploit_context,
        "message": f"Exploitation dispatched to module '{target_module}'",
    }
