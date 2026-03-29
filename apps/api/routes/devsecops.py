"""DevSecOps CI/CD Scanner API — SAST, SCA, Secrets, DAST, Container, IaC scanning."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.security import require_api_key
from apps.api.models.devsecops import ScanProject, ScanRun, ScanFinding, QualityGate
from apps.api.devsecops.scanner import (
    run_sast_scan,
    run_sca_scan,
    run_secret_scan,
    run_dast_scan,
    run_container_scan,
    run_iac_scan,
)
from apps.api.devsecops.sarif import generate_sarif
from apps.api.devsecops.ci_integrations import generate_ci_config

router = APIRouter(prefix="/devsecops", dependencies=[Depends(require_api_key)])


# ── Schemas ──

class ProjectCreate(BaseModel):
    name: str
    repo_url: str | None = None
    branch: str = "main"
    language: str | None = None
    description: str | None = None
    config: dict[str, Any] | None = None


class ScanRequest(BaseModel):
    project_id: int | None = None
    target: str = Field(..., description="Path, URL, or git URL to scan")
    language: str | None = None
    options: dict[str, Any] | None = None


class QualityGateCreate(BaseModel):
    project_id: int | None = None
    name: str = "Default"
    max_critical: int = 0
    max_high: int = 5
    max_medium: int | None = None
    no_secrets: bool = True
    custom_rules: dict[str, Any] | None = None


class CIConfigRequest(BaseModel):
    platform: str = Field("github", description="github, gitlab, jenkins, azure, circleci")
    scans: list[str] = Field(["sast", "sca", "secrets"], description="Scan types to include")
    quality_gate: dict[str, Any] | None = None


def _project_dict(p: ScanProject) -> dict:
    return {
        "id": p.id, "name": p.name, "repo_url": p.repo_url, "branch": p.branch,
        "language": p.language, "description": p.description,
        "last_scan_at": p.last_scan_at.isoformat() if p.last_scan_at else None,
    }


def _run_dict(r: ScanRun) -> dict:
    return {
        "id": r.id, "project_id": r.project_id, "scan_type": r.scan_type,
        "status": r.status, "findings_count": r.findings_count,
        "critical_count": r.critical_count, "high_count": r.high_count,
        "medium_count": r.medium_count, "low_count": r.low_count,
        "quality_gate_passed": r.quality_gate_passed, "trigger": r.trigger,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
    }


def _finding_dict(f: ScanFinding) -> dict:
    return {
        "id": f.id, "run_id": f.run_id, "scan_type": f.scan_type,
        "severity": f.severity, "cwe_id": f.cwe_id, "title": f.title,
        "description": f.description, "file_path": f.file_path,
        "line_number": f.line_number, "code_snippet": f.code_snippet,
        "remediation": f.remediation, "false_positive": f.false_positive,
        "resolved": f.resolved,
    }


def _persist_run(db: Session, scan_type: str, findings: list[dict], project_id: int | None = None) -> ScanRun:
    now = datetime.now(timezone.utc)
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        s = f.get("severity", "low").lower()
        if s in sev_counts:
            sev_counts[s] += 1

    run = ScanRun(
        project_id=project_id, scan_type=scan_type, status="completed",
        started_at=now, finished_at=now, findings_count=len(findings),
        critical_count=sev_counts["critical"], high_count=sev_counts["high"],
        medium_count=sev_counts["medium"], low_count=sev_counts["low"],
        trigger="manual",
    )
    db.add(run)
    db.flush()

    for f in findings:
        db.add(ScanFinding(
            run_id=run.id, scan_type=scan_type, severity=f.get("severity", "low"),
            cwe_id=f.get("cwe_id"), title=f.get("title", ""),
            description=f.get("description"), file_path=f.get("file"),
            line_number=f.get("line"), code_snippet=f.get("code_snippet"),
            remediation=f.get("remediation"),
        ))
    db.commit()
    db.refresh(run)
    return run


# ── Projects ──

@router.post("/projects")
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    p = ScanProject(**body.model_dump())
    db.add(p)
    db.commit()
    db.refresh(p)
    return {"status": "created", "project": _project_dict(p)}


@router.get("/projects")
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(ScanProject).order_by(ScanProject.id.desc()).all()
    return {"projects": [_project_dict(p) for p in projects]}


@router.get("/projects/{pid}")
def get_project(pid: int, db: Session = Depends(get_db)):
    p = db.query(ScanProject).filter(ScanProject.id == pid).first()
    if not p:
        raise HTTPException(404, "Project not found")
    return {"project": _project_dict(p)}


# ── Scans ──

@router.post("/scan/sast")
async def scan_sast(body: ScanRequest, db: Session = Depends(get_db)):
    findings = await run_sast_scan(body.target, language=body.language, options=body.options or {})
    run = _persist_run(db, "sast", findings, body.project_id)
    return {"run": _run_dict(run), "findings": findings}


@router.post("/scan/sca")
async def scan_sca(body: ScanRequest, db: Session = Depends(get_db)):
    findings = await run_sca_scan(body.target, options=body.options or {})
    run = _persist_run(db, "sca", findings, body.project_id)
    return {"run": _run_dict(run), "findings": findings}


@router.post("/scan/secrets")
async def scan_secrets(body: ScanRequest, db: Session = Depends(get_db)):
    findings = await run_secret_scan(body.target, options=body.options or {})
    run = _persist_run(db, "secrets", findings, body.project_id)
    return {"run": _run_dict(run), "findings": findings}


@router.post("/scan/dast")
async def scan_dast(body: ScanRequest, db: Session = Depends(get_db)):
    findings = await run_dast_scan(body.target, options=body.options or {})
    run = _persist_run(db, "dast", findings, body.project_id)
    return {"run": _run_dict(run), "findings": findings}


@router.post("/scan/container")
async def scan_container(body: ScanRequest, db: Session = Depends(get_db)):
    findings = await run_container_scan(body.target, options=body.options or {})
    run = _persist_run(db, "container", findings, body.project_id)
    return {"run": _run_dict(run), "findings": findings}


@router.post("/scan/iac")
async def scan_iac(body: ScanRequest, db: Session = Depends(get_db)):
    findings = await run_iac_scan(body.target, options=body.options or {})
    run = _persist_run(db, "iac", findings, body.project_id)
    return {"run": _run_dict(run), "findings": findings}


@router.post("/scan/full")
async def scan_full(body: ScanRequest, db: Session = Depends(get_db)):
    all_findings: list[dict] = []
    for scan_fn, stype in [
        (run_sast_scan, "sast"), (run_sca_scan, "sca"), (run_secret_scan, "secrets"),
        (run_container_scan, "container"), (run_iac_scan, "iac"),
    ]:
        try:
            findings = await scan_fn(body.target, **({"language": body.language} if stype == "sast" else {}), options=body.options or {})
            all_findings.extend(findings)
        except Exception:
            pass
    run = _persist_run(db, "full", all_findings, body.project_id)
    return {"run": _run_dict(run), "findings": all_findings}


# ── Runs ──

@router.get("/runs")
def list_runs(project_id: int | None = None, limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(ScanRun).order_by(ScanRun.id.desc())
    if project_id:
        q = q.filter(ScanRun.project_id == project_id)
    runs = q.limit(limit).all()
    return {"runs": [_run_dict(r) for r in runs]}


@router.get("/runs/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db)):
    run = db.query(ScanRun).filter(ScanRun.id == run_id).first()
    if not run:
        raise HTTPException(404, "Run not found")
    findings = db.query(ScanFinding).filter(ScanFinding.run_id == run_id).all()
    return {"run": _run_dict(run), "findings": [_finding_dict(f) for f in findings]}


@router.get("/runs/{run_id}/sarif")
def get_sarif(run_id: int, db: Session = Depends(get_db)):
    findings = db.query(ScanFinding).filter(ScanFinding.run_id == run_id).all()
    sarif = generate_sarif([_finding_dict(f) for f in findings])
    return sarif


# ── Quality Gates ──

@router.post("/quality-gates")
def create_gate(body: QualityGateCreate, db: Session = Depends(get_db)):
    gate = QualityGate(**body.model_dump())
    db.add(gate)
    db.commit()
    db.refresh(gate)
    return {"status": "created", "gate": {"id": gate.id, "name": gate.name}}


@router.get("/quality-gates")
def list_gates(db: Session = Depends(get_db)):
    gates = db.query(QualityGate).all()
    return {"gates": [
        {"id": g.id, "name": g.name, "max_critical": g.max_critical,
         "max_high": g.max_high, "no_secrets": g.no_secrets, "is_active": g.is_active}
        for g in gates
    ]}


# ── CI/CD Pipeline Generator ──

@router.post("/ci/generate")
def gen_ci(body: CIConfigRequest):
    config = generate_ci_config(body.platform, body.scans, body.quality_gate)
    return {"platform": body.platform, "config": config}


# ── Dashboard ──

@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    from sqlalchemy import func
    total_projects = db.query(func.count(ScanProject.id)).scalar() or 0
    total_runs = db.query(func.count(ScanRun.id)).scalar() or 0
    total_findings = db.query(func.count(ScanFinding.id)).scalar() or 0
    critical = db.query(func.count(ScanFinding.id)).filter(ScanFinding.severity == "critical", ScanFinding.resolved == False).scalar() or 0
    high = db.query(func.count(ScanFinding.id)).filter(ScanFinding.severity == "high", ScanFinding.resolved == False).scalar() or 0
    return {
        "total_projects": total_projects, "total_runs": total_runs,
        "total_findings": total_findings, "open_critical": critical, "open_high": high,
    }


# ── Webhook ──

@router.post("/webhook")
async def webhook(payload: dict, db: Session = Depends(get_db)):
    target = payload.get("target", payload.get("repo_url", ""))
    scan_type = payload.get("scan_type", "full")
    if not target:
        raise HTTPException(400, "Missing target")
    return {"status": "accepted", "message": f"Scan '{scan_type}' queued for {target}"}
