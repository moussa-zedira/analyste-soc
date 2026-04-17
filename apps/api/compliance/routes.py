"""Routes Compliance : liste des frameworks + rapports de couverture."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from apps.api.compliance.frameworks import (
    ALL_FRAMEWORKS,
    get_framework,
    list_frameworks,
)
from apps.api.compliance.reporter import (
    evaluate_all,
    evaluate_framework,
)
from apps.api.db.session import get_db

router = APIRouter(prefix="/compliance", tags=["Compliance"])


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
                "id": c.id, "title": c.title, "description": c.description,
                "capabilities": c.capabilities, "mandatory": c.mandatory,
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
    """Rapport de couverture global pour tous les frameworks."""
    reports = evaluate_all(db)
    summary = []
    for fid, rep in reports.items():
        summary.append({
            "id": fid,
            "name": rep["framework"]["name"],
            "controls_total": rep["summary"]["controls_total"],
            "coverage_score": rep["summary"]["coverage_score"],
            "by_status": rep["summary"]["by_status"],
        })
    return {"summary": summary, "reports": reports}
