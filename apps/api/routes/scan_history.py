"""Routes pour l'historique et l'export des scans pentest."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.scan_result import ScanResult
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ScanResultCreate(BaseModel):
    """Payload pour enregistrer un resultat de scan."""

    module_id: str
    target: str
    mode: str = "internal"
    status: str = "completed"
    result_json: str  # JSON serialise
    duration_ms: int = 0
    findings_count: int = 0
    severity_max: Optional[str] = None
    notes: Optional[str] = None


class ScanResultOut(BaseModel):
    """Representation d'un scan pour l'API."""

    id: str
    created_at: str
    module_id: str
    target: str
    mode: str
    status: str
    duration_ms: int
    findings_count: int
    severity_max: Optional[str]
    notes: Optional[str]


class ScanResultDetail(ScanResultOut):
    """Representation complete avec le JSON de resultats."""

    result_json: str


class ScanStatsOut(BaseModel):
    """Statistiques agregees des scans."""

    total_scans: int = 0
    by_module: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_status: dict[str, int] = Field(default_factory=dict)
    avg_duration_ms: float = 0.0
    total_findings: int = 0


class PaginatedScans(BaseModel):
    """Reponse paginee."""

    items: list[ScanResultOut]
    total: int
    limit: int
    offset: int


class PurgeRequest(BaseModel):
    """Payload pour la purge selective des scans."""

    export_first: bool = True  # Exporter avant suppression
    older_than_hours: int | None = None  # Seulement les scans plus vieux que N heures
    module_ids: list[str] | None = None  # Seulement certains modules
    confirm: str = ""  # Doit etre "CONFIRM_PURGE" pour executer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_redis_keys(pattern: str = "pentest:*") -> int:
    """Supprime les cles Redis correspondant au pattern."""
    try:
        from apps.api.cache import get_redis_client

        r = get_redis_client()
        if r is None:
            return 0
        keys: list = []
        cursor = 0
        while True:
            cursor, batch = r.scan(cursor, match=pattern, count=100)
            keys.extend(batch)
            if cursor == 0:
                break
        if keys:
            r.delete(*keys)
        return len(keys)
    except Exception:
        return 0


def _row_to_out(scan: ScanResult) -> ScanResultOut:
    return ScanResultOut(
        id=scan.id,
        created_at=scan.created_at.isoformat() if scan.created_at else "",
        module_id=scan.module_id,
        target=scan.target,
        mode=scan.mode or "internal",
        status=scan.status or "completed",
        duration_ms=scan.duration_ms or 0,
        findings_count=scan.findings_count or 0,
        severity_max=scan.severity_max,
        notes=scan.notes,
    )


def _row_to_detail(scan: ScanResult) -> ScanResultDetail:
    return ScanResultDetail(
        id=scan.id,
        created_at=scan.created_at.isoformat() if scan.created_at else "",
        module_id=scan.module_id,
        target=scan.target,
        mode=scan.mode or "internal",
        status=scan.status or "completed",
        duration_ms=scan.duration_ms or 0,
        findings_count=scan.findings_count or 0,
        severity_max=scan.severity_max,
        notes=scan.notes,
        result_json=scan.result_json,
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=ScanStatsOut)
def get_scan_stats(db: Session = Depends(get_db)) -> ScanStatsOut:
    """Statistiques agregees de tous les scans."""
    total = db.query(func.count(ScanResult.id)).scalar() or 0

    # Par module
    by_module_rows = (
        db.query(ScanResult.module_id, func.count(ScanResult.id))
        .group_by(ScanResult.module_id)
        .all()
    )
    by_module = {row[0]: row[1] for row in by_module_rows}

    # Par severite
    by_severity_rows = (
        db.query(ScanResult.severity_max, func.count(ScanResult.id))
        .filter(ScanResult.severity_max.isnot(None))
        .group_by(ScanResult.severity_max)
        .all()
    )
    by_severity = {row[0]: row[1] for row in by_severity_rows}

    # Par statut
    by_status_rows = (
        db.query(ScanResult.status, func.count(ScanResult.id))
        .group_by(ScanResult.status)
        .all()
    )
    by_status = {row[0]: row[1] for row in by_status_rows}

    avg_dur = db.query(func.avg(ScanResult.duration_ms)).scalar() or 0.0
    total_findings = db.query(func.sum(ScanResult.findings_count)).scalar() or 0

    return ScanStatsOut(
        total_scans=total,
        by_module=by_module,
        by_severity=by_severity,
        by_status=by_status,
        avg_duration_ms=round(float(avg_dur), 1),
        total_findings=int(total_findings),
    )


@router.get("", response_model=PaginatedScans)
def list_scans(
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    module_id: Optional[str] = None,
    target: Optional[str] = None,
    severity: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> PaginatedScans:
    """Liste les scans avec filtres et pagination."""
    query = db.query(ScanResult)

    if module_id:
        query = query.filter(ScanResult.module_id == module_id)
    if target:
        query = query.filter(ScanResult.target.ilike(f"%{target}%"))
    if severity:
        query = query.filter(ScanResult.severity_max == severity)
    if status_filter:
        query = query.filter(ScanResult.status == status_filter)
    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            query = query.filter(ScanResult.created_at >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            query = query.filter(ScanResult.created_at <= dt_to)
        except ValueError:
            pass

    total = query.count()
    scans = (
        query.order_by(ScanResult.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return PaginatedScans(
        items=[_row_to_out(s) for s in scans],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}", response_model=ScanResultDetail)
def get_scan(scan_id: str, db: Session = Depends(get_db)) -> ScanResultDetail:
    """Recupere un scan avec son result_json complet."""
    scan = db.get(ScanResult, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    return _row_to_detail(scan)


@router.post("", response_model=ScanResultDetail, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanResultCreate, db: Session = Depends(get_db)
) -> ScanResultDetail:
    """Enregistre un nouveau resultat de scan."""
    # Validate that result_json is valid JSON
    try:
        json.loads(payload.result_json)
    except (json.JSONDecodeError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="result_json must be valid JSON",
        )

    scan = ScanResult(
        id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc),
        module_id=payload.module_id,
        target=payload.target,
        mode=payload.mode,
        status=payload.status,
        result_json=payload.result_json,
        duration_ms=payload.duration_ms,
        findings_count=payload.findings_count,
        severity_max=payload.severity_max,
        notes=payload.notes,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return _row_to_detail(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, db: Session = Depends(get_db)) -> None:
    """Supprime un scan."""
    scan = db.get(ScanResult, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Export routes
# ---------------------------------------------------------------------------


@router.get("/{scan_id}/export/json")
def export_scan_json(scan_id: str, db: Session = Depends(get_db)):
    """Telecharge le scan au format JSON."""
    scan = db.get(ScanResult, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    export_data = {
        "id": scan.id,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "module_id": scan.module_id,
        "target": scan.target,
        "mode": scan.mode,
        "status": scan.status,
        "duration_ms": scan.duration_ms,
        "findings_count": scan.findings_count,
        "severity_max": scan.severity_max,
        "notes": scan.notes,
        "results": json.loads(scan.result_json),
    }

    content = json.dumps(export_data, indent=2, ensure_ascii=False)
    filename = f"scan_{scan.module_id}_{scan_id[:8]}.json"

    return StreamingResponse(
        io.BytesIO(content.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{scan_id}/export/csv")
def export_scan_csv(scan_id: str, db: Session = Depends(get_db)):
    """Telecharge les donnees extraites au format CSV (Excel-compatible)."""
    scan = db.get(ScanResult, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    try:
        result_data = json.loads(scan.result_json)
    except (json.JSONDecodeError, TypeError):
        result_data = {}

    buf = io.StringIO()
    # BOM UTF-8 pour que Excel ouvre correctement les accents
    buf.write("\ufeff")

    rows = _extract_csv_rows(result_data, scan)

    if rows:
        writer = csv.DictWriter(buf, fieldnames=rows[0].keys(), quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    else:
        # Fallback : aplatir le JSON en colonnes
        flat = _flatten_dict(result_data)
        writer = csv.DictWriter(buf, fieldnames=flat.keys(), quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerow(flat)

    content = buf.getvalue()
    filename = f"scan_{scan.module_id}_{scan_id[:8]}.csv"

    return StreamingResponse(
        io.BytesIO(content.encode("utf-8-sig")),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _extract_csv_rows(data: dict | list, scan: ScanResult) -> list[dict]:
    """Extrait les donnees tabulaires depuis le JSON de resultats."""
    if not isinstance(data, dict):
        return []

    rows: list[dict] = []
    meta = {
        "scan_id": scan.id,
        "module": scan.module_id,
        "target": scan.target,
        "date": scan.created_at.isoformat() if scan.created_at else "",
    }

    # --- sqli-extract : rows extraites de la DB ---
    extracted = data.get("extracted", {})
    if isinstance(extracted, dict) and extracted.get("rows"):
        for row in extracted["rows"]:
            rows.append({**meta, **{str(k): str(v) for k, v in row.items()}})
        return rows

    # --- cred-dump : credentials ---
    creds = data.get("credentials", [])
    if creds:
        for c in creds:
            rows.append({
                **meta,
                "type": c.get("type", ""),
                "username": c.get("username", ""),
                "password": c.get("password", c.get("hash", "")),
                "source": c.get("source", ""),
            })
        return rows

    # --- lfi-exploit : fichiers lus ---
    files = data.get("files", data.get("results", []))
    if isinstance(files, list) and files and isinstance(files[0], dict):
        for f in files:
            rows.append({
                **meta,
                "path": f.get("path", f.get("file", "")),
                "status": f.get("status", ""),
                "content": str(f.get("content", f.get("data", "")))[:5000],
            })
        return rows

    # --- crawl : emails, tokens, endpoints ---
    for key in ("emails", "api_keys", "tokens", "endpoints", "forms"):
        items = data.get(key, [])
        if items:
            for item in items:
                if isinstance(item, dict):
                    rows.append({**meta, "category": key, **{str(k): str(v) for k, v in item.items()}})
                else:
                    rows.append({**meta, "category": key, "value": str(item)})

    if rows:
        return rows

    # --- dns-recon : records, subdomains ---
    for key in ("records", "subdomains", "services"):
        items = data.get(key, [])
        if isinstance(items, list) and items:
            for item in items:
                if isinstance(item, dict):
                    rows.append({**meta, "category": key, **{str(k): str(v) for k, v in item.items()}})
                else:
                    rows.append({**meta, "category": key, "value": str(item)})

    if rows:
        return rows

    # --- generic : findings / vulnerabilities / results ---
    findings = _extract_findings(data)
    if findings:
        for f in findings:
            flat = {str(k): str(v) if not isinstance(v, (dict, list)) else json.dumps(v, ensure_ascii=False) for k, v in f.items()}
            rows.append({**meta, **flat})
        return rows

    return []


def _flatten_dict(d: dict, prefix: str = "") -> dict:
    """Aplatit un dict imbrique en cles dotees."""
    flat: dict = {}
    for k, v in d.items():
        key = f"{prefix}{k}" if not prefix else f"{prefix}.{k}"
        if isinstance(v, dict):
            flat.update(_flatten_dict(v, key))
        elif isinstance(v, list):
            flat[key] = json.dumps(v, ensure_ascii=False)[:2000]
        else:
            flat[key] = str(v) if v is not None else ""
    return flat


@router.get("/{scan_id}/export/pdf")
def export_scan_pdf(scan_id: str, db: Session = Depends(get_db)):
    """Telecharge un rapport PDF professionnel du scan."""
    scan = db.get(ScanResult, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found"
        )

    pdf_bytes = _generate_pdf_report(scan)
    filename = f"scan_{scan.module_id}_{scan_id[:8]}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Purge / Nettoyage
# ---------------------------------------------------------------------------


def _build_purge_filter(db: Session, req: PurgeRequest):
    """Construit la requete filtree pour la purge."""
    query = db.query(ScanResult)
    if req.older_than_hours is not None:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=req.older_than_hours)
        query = query.filter(ScanResult.created_at < cutoff)
    if req.module_ids:
        query = query.filter(ScanResult.module_id.in_(req.module_ids))
    return query


@router.post("/purge")
def purge_scans(req: PurgeRequest, db: Session = Depends(get_db)):
    """Purge les resultats de scan avec export optionnel prealable.

    Par defaut effectue un dry-run qui retourne le nombre d'enregistrements
    concernes. Envoyer confirm='CONFIRM_PURGE' pour executer la suppression.
    """
    query = _build_purge_filter(db, req)

    if req.confirm != "CONFIRM_PURGE":
        # Dry run — retourne le compte sans rien supprimer
        count = query.count()
        return {
            "mode": "dry_run",
            "records_to_delete": count,
            "message": "Envoie confirm='CONFIRM_PURGE' pour executer",
        }

    # Export prealable si demande
    export_data: list[dict] | None = None
    if req.export_first:
        records = query.all()
        export_data = [
            {
                "id": r.id,
                "module_id": r.module_id,
                "target": r.target,
                "mode": r.mode,
                "status": r.status,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "duration_ms": r.duration_ms,
                "findings_count": r.findings_count,
                "severity_max": r.severity_max,
                "notes": r.notes,
                "result_json": r.result_json,
            }
            for r in records
        ]

    # Suppression effective
    deleted = _build_purge_filter(db, req).delete(synchronize_session="fetch")
    db.commit()

    # Nettoyage des cles Redis pentest
    redis_cleaned = _clean_redis_keys()

    return {
        "deleted_scans": deleted,
        "redis_keys_cleaned": redis_cleaned,
        "export": export_data,
        "note": "Executez VACUUM ANALYZE scan_results pour recuperer l'espace disque",
    }


@router.post("/wipe-all")
def wipe_all(confirm: str = "", db: Session = Depends(get_db)):
    """Supprime TOUS les scans, sessions et cache. Irreversible.

    Dry-run par defaut. Envoyer confirm='WIPE_EVERYTHING' pour executer.
    """
    if confirm != "WIPE_EVERYTHING":
        total = db.query(func.count(ScanResult.id)).scalar() or 0
        return {
            "mode": "dry_run",
            "total_records": total,
            "message": "Envoie confirm='WIPE_EVERYTHING'",
        }

    # Suppression de tous les scans
    deleted = db.query(ScanResult).delete(synchronize_session="fetch")
    db.commit()

    # Nettoyage de TOUTES les cles Redis pentest
    redis_cleaned = _clean_redis_keys(pattern="*pentest*")

    # Nettoyage des sessions en memoire
    from apps.api.pentest.tools.sessions import _sessions

    sessions_cleaned = len(_sessions)
    _sessions.clear()

    return {
        "scans_deleted": deleted,
        "sessions_cleared": sessions_cleaned,
        "redis_cleaned": redis_cleaned,
        "status": "WIPED",
        "note": "Toutes les traces ont ete supprimees. VACUUM ANALYZE recommande.",
    }


# ---------------------------------------------------------------------------
# PDF generation with reportlab
# ---------------------------------------------------------------------------

_SEVERITY_COLORS = {
    "critical": (0.8, 0.0, 0.0),
    "high": (0.9, 0.3, 0.0),
    "medium": (0.9, 0.7, 0.0),
    "low": (0.2, 0.6, 0.2),
    "info": (0.3, 0.3, 0.8),
}


def _generate_pdf_report(scan: ScanResult) -> bytes:
    """Genere un rapport PDF pentest professionnel avec reportlab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm, mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        spaceAfter=6 * mm,
        textColor=colors.HexColor("#1a237e"),
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        spaceBefore=8 * mm,
        spaceAfter=4 * mm,
        textColor=colors.HexColor("#283593"),
        borderWidth=1,
        borderColor=colors.HexColor("#c5cae9"),
        borderPadding=4,
    )
    body_style = styles["BodyText"]
    small_style = ParagraphStyle(
        "SmallText",
        parent=body_style,
        fontSize=8,
        textColor=colors.grey,
    )

    elements: list = []

    # --- Header ---
    elements.append(Paragraph("Pentest Scan Report", title_style))

    created_str = (
        scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if scan.created_at
        else "N/A"
    )
    header_data = [
        ["Date:", created_str],
        ["Module:", scan.module_id],
        ["Target:", scan.target],
        ["Mode:", scan.mode or "internal"],
        ["Status:", scan.status or "completed"],
    ]
    header_table = Table(header_data, colWidths=[4 * cm, 12 * cm])
    header_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    elements.append(header_table)
    elements.append(Spacer(1, 6 * mm))

    # --- Summary ---
    elements.append(Paragraph("Summary", heading_style))

    severity_display = scan.severity_max or "none"
    summary_data = [
        ["Findings Count:", str(scan.findings_count or 0)],
        ["Max Severity:", severity_display.upper()],
        ["Duration:", f"{scan.duration_ms or 0} ms"],
    ]
    summary_table = Table(summary_data, colWidths=[4 * cm, 12 * cm])

    # Color the severity cell
    sev_color = _SEVERITY_COLORS.get(severity_display.lower(), (0.5, 0.5, 0.5))
    summary_table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                (
                    "TEXTCOLOR",
                    (1, 1),
                    (1, 1),
                    colors.Color(*sev_color),
                ),
                ("FONTNAME", (1, 1), (1, 1), "Helvetica-Bold"),
            ]
        )
    )
    elements.append(summary_table)
    elements.append(Spacer(1, 6 * mm))

    # --- Detailed Findings ---
    elements.append(Paragraph("Detailed Findings", heading_style))

    try:
        result_data = json.loads(scan.result_json)
    except (json.JSONDecodeError, TypeError):
        result_data = {}

    # Try to extract findings from common structures
    findings = _extract_findings(result_data)

    if findings:
        table_header = ["#", "Finding", "Severity", "Details"]
        table_data = [table_header]

        for idx, finding in enumerate(findings, 1):
            name = str(finding.get("name", finding.get("title", f"Finding {idx}")))
            sev = str(finding.get("severity", "info"))
            detail = str(finding.get("detail", finding.get("description", "")))
            # Truncate long details for the table
            if len(detail) > 120:
                detail = detail[:117] + "..."
            table_data.append([str(idx), name, sev.upper(), detail])

        findings_table = Table(
            table_data, colWidths=[1 * cm, 5 * cm, 2.5 * cm, 8.5 * cm]
        )
        findings_table.setStyle(
            TableStyle(
                [
                    # Header row
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a237e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, 0), 9),
                    # Body
                    ("FONTSIZE", (0, 1), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    # Alternate row colors
                    *[
                        (
                            "BACKGROUND",
                            (0, i),
                            (-1, i),
                            colors.HexColor("#f5f5f5"),
                        )
                        for i in range(2, len(table_data), 2)
                    ],
                ]
            )
        )
        elements.append(findings_table)
    else:
        # No structured findings — dump the raw JSON in a readable format
        elements.append(
            Paragraph("No structured findings extracted. Raw result data:", body_style)
        )
        elements.append(Spacer(1, 3 * mm))
        raw_text = json.dumps(result_data, indent=2, ensure_ascii=False)
        # Truncate if too long
        if len(raw_text) > 3000:
            raw_text = raw_text[:3000] + "\n... (truncated)"
        # Escape HTML entities for Paragraph
        raw_text = (
            raw_text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", "<br/>")
            .replace(" ", "&nbsp;")
        )
        code_style = ParagraphStyle(
            "CodeBlock",
            parent=body_style,
            fontName="Courier",
            fontSize=7,
            leading=9,
            backColor=colors.HexColor("#f5f5f5"),
            borderWidth=0.5,
            borderColor=colors.grey,
            borderPadding=6,
        )
        elements.append(Paragraph(raw_text, code_style))

    # --- Notes ---
    if scan.notes:
        elements.append(Spacer(1, 6 * mm))
        elements.append(Paragraph("Notes", heading_style))
        elements.append(Paragraph(scan.notes, body_style))

    # --- Footer ---
    elements.append(Spacer(1, 10 * mm))
    elements.append(
        Paragraph(
            f"Generated by Cyber Defense Dashboard | {created_str}",
            small_style,
        )
    )

    doc.build(elements)
    return buf.getvalue()


def _extract_findings(data: dict | list) -> list[dict]:
    """Tente d'extraire une liste de findings depuis differentes structures JSON."""
    # If the data is already a list of findings
    if isinstance(data, list):
        return data

    if not isinstance(data, dict):
        return []

    # Common keys where findings might live
    for key in ("findings", "vulnerabilities", "results", "issues", "items"):
        val = data.get(key)
        if isinstance(val, list) and val:
            return val

    # If the dict itself looks like a single finding
    if "name" in data or "title" in data or "severity" in data:
        return [data]

    return []
