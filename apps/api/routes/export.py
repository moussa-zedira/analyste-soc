"""Export PDF — génération de rapports pour scans et incidents."""

from __future__ import annotations

import io
import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.incident import Incident
from apps.api.models.scan_history import ScanHistory
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


def _build_scan_pdf(scan: ScanHistory) -> bytes:
    """Génère un rapport PDF pour un scan réseau."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ScanTitle",
        parent=styles["Title"],
        fontSize=18,
        textColor=colors.HexColor("#00BCD4"),
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "ScanHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#00BCD4"),
        spaceAfter=6,
        spaceBefore=14,
    )
    normal = styles["Normal"]

    elements: list = []

    # Title
    elements.append(Paragraph("CYBERDEF — Scan Report", title_style))
    elements.append(Spacer(1, 4 * mm))

    result = json.loads(scan.result_json) if scan.result_json else {}

    # Meta info
    meta_data = [
        ["Target", scan.target],
        ["Type", scan.target_type],
        ["IP", scan.resolved_ip or "N/A"],
        ["Score", f"{scan.security_score}/100"],
        ["Open Ports", str(scan.open_ports_count)],
        ["Duration", f"{scan.scan_duration_ms}ms"],
        ["Date", scan.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.created_at else "N/A"],
    ]
    meta_table = Table(meta_data, colWidths=[100, 350])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#00BCD4")),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.white),
                ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#0d0d1a")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333355")),
            ]
        )
    )
    elements.append(meta_table)

    # Open ports
    open_ports = result.get("open_ports", [])
    if open_ports:
        elements.append(Paragraph("Open Ports", heading_style))
        port_data = [["Port", "Service", "State", "Banner"]]
        for p in open_ports:
            port_data.append(
                [
                    str(p.get("port", "")),
                    p.get("service", ""),
                    p.get("state", ""),
                    (p.get("banner") or "")[:60],
                ]
            )
        port_table = Table(port_data, colWidths=[60, 80, 60, 250])
        port_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00BCD4")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0d0d1a")),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333355")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                ]
            )
        )
        elements.append(port_table)

    # GeoIP
    geo = result.get("geo")
    if geo:
        elements.append(Paragraph("Geolocation", heading_style))
        geo_data = [[k, str(v)] for k, v in geo.items() if v is not None]
        if geo_data:
            geo_table = Table(geo_data, colWidths=[100, 350])
            geo_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                        ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#0d0d1a")),
                        ("FONTSIZE", (0, 0), (-1, -1), 8),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333355")),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ]
                )
            )
            elements.append(geo_table)

    # Security score details
    score_details = result.get("score_details", [])
    if score_details:
        elements.append(Paragraph("Security Score Details", heading_style))
        score_data = [["Check", "Status", "Points"]]
        for d in score_details:
            score_data.append(
                [
                    d.get("check", ""),
                    "PASS" if d.get("passed") else "FAIL",
                    str(d.get("points", 0)),
                ]
            )
        score_table = Table(score_data, colWidths=[250, 60, 60])
        score_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00BCD4")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0d0d1a")),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333355")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(score_table)

    # CVEs
    cves = result.get("cves", [])
    if cves:
        elements.append(Paragraph("Vulnerabilities (CVE)", heading_style))
        cve_data = [["CVE ID", "Severity", "Description"]]
        for c in cves:
            cve_data.append(
                [
                    c.get("id", ""),
                    c.get("severity", ""),
                    (c.get("description") or "")[:80],
                ]
            )
        cve_table = Table(cve_data, colWidths=[100, 60, 290])
        cve_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EF4444")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0d0d1a")),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333355")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        elements.append(cve_table)

    # Footer
    elements.append(Spacer(1, 10 * mm))
    elements.append(
        Paragraph(
            f"Generated by CyberDef SIEM — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            ParagraphStyle("Footer", parent=normal, fontSize=7, textColor=colors.grey),
        )
    )

    doc.build(elements)
    return buf.getvalue()


def _build_incident_pdf(incident: Incident) -> bytes:
    """Génère un rapport PDF pour un incident."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "IncTitle",
        parent=styles["Title"],
        fontSize=18,
        textColor=colors.HexColor("#00BCD4"),
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "IncHeading",
        parent=styles["Heading2"],
        fontSize=13,
        textColor=colors.HexColor("#00BCD4"),
        spaceAfter=6,
        spaceBefore=14,
    )
    normal = styles["Normal"]

    elements: list = []
    elements.append(Paragraph("CYBERDEF — Incident Report", title_style))
    elements.append(Spacer(1, 4 * mm))

    {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#F59E0B",
        "low": "#3B82F6",
    }.get(incident.severity, "#6B7280")

    meta_data = [
        ["ID", incident.id],
        ["Title", incident.title],
        ["Severity", incident.severity.upper()],
        ["Status", incident.status],
        ["Rule", incident.rule_id],
        ["Entity", incident.entity_key],
        [
            "Created",
            incident.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if incident.created_at else "N/A",
        ],
    ]
    meta_table = Table(meta_data, colWidths=[100, 350])
    meta_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#1a1a2e")),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#00BCD4")),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.white),
                ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#0d0d1a")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333355")),
            ]
        )
    )
    elements.append(meta_table)

    # Description
    elements.append(Paragraph("Description", heading_style))
    elements.append(Paragraph(incident.description or "N/A", normal))

    # Related events
    if incident.events:
        elements.append(Paragraph(f"Related Events ({len(incident.events)})", heading_style))
        ev_data = [["Timestamp", "Type", "Source", "Severity", "Source IP"]]
        for ev in incident.events[:50]:
            ev_data.append(
                [
                    ev.ts.strftime("%H:%M:%S") if ev.ts else "",
                    ev.event_type or "",
                    ev.source or "",
                    ev.severity or "",
                    ev.src_ip or "",
                ]
            )
        ev_table = Table(ev_data, colWidths=[70, 90, 70, 60, 100])
        ev_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00BCD4")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0d0d1a")),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#333355")),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        elements.append(ev_table)

    # Footer
    elements.append(Spacer(1, 10 * mm))
    elements.append(
        Paragraph(
            f"Generated by CyberDef SIEM — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            ParagraphStyle("Footer", parent=normal, fontSize=7, textColor=colors.grey),
        )
    )

    doc.build(elements)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/scan/{scan_id}/pdf")
def export_scan_pdf(
    scan_id: str,
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Exporte un rapport de scan en PDF."""
    scan = db.get(ScanHistory, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan non trouvé")

    pdf_bytes = _build_scan_pdf(scan)
    filename = f"scan_{scan.target}_{scan_id[:8]}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/incident/{incident_id}/pdf")
def export_incident_pdf(
    incident_id: str,
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Exporte un rapport d'incident en PDF."""
    incident = db.get(Incident, incident_id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident non trouvé")

    pdf_bytes = _build_incident_pdf(incident)
    filename = f"incident_{incident_id[:8]}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
