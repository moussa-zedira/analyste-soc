"""Export PDF d'un rapport de conformite via reportlab."""

from __future__ import annotations

import io
from datetime import UTC, datetime
from typing import Any

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

STATUS_COLORS = {
    "covered": colors.HexColor("#1f9d55"),
    "partial": colors.HexColor("#f0b429"),
    "uncovered": colors.HexColor("#cc1f1a"),
    "manual": colors.HexColor("#718096"),
}


def _build_styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "title",
            parent=base["Title"],
            fontSize=24,
            leading=28,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0b3d91"),
            spaceAfter=18,
        ),
        "subtitle": ParagraphStyle(
            "subtitle",
            parent=base["Heading2"],
            fontSize=14,
            leading=18,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#444"),
            spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "h2",
            parent=base["Heading2"],
            fontSize=15,
            leading=18,
            textColor=colors.HexColor("#0b3d91"),
            spaceBefore=14,
            spaceAfter=6,
        ),
        "h3": ParagraphStyle(
            "h3",
            parent=base["Heading3"],
            fontSize=12,
            leading=14,
            textColor=colors.HexColor("#222"),
            spaceBefore=8,
            spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["BodyText"],
            fontSize=9,
            leading=12,
            alignment=TA_LEFT,
        ),
        "small": ParagraphStyle(
            "small",
            parent=base["BodyText"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#444"),
        ),
        "kpi": ParagraphStyle(
            "kpi",
            parent=base["Heading1"],
            fontSize=44,
            leading=48,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#0b3d91"),
        ),
    }


def _coverage_chart(by_status: dict[str, int]) -> Drawing:
    drawing = Drawing(380, 180)
    statuses = ["covered", "partial", "uncovered", "manual"]
    values = [int(by_status.get(s, 0)) for s in statuses]
    chart = VerticalBarChart()
    chart.x = 50
    chart.y = 30
    chart.width = 300
    chart.height = 130
    chart.data = [values]
    chart.categoryAxis.categoryNames = ["Covered", "Partial", "Uncovered", "Manual"]
    chart.valueAxis.valueMin = 0
    chart.valueAxis.valueMax = max(values + [1])
    chart.bars[0].fillColor = colors.HexColor("#0b3d91")
    chart.barWidth = 14
    chart.groupSpacing = 18
    drawing.add(chart)
    return drawing


def _legend_block() -> Drawing:
    drawing = Drawing(420, 22)
    x = 0
    for label, color in [
        ("Covered", STATUS_COLORS["covered"]),
        ("Partial", STATUS_COLORS["partial"]),
        ("Uncovered", STATUS_COLORS["uncovered"]),
        ("Manual", STATUS_COLORS["manual"]),
    ]:
        drawing.add(Rect(x, 4, 14, 14, fillColor=color, strokeColor=color))
        drawing.add(String(x + 18, 8, label, fontSize=9, fillColor=colors.black))
        x += 100
    return drawing


def _format_evidence(ev_by_cap: dict[str, list[dict[str, Any]]]) -> str:
    if not ev_by_cap:
        return "<i>none</i>"
    parts: list[str] = []
    for cap, items in ev_by_cap.items():
        if not items:
            parts.append(f"<b>{cap}</b>: <font color='#cc1f1a'>missing</font>")
            continue
        refs = []
        for it in items[:5]:
            t = it.get("type", "?")
            r = it.get("ref", "")
            refs.append(f"{t}:{r}")
        parts.append(f"<b>{cap}</b>: " + " | ".join(refs))
    return "<br/>".join(parts)


def _controls_table(controls: list[dict[str, Any]], styles: dict) -> Table:
    headers = ["Control", "Title", "Status", "Capabilities (cov/total)"]
    data: list[list[Any]] = [headers]
    row_styles: list[tuple] = []
    for idx, c in enumerate(controls, start=1):
        status = c.get("status", "manual")
        caps = c.get("capabilities") or []
        covered = c.get("covered_capabilities") or []
        title_para = Paragraph(c.get("title", ""), styles["small"])
        data.append(
            [
                Paragraph(f"<b>{c.get('id', '')}</b>", styles["small"]),
                title_para,
                Paragraph(status.upper(), styles["small"]),
                Paragraph(f"{len(covered)}/{len(caps)}", styles["small"]),
            ]
        )
        row_styles.append(
            (
                "BACKGROUND",
                (2, idx),
                (2, idx),
                STATUS_COLORS.get(status, colors.grey),
            )
        )
        row_styles.append(("TEXTCOLOR", (2, idx), (2, idx), colors.white))
    table = Table(data, colWidths=[3.5 * cm, 8.0 * cm, 2.5 * cm, 3.5 * cm], repeatRows=1)
    base_style = TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
            ("TOPPADDING", (0, 0), (-1, 0), 6),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (2, 1), (2, -1), "CENTER"),
            ("ALIGN", (3, 1), (3, -1), "CENTER"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ]
    )
    for s in row_styles:
        base_style.add(*s)
    table.setStyle(base_style)
    return table


def _evidence_table(controls: list[dict[str, Any]], styles: dict) -> Table:
    data: list[list[Any]] = [["Control", "Evidence"]]
    for c in controls:
        ev_text = _format_evidence(c.get("evidence", {}))
        data.append(
            [
                Paragraph(
                    f"<b>{c.get('id', '')}</b><br/><font size=7>{c.get('title', '')}</font>",
                    styles["small"],
                ),
                Paragraph(ev_text, styles["small"]),
            ]
        )
    table = Table(data, colWidths=[4.5 * cm, 13.0 * cm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ]
        )
    )
    return table


def _remediations_table(remediations: list[dict[str, Any]], styles: dict) -> Table | Paragraph:
    if not remediations:
        return Paragraph("<i>No open remediation items.</i>", styles["body"])
    data: list[list[Any]] = [["Control", "Severity", "Title", "Status", "Due"]]
    for r in remediations:
        data.append(
            [
                Paragraph(r.get("control_id", ""), styles["small"]),
                Paragraph(r.get("severity", ""), styles["small"]),
                Paragraph(r.get("title", ""), styles["small"]),
                Paragraph(r.get("status", ""), styles["small"]),
                Paragraph(str(r.get("due_date", "") or "-"), styles["small"]),
            ]
        )
    table = Table(data, colWidths=[3.0 * cm, 1.8 * cm, 7.5 * cm, 2.2 * cm, 3.0 * cm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 9),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ]
        )
    )
    return table


def generate_compliance_pdf(
    report: dict[str, Any],
    framework_meta: dict[str, Any] | None = None,
    output_path: str | None = None,
    remediations: list[dict[str, Any]] | None = None,
) -> bytes:
    framework = report.get("framework", {}) or framework_meta or {}
    summary = report.get("summary", {})
    controls = report.get("controls", [])
    remediations = remediations or []

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title=f"Compliance Report — {framework.get('name', 'Framework')}",
        author="Cyber Defense Dashboard",
    )

    styles = _build_styles()
    story: list = []

    story.append(Spacer(1, 60))
    story.append(Paragraph("Compliance Coverage Report", styles["title"]))
    story.append(Paragraph(framework.get("name", "Framework"), styles["subtitle"]))
    story.append(Spacer(1, 12))

    score = summary.get("coverage_score", 0.0)
    story.append(Paragraph(f"{score:.1f}%", styles["kpi"]))
    story.append(Paragraph("Coverage score", styles["subtitle"]))
    story.append(Spacer(1, 18))

    meta_data = [
        ["Framework ID", framework.get("id", "-")],
        ["Version", framework.get("version", "-")],
        ["URL", framework.get("url", "-")],
        ["Controls evaluated", str(summary.get("controls_total", len(controls)))],
        ["Generated at", datetime.now(UTC).isoformat(timespec="seconds")],
    ]
    meta_tbl = Table(meta_data, colWidths=[5.0 * cm, 11.0 * cm])
    meta_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef3fb")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#0b3d91")),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ]
        )
    )
    story.append(meta_tbl)

    story.append(PageBreak())

    story.append(Paragraph("1. Executive Summary", styles["h2"]))
    story.append(
        Paragraph(
            f"This report assesses the platform's coverage of the <b>{framework.get('name', '')}</b> "
            f"framework. {summary.get('controls_total', 0)} controls were evaluated. "
            f"Aggregate coverage score: <b>{score:.1f}%</b>.",
            styles["body"],
        )
    )
    story.append(Spacer(1, 10))
    story.append(_coverage_chart(summary.get("by_status", {})))
    story.append(_legend_block())
    story.append(Spacer(1, 10))

    by_status = summary.get("by_status", {})
    counts_data = [
        ["Status", "Count"],
        ["Covered", str(by_status.get("covered", 0))],
        ["Partial", str(by_status.get("partial", 0))],
        ["Uncovered", str(by_status.get("uncovered", 0))],
        ["Manual", str(by_status.get("manual", 0))],
    ]
    counts_tbl = Table(counts_data, colWidths=[6.0 * cm, 3.0 * cm])
    counts_tbl.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b3d91")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (1, 0), (1, -1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cccccc")),
            ]
        )
    )
    story.append(counts_tbl)

    story.append(PageBreak())
    story.append(Paragraph("2. Controls Coverage", styles["h2"]))
    story.append(_controls_table(controls, styles))

    story.append(PageBreak())
    story.append(Paragraph("3. Evidence Annex", styles["h2"]))
    story.append(_evidence_table(controls, styles))

    story.append(PageBreak())
    story.append(Paragraph("4. Remediations", styles["h2"]))
    story.append(_remediations_table(remediations, styles))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    if output_path:
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)
    return pdf_bytes
