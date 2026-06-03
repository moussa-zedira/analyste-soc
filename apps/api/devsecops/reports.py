"""DevSecOps Reports — dashboard metrics, trend analysis, exports."""

from __future__ import annotations

import csv
import io
import json
import logging
from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.models.devsecops import ScanFinding, ScanRun

logger = logging.getLogger(__name__)
slog = structlog.get_logger(__name__)


def get_dashboard_metrics(db: Session, project_id: int | None = None) -> dict[str, Any]:
    """Compute security posture dashboard metrics."""
    run_query = db.query(ScanRun)
    finding_query = db.query(ScanFinding)

    if project_id:
        run_query = run_query.filter(ScanRun.project_id == project_id)
        finding_ids = db.query(ScanRun.id).filter(ScanRun.project_id == project_id).subquery()
        finding_query = finding_query.filter(ScanFinding.run_id.in_(finding_ids))

    total_runs = run_query.count()
    total_findings = finding_query.filter(not ScanFinding.false_positive).count()

    severity_counts = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        severity_counts[sev] = finding_query.filter(
            ScanFinding.severity == sev,
            not ScanFinding.false_positive,
        ).count()

    # Findings by scan type
    type_counts = {}
    for row in (
        finding_query.filter(not ScanFinding.false_positive)
        .with_entities(ScanFinding.scan_type, func.count(ScanFinding.id))
        .group_by(ScanFinding.scan_type)
        .all()
    ):
        type_counts[row[0]] = row[1]

    # Resolution rate
    resolved = finding_query.filter(ScanFinding.resolved).count()
    resolution_rate = round(resolved / total_findings * 100, 1) if total_findings else 0.0

    # Quality gate pass rate
    gate_runs = run_query.filter(ScanRun.quality_gate_passed.isnot(None)).count()
    gate_passed = run_query.filter(ScanRun.quality_gate_passed).count()
    gate_pass_rate = round(gate_passed / gate_runs * 100, 1) if gate_runs else 0.0

    # Last scan
    last_run = run_query.order_by(ScanRun.created_at.desc()).first()

    return {
        "total_runs": total_runs,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "type_counts": type_counts,
        "resolved_findings": resolved,
        "resolution_rate": resolution_rate,
        "quality_gate_pass_rate": gate_pass_rate,
        "last_scan": last_run.created_at.isoformat() if last_run and last_run.created_at else None,
    }


def get_trend_analysis(
    db: Session,
    project_id: int | None = None,
    days: int = 30,
) -> list[dict[str, Any]]:
    """Compute finding trends over time (findings per day, grouped by severity)."""
    cutoff = datetime.now(UTC) - timedelta(days=days)

    query = (
        db.query(
            func.date(ScanRun.created_at).label("day"),
            ScanFinding.severity,
            func.count(ScanFinding.id).label("count"),
        )
        .join(ScanRun, ScanFinding.run_id == ScanRun.id)
        .filter(ScanRun.created_at >= cutoff, not ScanFinding.false_positive)
    )
    if project_id:
        query = query.filter(ScanRun.project_id == project_id)

    rows = query.group_by(func.date(ScanRun.created_at), ScanFinding.severity).all()

    trend: dict[str, dict[str, int]] = defaultdict(
        lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    for day, severity, count in rows:
        day_str = str(day)
        trend[day_str][severity] = count

    return [{"date": d, **counts} for d, counts in sorted(trend.items())]


def get_top_vulnerable_deps(
    db: Session,
    project_id: int | None = None,
    limit: int = 20,
) -> list[dict[str, Any]]:
    """Return top vulnerable dependencies ranked by frequency and severity."""
    query = db.query(ScanFinding).filter(
        ScanFinding.scan_type == "sca",
        not ScanFinding.false_positive,
        not ScanFinding.resolved,
    )
    if project_id:
        run_ids = db.query(ScanRun.id).filter(ScanRun.project_id == project_id).subquery()
        query = query.filter(ScanFinding.run_id.in_(run_ids))

    findings = query.order_by(ScanFinding.created_at.desc()).limit(200).all()

    dep_map: dict[str, dict] = {}
    for f in findings:
        title = f.title or ""
        key = title.split(":")[-1].strip() if ":" in title else title
        if key not in dep_map:
            dep_map[key] = {
                "dependency": key,
                "count": 0,
                "severity": f.severity,
                "cwe_id": f.cwe_id,
            }
        dep_map[key]["count"] += 1

    ranked = sorted(dep_map.values(), key=lambda x: (-x["count"], x["severity"]))
    return ranked[:limit]


def get_secret_leak_summary(
    db: Session,
    project_id: int | None = None,
) -> dict[str, Any]:
    """Summary of secret leaks detected."""
    query = db.query(ScanFinding).filter(
        ScanFinding.scan_type == "secrets",
        not ScanFinding.false_positive,
    )
    if project_id:
        run_ids = db.query(ScanRun.id).filter(ScanRun.project_id == project_id).subquery()
        query = query.filter(ScanFinding.run_id.in_(run_ids))

    findings = query.all()
    type_counts: dict[str, int] = Counter()
    for f in findings:
        type_counts[f.title or "Unknown"] += 1

    return {
        "total_secrets": len(findings),
        "resolved": sum(1 for f in findings if f.resolved),
        "by_type": dict(type_counts.most_common(20)),
    }


def export_findings_csv(findings: list[dict]) -> str:
    """Export findings to CSV format."""
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "scan_type",
            "severity",
            "title",
            "cwe_id",
            "file_path",
            "line_number",
            "description",
            "remediation",
            "false_positive",
            "resolved",
        ],
    )
    writer.writeheader()
    for f in findings:
        writer.writerow(
            {
                "scan_type": f.get("scan_type", ""),
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
                "cwe_id": f.get("cwe_id", ""),
                "file_path": f.get("file_path", ""),
                "line_number": f.get("line_number", ""),
                "description": f.get("description", ""),
                "remediation": f.get("remediation", ""),
                "false_positive": f.get("false_positive", False),
                "resolved": f.get("resolved", False),
            }
        )
    return output.getvalue()


def export_findings_json(findings: list[dict]) -> str:
    """Export findings to JSON format."""
    return json.dumps(findings, indent=2, ensure_ascii=False, default=str)


def generate_executive_summary(metrics: dict, trend: list[dict]) -> dict[str, Any]:
    """Generate an executive summary from dashboard metrics."""
    sev = metrics.get("severity_counts", {})
    total = metrics.get("total_findings", 0)

    risk_level = "LOW"
    if sev.get("critical", 0) > 0:
        risk_level = "CRITICAL"
    elif sev.get("high", 0) > 5:
        risk_level = "HIGH"
    elif sev.get("high", 0) > 0 or sev.get("medium", 0) > 10:
        risk_level = "MEDIUM"

    # Trend direction
    if len(trend) >= 2:
        recent = sum(trend[-1].get(s, 0) for s in ("critical", "high", "medium"))
        older = sum(trend[0].get(s, 0) for s in ("critical", "high", "medium"))
        trend_direction = (
            "improving" if recent < older else "worsening" if recent > older else "stable"
        )
    else:
        trend_direction = "insufficient data"

    return {
        "risk_level": risk_level,
        "total_findings": total,
        "critical_findings": sev.get("critical", 0),
        "high_findings": sev.get("high", 0),
        "resolution_rate": metrics.get("resolution_rate", 0),
        "quality_gate_pass_rate": metrics.get("quality_gate_pass_rate", 0),
        "trend_direction": trend_direction,
        "recommendation": _get_recommendation(risk_level, sev),
    }


def _get_recommendation(risk_level: str, severity_counts: dict) -> str:
    """Generate a recommendation based on risk level."""
    if risk_level == "CRITICAL":
        return (
            "IMMEDIATE ACTION REQUIRED: Critical vulnerabilities detected. "
            "Address all critical findings before the next deployment. "
            "Consider halting releases until critical issues are resolved."
        )
    if risk_level == "HIGH":
        return (
            "HIGH PRIORITY: Multiple high-severity findings detected. "
            "Create remediation tickets and address within the current sprint."
        )
    if risk_level == "MEDIUM":
        return (
            "MODERATE RISK: Some security issues found. "
            "Schedule remediation within the next 2 sprints."
        )
    return "Security posture is healthy. Continue regular scanning and monitoring."
