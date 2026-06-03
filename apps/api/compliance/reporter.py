"""Compliance reporter : evalue la couverture d'un framework par la plateforme.

Calcule pour chaque controle :
  - status : covered / partial / uncovered
  - evidence : liste des preuves (regles Sigma, modules pentest, etc.)
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

from apps.api.compliance.frameworks import (
    ALL_FRAMEWORKS,
    Control,
    Framework,
)

# ──────────────────────────────────────────────────────────────────────
# Capability registry — qui implemente quoi
# ──────────────────────────────────────────────────────────────────────

# Pour chaque capability, une liste d'evidence statique (modules, fichiers).
# En production, on pourrait l'enrichir dynamiquement (count Sigma rules
# avec cette tag, etc.). Ici on combine statique + sondes runtime.

STATIC_EVIDENCE: dict[str, list[dict[str, str]]] = {
    "sigma.rules": [
        {"type": "module", "ref": "apps/api/detection/sigma_engine.py"},
        {"type": "seed", "ref": "apps/api/detection/sigma_builtin.py"},
    ],
    "mitre.coverage": [
        {"type": "module", "ref": "apps/api/detection/mitre.py"},
        {"type": "ui", "ref": "/threat-hunt"},
    ],
    "uba.profiling": [
        {"type": "module", "ref": "apps/api/uba/engine.py"},
        {"type": "endpoint", "ref": "/uba/entities"},
    ],
    "case_mgmt.sla": [
        {"type": "module", "ref": "apps/api/cases/service.py"},
        {"type": "endpoint", "ref": "/cases"},
    ],
    "incident.playbook": [
        {"type": "module", "ref": "apps/api/routes/soar.py"},
    ],
    "detection.brute_force": [
        {"type": "rule", "ref": "builtin: brute_force_5_in_1m"},
    ],
    "detection.malware": [
        {"type": "module", "ref": "apps/api/routes/threat_intel.py"},
        {"type": "module", "ref": "apps/api/routes/ioc.py"},
    ],
    "detection.exfil": [
        {"type": "module", "ref": "apps/api/pentest/post_exploit/exfiltration.py"},
        {"type": "rule", "ref": "builtin: dns_volume_burst"},
    ],
    "detection.lateral": [
        {"type": "module", "ref": "apps/api/pentest/post_exploit/lateral.py"},
    ],
    "audit.immutable": [
        {"type": "model", "ref": "apps/api/models/pentest_audit.py"},
        {"type": "trigger", "ref": "alembic/008 — postgres trigger no_update_delete"},
    ],
    "audit.user_actions": [
        {"type": "model", "ref": "apps/api/models/audit_log.py"},
    ],
    "encryption.tls": [
        {"type": "config", "ref": "nginx/nginx.conf — TLSv1.2/1.3 HIGH"},
        {"type": "overlay", "ref": "docker-compose.tls.yml"},
    ],
    "secrets.vault": [
        {"type": "module", "ref": "apps/api/config.py — _load_file_backed_secrets"},
        {"type": "overlay", "ref": "docker-compose.secrets.yml"},
    ],
    "vuln.scan": [
        {"type": "module", "ref": "apps/api/pentest/recon/vuln_scanner.py"},
        {"type": "module", "ref": "apps/api/routes/devsecops.py"},
    ],
    "ioc.feeds": [
        {"type": "module", "ref": "apps/api/routes/feeds.py"},
        {"type": "module", "ref": "apps/api/routes/ioc.py"},
    ],
    "backup.dr": [
        {"type": "script", "ref": "scripts/backup.sh"},
        {"type": "doc", "ref": "docs/RUNBOOK_DR.md"},
    ],
}


def _metric(ref: str, value: float | int) -> dict[str, Any]:
    return {"type": "metric", "ref": ref, "value": value}


def _capability_evidence(cap: str, db: Session | None) -> list[dict[str, Any]]:
    """Evidence statique + sondes runtime (counts, metrics, dates)."""
    evidence: list[dict[str, Any]] = list(STATIC_EVIDENCE.get(cap, []))
    if db is None:
        return evidence
    cutoff_30d = datetime.now(UTC) - timedelta(days=30)
    try:
        if cap == "sigma.rules":
            from apps.api.models.sigma_rule import SigmaRule

            n = db.query(SigmaRule).count()
            evidence.append(_metric(f"sigma_rules={n}", n))
        elif cap == "ioc.feeds":
            try:
                from apps.api.models.ioc import IOC, ThreatFeed

                n_active = db.query(IOC).filter(IOC.state == "active").count()
                evidence.append(_metric(f"iocs_active={n_active}", n_active))
                rows = (
                    db.query(IOC.source, func.count(IOC.id))
                    .filter(IOC.state == "active")
                    .group_by(IOC.source)
                    .all()
                )
                for src, cnt in rows:
                    evidence.append(_metric(f"iocs[{src}]={cnt}", int(cnt)))
                feeds_enabled = db.query(ThreatFeed).filter(ThreatFeed.enabled).count()
                evidence.append(_metric(f"feeds_enabled={feeds_enabled}", feeds_enabled))
            except Exception:
                logger.debug("reporter: evidence collection failed", exc_info=True)
        elif cap == "uba.profiling":
            from apps.api.models.uba import UserBaseline

            n = db.query(UserBaseline).count()
            evidence.append(_metric(f"profiles={n}", n))
        elif cap == "case_mgmt.sla":
            from apps.api.models.case import Case

            total = db.query(Case).count()
            evidence.append(_metric(f"cases_total={total}", total))
            try:
                closed = (
                    db.query(Case)
                    .filter(Case.status == "closed")
                    .filter(Case.closed_at.isnot(None))
                    .filter(Case.closed_at >= cutoff_30d)
                    .all()
                )
                ttrs = [
                    (c.closed_at - c.created_at).total_seconds() / 60.0
                    for c in closed
                    if c.created_at and c.closed_at
                ]
                if ttrs:
                    mean_ttr = sum(ttrs) / len(ttrs)
                    evidence.append(
                        _metric(
                            f"mean_ttr_minutes_30d={mean_ttr:.1f}",
                            round(mean_ttr, 1),
                        )
                    )
                evidence.append(_metric(f"cases_closed_30d={len(closed)}", len(closed)))
            except Exception:
                logger.debug("reporter: evidence collection failed", exc_info=True)
        elif cap == "audit.immutable":
            from apps.api.models.pentest_audit import PentestAuditLog

            n = db.query(PentestAuditLog).count()
            evidence.append(_metric(f"audit_entries={n}", n))
            try:
                last = db.query(PentestAuditLog).order_by(PentestAuditLog.id.desc()).first()
                if last is not None:
                    ts_attr = getattr(last, "ts", None) or getattr(last, "created_at", None)
                    if ts_attr is not None:
                        evidence.append(
                            {
                                "type": "metric",
                                "ref": f"last_audit={ts_attr.isoformat()}",
                                "value": ts_attr.isoformat(),
                            }
                        )
            except Exception:
                logger.debug("reporter: evidence collection failed", exc_info=True)
        elif cap == "audit.user_actions":
            try:
                from apps.api.models.audit_log import AuditLog

                n = db.query(AuditLog).count()
                evidence.append(_metric(f"audit_user_entries={n}", n))
                last = db.query(AuditLog).order_by(AuditLog.created_at.desc()).first()
                if last is not None and last.created_at is not None:
                    evidence.append(
                        {
                            "type": "metric",
                            "ref": f"last_user_action={last.created_at.isoformat()}",
                            "value": last.created_at.isoformat(),
                        }
                    )
            except Exception:
                logger.debug("reporter: evidence collection failed", exc_info=True)
        elif cap in {
            "detection.brute_force",
            "detection.malware",
            "detection.exfil",
            "detection.lateral",
            "incident.playbook",
        }:
            try:
                from apps.api.models.incident import Incident

                resolved = (
                    db.query(Incident)
                    .filter(Incident.status.in_(["resolved", "closed"]))
                    .filter(Incident.updated_at >= cutoff_30d)
                    .count()
                )
                evidence.append(
                    _metric(
                        f"incidents_resolved_30d={resolved}",
                        resolved,
                    )
                )
            except Exception:
                logger.debug("reporter: evidence collection failed", exc_info=True)
        elif cap == "vuln.scan":
            try:
                from apps.api.models.scan_history import ScanHistory

                n = db.query(ScanHistory).count()
                evidence.append(_metric(f"scans_total={n}", n))
            except Exception:
                logger.debug("reporter: evidence collection failed", exc_info=True)
            try:
                from apps.api.models.devsecops import ScanRun

                runs_30d = (
                    (db.query(ScanRun).filter(ScanRun.created_at >= cutoff_30d).count())
                    if hasattr(ScanRun, "created_at")
                    else db.query(ScanRun).count()
                )
                evidence.append(_metric(f"devsecops_runs_30d={runs_30d}", runs_30d))
            except Exception:
                logger.debug("reporter: evidence collection failed", exc_info=True)
    except Exception:
        logger.debug("reporter: evidence collection failed", exc_info=True)
    return evidence


# ──────────────────────────────────────────────────────────────────────
# Evaluation
# ──────────────────────────────────────────────────────────────────────


def evaluate_control(control: Control, db: Session | None) -> dict[str, Any]:
    covered_caps: list[str] = []
    missing_caps: list[str] = []
    evidence_by_cap: dict[str, list[dict[str, str]]] = {}
    for cap in control.capabilities:
        ev = _capability_evidence(cap, db)
        if ev:
            covered_caps.append(cap)
        else:
            missing_caps.append(cap)
        evidence_by_cap[cap] = ev

    if not control.capabilities:
        status = "manual"
    elif not missing_caps:
        status = "covered"
    elif covered_caps:
        status = "partial"
    else:
        status = "uncovered"
    return {
        "id": control.id,
        "title": control.title,
        "description": control.description,
        "mandatory": control.mandatory,
        "status": status,
        "capabilities": control.capabilities,
        "covered_capabilities": covered_caps,
        "missing_capabilities": missing_caps,
        "evidence": evidence_by_cap,
    }


def evaluate_framework(framework: Framework, db: Session | None) -> dict[str, Any]:
    controls = [evaluate_control(c, db) for c in framework.controls]
    counts: dict[str, int] = {"covered": 0, "partial": 0, "uncovered": 0, "manual": 0}
    for c in controls:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    total = len(controls) or 1
    score = (counts["covered"] + 0.5 * counts["partial"]) / total * 100.0
    return {
        "framework": {
            "id": framework.id,
            "name": framework.name,
            "version": framework.version,
            "url": framework.url,
        },
        "summary": {
            "controls_total": total,
            "by_status": counts,
            "coverage_score": round(score, 1),
        },
        "controls": controls,
    }


def evaluate_all(db: Session | None) -> dict[str, Any]:
    return {fid: evaluate_framework(f, db) for fid, f in ALL_FRAMEWORKS.items()}
