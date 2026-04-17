"""Compliance reporter : evalue la couverture d'un framework par la plateforme.

Calcule pour chaque controle :
  - status : covered / partial / uncovered
  - evidence : liste des preuves (regles Sigma, modules pentest, etc.)
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from sqlalchemy.orm import Session

from apps.api.compliance.frameworks import (
    ALL_FRAMEWORKS,
    Control,
    Framework,
    get_framework,
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


def _capability_evidence(cap: str, db: Session | None) -> list[dict[str, str]]:
    """Evidence statique + sondes runtime (count Sigma rules, IOCs, etc.)."""
    evidence = list(STATIC_EVIDENCE.get(cap, []))
    if db is None:
        return evidence
    try:
        if cap == "sigma.rules":
            from apps.api.models.sigma_rule import SigmaRule
            n = db.query(SigmaRule).count()
            evidence.append({"type": "runtime_count", "ref": f"sigma_rules={n}"})
        elif cap == "ioc.feeds":
            from apps.api.models.ioc import IOC
            n = db.query(IOC).count()
            evidence.append({"type": "runtime_count", "ref": f"iocs={n}"})
        elif cap == "uba.profiling":
            from apps.api.models.uba import UserBaseline
            n = db.query(UserBaseline).count()
            evidence.append({"type": "runtime_count", "ref": f"profiles={n}"})
        elif cap == "case_mgmt.sla":
            from apps.api.models.case import Case
            n = db.query(Case).count()
            evidence.append({"type": "runtime_count", "ref": f"cases={n}"})
        elif cap == "audit.immutable":
            from apps.api.models.pentest_audit import PentestAuditLog
            n = db.query(PentestAuditLog).count()
            evidence.append({"type": "runtime_count", "ref": f"audit_entries={n}"})
    except Exception:
        # Si la table n'existe pas (migrations pas appliquees), pas grave.
        pass
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
    return {
        fid: evaluate_framework(f, db) for fid, f in ALL_FRAMEWORKS.items()
    }
