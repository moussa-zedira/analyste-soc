"""Rules API — trigger detection engine runs."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.auth import RoleChecker
from apps.api.db.session import get_db
from apps.api.detection.engine import run_detection
from apps.api.detection.mitre import get_techniques_for_rule
from apps.api.detection.rules import get_rules
from apps.api.security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_key)])


class RulesRunResponse(BaseModel):
    rules_evaluated: int
    incidents_created: int


@router.post("/run", response_model=RulesRunResponse, dependencies=[Depends(RoleChecker("admin"))])
def run_rules(
    db: Session = Depends(get_db),
) -> dict:
    """Execute all enabled detection rules via the detection engine."""
    try:
        result = run_detection(db)
    except Exception:
        logger.exception("Detection engine failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Detection engine encountered an error.",
        )
    return result


class RuleMitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str


class RuleInfo(BaseModel):
    id: str
    event_type: str
    threshold_count: int
    time_window_seconds: int
    severity: str
    tags: list[str]
    enabled: bool
    mitre_techniques: list[RuleMitreTechnique]


@router.get("", response_model=list[RuleInfo])
def list_rules() -> list[dict]:
    """List all detection rules with MITRE ATT&CK mappings."""
    rules = get_rules(enabled_only=False)
    result = []
    for r in rules:
        techniques = get_techniques_for_rule(r.id)
        result.append({
            "id": r.id,
            "event_type": r.event_type,
            "threshold_count": r.threshold_count,
            "time_window_seconds": int(r.time_window.total_seconds()),
            "severity": r.severity.value,
            "tags": list(r.tags),
            "enabled": r.enabled,
            "mitre_techniques": [
                {
                    "technique_id": t.id,
                    "technique_name": t.name,
                    "tactic_id": t.tactic_id,
                    "tactic_name": t.tactic_name,
                }
                for t in techniques
            ],
        })
    return result
