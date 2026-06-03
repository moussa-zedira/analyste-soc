"""API MITRE ATT&CK — couverture des regles de detection et export Navigator."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from apps.api.auth import RoleChecker
from apps.api.detection.mitre import (
    ALL_TECHNIQUES,
    RULE_MITRE_MAP,
    TACTIC_ORDER,
    coverage_by_tactic,
    navigator_layer,
)
from apps.api.security import require_api_key

router = APIRouter(
    prefix="/detection/mitre",
    tags=["detection-mitre"],
    dependencies=[Depends(require_api_key)],
)


@router.get("/coverage", dependencies=[Depends(RoleChecker(["admin", "analyst", "viewer"]))])
def mitre_coverage() -> dict[str, object]:
    """Couverture des regles par tactique MITRE ATT&CK."""
    coverage = coverage_by_tactic()
    return {
        "tactics": [
            {
                "id": t["id"],
                "name": t["name"],
                "techniques": coverage.get(t["id"], {}).get("techniques", []),
            }
            for t in TACTIC_ORDER
        ],
        "totals": {
            "techniques_known": len(ALL_TECHNIQUES),
            "techniques_covered": len(
                {tech.id for techs in RULE_MITRE_MAP.values() for tech in techs}
            ),
            "rules_mapped": len(RULE_MITRE_MAP),
        },
    }


@router.get("/navigator", dependencies=[Depends(RoleChecker(["admin", "analyst", "viewer"]))])
def mitre_navigator() -> dict[str, object]:
    """Couche compatible MITRE ATT&CK Navigator (v4.5)."""
    return navigator_layer()
