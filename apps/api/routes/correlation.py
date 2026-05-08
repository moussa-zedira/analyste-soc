"""API Correlation — endpoints pour le moteur de correlation multi-evenements."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.detection.correlation import (
    CorrelationMatch,
    CorrelationRule,
    CorrelationType,
    EventPattern,
    get_correlation_engine,
)
from apps.api.detection.state_machine import (
    get_state_machine_engine,
)
from apps.api.models.event import Event
from apps.api.security import require_api_key

router = APIRouter(
    prefix="/correlation",
    tags=["correlation"],
    dependencies=[Depends(require_api_key)],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class EventPatternSchema(BaseModel):
    event_type: str | None = None
    severity: str | None = None
    field_conditions: dict[str, Any] = Field(default_factory=dict)
    regex_conditions: dict[str, str] = Field(default_factory=dict)
    negate: bool = False
    label: str = ""


class CorrelationRuleCreate(BaseModel):
    name: str
    description: str = ""
    correlation_type: str = "temporal"
    event_patterns: list[EventPatternSchema]
    time_window: int = 300
    group_by: list[str] = Field(default_factory=lambda: ["src_ip"])
    threshold: int = 1
    severity: str = "high"
    mitre_tactics: list[str] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=lambda: ["create_incident"])
    tags: list[str] = Field(default_factory=list)
    baseline_window: int = 3600
    std_dev_threshold: float = 3.0
    ordered: bool = True
    max_gap: int | None = None


class CorrelationRuleRead(BaseModel):
    id: str
    name: str
    description: str
    correlation_type: str
    event_patterns: list[dict]
    time_window: int
    group_by: list[str]
    threshold: int
    severity: str
    mitre_tactics: list[str]
    actions: list[str]
    enabled: bool
    tags: list[str]


class CorrelationMatchRead(BaseModel):
    rule_id: str
    rule_name: str
    severity: str
    group_key: str
    group_values: dict[str, str]
    matched_event_count: int
    matched_at: str
    mitre_tactics: list[str]
    description: str
    score: float = 0.0


class ActiveStateRead(BaseModel):
    instance_id: str
    machine_id: str
    current_state: str
    group_key: str
    group_values: dict[str, str]
    entered_at: float
    last_transition: float
    matched_event_count: int
    history: list[dict]


class SimulateRequest(BaseModel):
    rule_id: str | None = None
    hours_back: int = 1


class SimulateResponse(BaseModel):
    events_analyzed: int
    matches: list[CorrelationMatchRead]
    duration_ms: float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule_to_read(rule: CorrelationRule) -> CorrelationRuleRead:
    patterns = []
    for p in rule.event_patterns:
        patterns.append({
            "event_type": p.event_type,
            "severity": p.severity,
            "field_conditions": p.field_conditions,
            "regex_conditions": p.regex_conditions,
            "negate": p.negate,
            "label": p.label,
        })
    return CorrelationRuleRead(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        correlation_type=rule.correlation_type.value,
        event_patterns=patterns,
        time_window=rule.time_window,
        group_by=rule.group_by,
        threshold=rule.threshold,
        severity=rule.severity,
        mitre_tactics=rule.mitre_tactics,
        actions=rule.actions,
        enabled=rule.enabled,
        tags=rule.tags,
    )


def _match_to_read(match: CorrelationMatch) -> CorrelationMatchRead:
    return CorrelationMatchRead(
        rule_id=match.rule_id,
        rule_name=match.rule_name,
        severity=match.severity,
        group_key=match.group_key,
        group_values=match.group_values,
        matched_event_count=len(match.matched_events),
        matched_at=match.matched_at.isoformat(),
        mitre_tactics=match.mitre_tactics,
        description=match.description,
        score=match.score,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/rules", response_model=list[CorrelationRuleRead])
def list_rules(
    enabled_only: bool = Query(True),
) -> list[CorrelationRuleRead]:
    """Liste toutes les regles de correlation."""
    engine = get_correlation_engine()
    rules = engine.get_rules(enabled_only=enabled_only)
    return [_rule_to_read(r) for r in rules]


@router.get("/rules/{rule_id}", response_model=CorrelationRuleRead)
def get_rule(rule_id: str) -> CorrelationRuleRead:
    """Recupere une regle de correlation par son ID."""
    engine = get_correlation_engine()
    rule = engine.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    return _rule_to_read(rule)


@router.post("/rules", response_model=CorrelationRuleRead, status_code=201)
def create_rule(body: CorrelationRuleCreate) -> CorrelationRuleRead:
    """Cree une nouvelle regle de correlation personnalisee."""
    engine = get_correlation_engine()

    try:
        corr_type = CorrelationType(body.correlation_type)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid correlation type: {body.correlation_type}. "
                   f"Valid: {[t.value for t in CorrelationType]}",
        )

    patterns = [
        EventPattern(
            event_type=p.event_type,
            severity=p.severity,
            field_conditions=p.field_conditions,
            regex_conditions=p.regex_conditions,
            negate=p.negate,
            label=p.label,
        )
        for p in body.event_patterns
    ]

    rule_id = f"custom-{uuid.uuid4().hex[:8]}"
    rule = CorrelationRule(
        id=rule_id,
        name=body.name,
        description=body.description,
        correlation_type=corr_type,
        event_patterns=patterns,
        time_window=body.time_window,
        group_by=body.group_by,
        threshold=body.threshold,
        severity=body.severity,
        mitre_tactics=body.mitre_tactics,
        actions=body.actions,
        tags=body.tags,
        baseline_window=body.baseline_window,
        std_dev_threshold=body.std_dev_threshold,
        ordered=body.ordered,
        max_gap=body.max_gap,
    )

    engine.register_rule(rule)
    return _rule_to_read(rule)


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: str) -> None:
    """Supprime une regle de correlation."""
    engine = get_correlation_engine()
    if not engine.unregister_rule(rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")


@router.put("/rules/{rule_id}/toggle")
def toggle_rule(rule_id: str) -> dict:
    """Active ou desactive une regle de correlation."""
    engine = get_correlation_engine()
    rule = engine.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = not rule.enabled
    return {"id": rule_id, "enabled": rule.enabled}


@router.get("/active", response_model=list[ActiveStateRead])
def get_active_states() -> list[ActiveStateRead]:
    """Affiche les etats de correlation actifs (machines a etats)."""
    sm_engine = get_state_machine_engine()
    states = sm_engine.get_active_states()
    return [
        ActiveStateRead(
            instance_id=s.instance_id,
            machine_id=s.machine_id,
            current_state=s.current_state,
            group_key=s.group_key,
            group_values=s.group_values,
            entered_at=s.entered_at,
            last_transition=s.last_transition,
            matched_event_count=len(s.matched_event_ids),
            history=s.history,
        )
        for s in states
    ]


@router.get("/matches", response_model=list[CorrelationMatchRead])
def get_recent_matches(
    hours_back: int = Query(1, ge=1, le=24),
    db: Session = Depends(get_db),
) -> list[CorrelationMatchRead]:
    """Retourne les correspondances de correlation recentes."""
    engine = get_correlation_engine()
    since = datetime.now(UTC) - timedelta(hours=hours_back)

    events = (
        db.query(Event)
        .filter(Event.ts >= since)
        .order_by(Event.ts.asc())
        .all()
    )

    matches = engine.evaluate(events, db)
    return [_match_to_read(m) for m in matches]


@router.post("/simulate", response_model=SimulateResponse)
def simulate_correlation(
    body: SimulateRequest,
    db: Session = Depends(get_db),
) -> SimulateResponse:
    """Teste les regles de correlation contre les donnees historiques."""
    import time

    engine = get_correlation_engine()
    since = datetime.now(UTC) - timedelta(hours=body.hours_back)

    events = (
        db.query(Event)
        .filter(Event.ts >= since)
        .order_by(Event.ts.asc())
        .all()
    )

    start = time.monotonic()

    if body.rule_id:
        rule = engine.get_rule(body.rule_id)
        if rule is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        matches = engine._evaluate_rule(rule, events)
    else:
        matches = engine.evaluate(events, db)

    duration = (time.monotonic() - start) * 1000

    return SimulateResponse(
        events_analyzed=len(events),
        matches=[_match_to_read(m) for m in matches],
        duration_ms=round(duration, 2),
    )


@router.get("/state-machines")
def list_state_machines() -> list[dict]:
    """Liste les machines a etats enregistrees."""
    sm_engine = get_state_machine_engine()
    machines = sm_engine.get_machines(enabled_only=False)
    return [
        {
            "id": m.id,
            "name": m.name,
            "description": m.description,
            "states": [s.name for s in m.states],
            "group_by": m.group_by,
            "severity": m.severity,
            "mitre_tactics": m.mitre_tactics,
            "enabled": m.enabled,
            "tags": m.tags,
        }
        for m in machines
    ]


@router.post("/state-machines/cleanup")
def cleanup_expired_states() -> dict:
    """Nettoie les etats expires des machines a etats."""
    sm_engine = get_state_machine_engine()
    removed = sm_engine.cleanup()
    return {"expired_states_removed": removed}


@router.get("/stats")
def correlation_stats(
    db: Session = Depends(get_db),
) -> dict:
    """Statistiques du moteur de correlation."""
    engine = get_correlation_engine()
    sm_engine = get_state_machine_engine()

    rules = engine.get_rules(enabled_only=False)
    active_rules = [r for r in rules if r.enabled]
    machines = sm_engine.get_machines(enabled_only=False)
    active_states = sm_engine.get_active_states()

    # Count by type
    type_counts: dict[str, int] = {}
    for r in rules:
        t = r.correlation_type.value
        type_counts[t] = type_counts.get(t, 0) + 1

    # Count by severity
    sev_counts: dict[str, int] = {}
    for r in rules:
        sev_counts[r.severity] = sev_counts.get(r.severity, 0) + 1

    return {
        "total_rules": len(rules),
        "active_rules": len(active_rules),
        "rules_by_type": type_counts,
        "rules_by_severity": sev_counts,
        "state_machines": len(machines),
        "active_states": len(active_states),
        "mitre_coverage": list({
            t for r in rules for t in r.mitre_tactics
        }),
    }
