"""LLM triage agent : analyse incidents/events et propose verdict + actions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from apps.api.ai.llm_client import LlmResponse, call_llm, parse_json_response
from apps.api.models.event import Event
from apps.api.models.incident import Incident

TRIAGE_SYSTEM = """You are a senior SOC analyst (Tier 3). You receive a security incident
or event with all available context and you must produce a structured triage in JSON.

The output MUST be a single JSON object with these exact fields:
- verdict: one of "true_positive", "false_positive", "needs_review"
- confidence: float 0..1
- severity: one of "critical", "high", "medium", "low", "info"
- summary: 2-3 sentence summary of what happened and why it matters
- recommended_actions: list of 3-5 concrete next steps (containment, investigation, eradication)
- mitre_techniques: list of MITRE ATT&CK technique IDs (e.g. ["T1078", "T1110.003"])
- iocs: list of indicators of compromise extracted (IPs, hashes, domains, usernames)
- root_cause_hypothesis: one short sentence
- tags: list of short labels (e.g. ["lateral-movement", "credential-access"])

Be precise, terse, and actionable. No preamble — output ONLY the JSON object.
"""


@dataclass
class TriageInput:
    kind: str  # "event" or "incident"
    title: str
    severity: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    event_type: str | None = None
    message: str | None = None
    related_events_count: int = 0
    related_events_sample: list[dict] | None = None
    extra: dict | None = None


def _build_prompt(t: TriageInput) -> str:
    parts = [
        f"# Incident Triage Request",
        f"",
        f"## Subject",
        f"- Kind: {t.kind}",
        f"- Title: {t.title}",
        f"- Reported severity: {t.severity or 'unknown'}",
        f"",
        f"## Network context",
        f"- src_ip: {t.src_ip or 'n/a'}",
        f"- dst_ip: {t.dst_ip or 'n/a'}",
        f"- username: {t.username or 'n/a'}",
        f"- event_type: {t.event_type or 'n/a'}",
        f"",
        f"## Message",
        f"{t.message or '(no message)'}",
    ]
    if t.related_events_count:
        parts += [
            "",
            f"## Related events ({t.related_events_count} total)",
        ]
        for e in (t.related_events_sample or [])[:5]:
            parts.append(f"- [{e.get('ts')}] {e.get('event_type')} src={e.get('src_ip')} {e.get('message','')[:120]}")
    if t.extra:
        parts += ["", "## Extra context", json.dumps(t.extra, indent=2, default=str)]
    parts += ["", "Produce the triage JSON now."]
    return "\n".join(parts)


def _to_input_from_incident(i: Incident, related: list[Event]) -> TriageInput:
    ev_first = related[0] if related else None
    return TriageInput(
        kind="incident",
        title=i.title or i.id,
        severity=i.severity,
        src_ip=ev_first.src_ip if ev_first else None,
        dst_ip=ev_first.dst_ip if ev_first else None,
        username=ev_first.username if ev_first else None,
        event_type=ev_first.event_type if ev_first else None,
        message=i.description or (ev_first.message if ev_first else None),
        related_events_count=len(related),
        related_events_sample=[
            {
                "ts": e.ts.isoformat() if e.ts else None,
                "event_type": e.event_type,
                "src_ip": e.src_ip,
                "message": e.message,
            }
            for e in related[:10]
        ],
    )


def _to_input_from_event(e: Event) -> TriageInput:
    return TriageInput(
        kind="event",
        title=f"{e.event_type or 'event'} [{e.id}]",
        severity=e.severity,
        src_ip=e.src_ip,
        dst_ip=e.dst_ip,
        username=e.username,
        event_type=e.event_type,
        message=e.message,
    )


def triage_input(t: TriageInput, prefer: str | None = None) -> dict[str, Any]:
    """Lance le triage et retourne un dict structuré + métadonnées LLM."""
    prompt = _build_prompt(t)
    resp: LlmResponse = call_llm(prompt, system=TRIAGE_SYSTEM, max_tokens=1024, prefer=prefer)
    parsed = parse_json_response(resp.text)

    if parsed is None:
        parsed = {
            "verdict": "needs_review",
            "confidence": 0.0,
            "severity": t.severity or "medium",
            "summary": "LLM did not return valid JSON. Raw text included.",
            "recommended_actions": ["Re-run with a different model", "Inspect raw output"],
            "mitre_techniques": [],
            "iocs": [],
            "root_cause_hypothesis": "unknown",
            "tags": ["llm-parse-error"],
        }

    # Garde-fous : champs requis avec défauts safe
    defaults = {
        "verdict": "needs_review",
        "confidence": 0.5,
        "severity": "medium",
        "summary": "",
        "recommended_actions": [],
        "mitre_techniques": [],
        "iocs": [],
        "root_cause_hypothesis": "",
        "tags": [],
    }
    for k, v in defaults.items():
        parsed.setdefault(k, v)

    return {
        "triage": parsed,
        "llm": {
            "provider": resp.provider,
            "model": resp.model,
            "usage": resp.usage,
        },
        "raw_text": resp.text,
    }


def triage_incident(db: Session, incident_id: str, prefer: str | None = None) -> dict[str, Any]:
    inc = db.query(Incident).filter(Incident.id == incident_id).first()
    if inc is None:
        raise ValueError(f"incident not found: {incident_id}")
    related = list(inc.events) if hasattr(inc, "events") else []
    return triage_input(_to_input_from_incident(inc, related), prefer=prefer)


def triage_event(db: Session, event_id: str, prefer: str | None = None) -> dict[str, Any]:
    ev = db.query(Event).filter(Event.id == event_id).first()
    if ev is None:
        raise ValueError(f"event not found: {event_id}")
    return triage_input(_to_input_from_event(ev), prefer=prefer)
