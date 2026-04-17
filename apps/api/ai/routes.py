"""Routes FastAPI : triage LLM, RAG, generation Sigma/Yara, cost tracking."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.ai.llm_client import (
    MODEL_PRICING,
    call,
    get_daily_cost,
    llm_status,
    parse_json_response,
)
from apps.api.ai.rag import collect_corpus, rag_search, rag_summary
from apps.api.ai.rule_generator import (
    RuleSeed,
    build_sigma_rule,
    build_yara_rule,
    enrich_seed_with_llm,
    render_sigma_yaml,
)
from apps.api.ai.triage import (
    TriageInput,
    triage_event,
    triage_incident,
    triage_input_async,
)
from apps.api.db.session import get_db

router = APIRouter(prefix="/ai", tags=["AI Native"])


# ── LLM ──────────────────────────────────────────────────────────────


@router.get("/status")
def get_status() -> dict[str, Any]:
    return llm_status()


class LlmCallRequest(BaseModel):
    prompt: str
    system: str | None = None
    max_tokens: int = Field(1024, ge=1, le=4096)
    prefer: str | None = Field(None, description="anthropic | openai | stub")


@router.post("/llm/call")
async def call_raw_llm(req: LlmCallRequest) -> dict[str, Any]:
    resp = await call(
        req.prompt,
        system=req.system,
        max_tokens=req.max_tokens,
        prefer=req.prefer,
        operation="raw",
    )
    return {
        "text": resp.text,
        "model": resp.model,
        "provider": resp.provider,
        "usage": resp.usage,
        "latency_ms": resp.latency_ms,
        "cost_usd": resp.cost_usd,
    }


# ── Triage ───────────────────────────────────────────────────────────


class TriageInlineRequest(BaseModel):
    title: str
    severity: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    event_type: str | None = None
    message: str | None = None
    extra: dict | None = None
    prefer: str | None = None


@router.post("/triage/inline")
async def triage_inline(req: TriageInlineRequest) -> dict[str, Any]:
    t = TriageInput(
        kind="inline",
        title=req.title,
        severity=req.severity,
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        username=req.username,
        event_type=req.event_type,
        message=req.message,
        extra=req.extra,
    )
    return await triage_input_async(t, prefer=req.prefer)


@router.post("/triage/event/{event_id}")
async def triage_event_route(event_id: str, prefer: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        return await triage_event(db, event_id, prefer=prefer)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/triage/incident/{incident_id}")
async def triage_incident_route(incident_id: str, prefer: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        return await triage_incident(db, incident_id, prefer=prefer)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ── RAG ──────────────────────────────────────────────────────────────


class RagSearchRequest(BaseModel):
    query: str
    top_k: int = Field(10, ge=1, le=50)
    min_score: float = Field(0.05, ge=0.0, le=1.0)
    include_events: bool = True
    include_incidents: bool = True
    lookback_hours: int = Field(168, ge=1, le=8760)


@router.post("/rag/search")
def rag_search_route(req: RagSearchRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    docs = collect_corpus(
        db,
        include_events=req.include_events,
        include_incidents=req.include_incidents,
        lookback_hours=req.lookback_hours,
    )
    results = rag_search(req.query, docs, top_k=req.top_k, min_score=req.min_score)
    return {
        "query": req.query,
        "corpus": rag_summary(docs),
        "results_count": len(results),
        "results": results,
    }


@router.get("/rag/corpus")
def rag_corpus_summary(
    lookback_hours: int = 168,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    docs = collect_corpus(db, lookback_hours=lookback_hours)
    return rag_summary(docs)


# ── Rule generator ───────────────────────────────────────────────────


class RuleGenerateRequest(BaseModel):
    title: str
    severity: str | None = "medium"
    event_type: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    message: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    description: str | None = None
    enrich_with_llm: bool = False
    formats: list[str] = Field(default_factory=lambda: ["sigma", "yara"])
    prefer: str | None = None


@router.post("/rules/generate")
def rules_generate(req: RuleGenerateRequest) -> dict[str, Any]:
    seed = RuleSeed(
        title=req.title,
        severity=req.severity,
        event_type=req.event_type,
        src_ip=req.src_ip,
        dst_ip=req.dst_ip,
        username=req.username,
        message=req.message,
        mitre_techniques=req.mitre_techniques,
        description=req.description,
    )
    enrichment_meta: dict[str, Any] | None = None
    if req.enrich_with_llm:
        seed, enrichment_meta = enrich_seed_with_llm(seed, prefer=req.prefer)

    out: dict[str, Any] = {
        "seed": {
            "title": seed.title,
            "severity": seed.severity,
            "event_type": seed.event_type,
            "mitre_techniques": seed.mitre_techniques,
            "description": seed.description,
        },
        "rules": {},
    }
    if "sigma" in req.formats:
        sigma_rule = build_sigma_rule(seed)
        out["rules"]["sigma"] = {"rule": sigma_rule, "yaml": render_sigma_yaml(sigma_rule)}
    if "yara" in req.formats:
        out["rules"]["yara"] = {"text": build_yara_rule(seed)}

    if enrichment_meta:
        out["llm_enrichment"] = enrichment_meta
    return out


@router.post("/rules/from-event/{event_id}")
def rules_from_event(
    event_id: str,
    enrich_with_llm: bool = False,
    formats: list[str] | None = None,
    prefer: str | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from apps.api.models.event import Event
    ev = db.query(Event).filter(Event.id == event_id).first()
    if ev is None:
        raise HTTPException(status_code=404, detail=f"event not found: {event_id}")
    body = RuleGenerateRequest(
        title=f"Detection: {ev.event_type or 'event'} from {ev.src_ip or 'unknown'}",
        severity=ev.severity,
        event_type=ev.event_type,
        src_ip=ev.src_ip,
        dst_ip=ev.dst_ip,
        username=ev.username,
        message=ev.message,
        enrich_with_llm=enrich_with_llm,
        formats=formats or ["sigma", "yara"],
        prefer=prefer,
    )
    return rules_generate(body)


# ── Cost tracking ────────────────────────────────────────────────────


@router.get("/cost")
def ai_cost() -> dict[str, Any]:
    """Couts LLM : aujourd'hui + 7 derniers jours + pricing de reference."""
    today = datetime.now(timezone.utc)
    days: list[dict[str, Any]] = []
    total_7d = 0.0
    for i in range(7):
        day = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        agg = get_daily_cost(day) or {"day": day, "total_usd": 0.0}
        days.append(agg)
        total_7d += float(agg.get("total_usd", 0.0) or 0.0)
    return {
        "today": days[0] if days else {},
        "last_7_days": days,
        "total_usd_7d": round(total_7d, 6),
        "pricing_usd_per_1m_tokens": {
            k: {"input": v[0], "output": v[1]} for k, v in MODEL_PRICING.items()
        },
    }
