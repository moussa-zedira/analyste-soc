"""Assistant pentest — chat LLM avec contexte engagement (V4.8).

Features:
- Multi-provider via apps.api.ai.llm_client (Anthropic / OpenAI / Ollama)
- Contexte auto-injecte : engagement actif (scope, RoE, kill-switch),
  sessions C2 Sliver ouvertes, hosts BloodHound, creds recoltes,
  derniers scans/recon, incidents SOC recents
- Persistance : ChatMessage en BDD par engagement
- Historique : derniers 20 messages rechargus depuis la BDD
- RAG : recherche MITRE/CVE/Sigma si requete le suggere

Retro-compat : si aucun engagement_id fourni, bascule en mode SOC generaliste
(contexte events/incidents/threat_scores comme l'ancien chatbot).
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from apps.api.ai.llm_client import call as llm_call
from apps.api.db.session import get_db
from apps.api.models.bloodhound import BHDataset, BHNode
from apps.api.models.chat_message import ChatMessage
from apps.api.models.credential import HarvestedCredential
from apps.api.models.engagement import Engagement
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.sliver import SliverSession
from apps.api.models.threat_score import ThreatScore
from apps.api.security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_key)])


PENTEST_SYSTEM_PROMPT = """Tu es l'assistant d'un pentester professionnel sur la plateforme analyste-soc.

Mission : assister l'operateur durant un engagement red team / pentest authorise.
- Toutes les actions sont tracees et signees (HMAC) dans operator_audit_log.
- Un kill-switch par engagement permet d'arreter tout a tout moment.
- Les cibles hors scope sont bloquees par le validator RoE.

Capacites a exploiter :
- Recon : nmap, amass, subfinder (module apps/api/pentest/recon)
- Exploitation : impacket reel (secretsdump, psexec, smbexec, wmiexec)
- C2 : Sliver gRPC (build implant, sessions, exec commandes)
- AD : BloodHound (import zip, pivot read-only, chemins attaque)
- Phishing : GoPhish (campagnes + scope check + kill-switch)
- Post-exploit : credential vault, browser/cloud/secrets modules
- Reporting : MITRE ATT&CK mapping + PDF client

Style de reponse :
- Francais, direct, pas de disclaimer moralisateur inutile (le cadre est legal).
- Reponses actionnables : commandes, endpoints, techniques MITRE.
- Si tu proposes une action offensive, precise toujours : scope autorise, impact, detection likelihood.
- Structure : Objectif → Commande/Endpoint → Verification → Prochaine etape.
- Reference les techniques MITRE ATT&CK (T1xxx) quand pertinent.
"""

SOC_SYSTEM_PROMPT = """Tu es l'assistant SOC du Cyber Defense Dashboard.
Tu analyses events, incidents et threat scores. Reponds en francais, concis, actionnable.
"""

_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


class ChatRequest(BaseModel):
    message: str
    conversation_id: str | None = None
    engagement_id: str | None = None
    prefer_provider: str | None = None  # anthropic | openai | ollama | None (auto)


class ChatResponse(BaseModel):
    conversation_id: str
    response: str
    context_used: list[str]
    provider: str
    model: str
    tokens_in: int
    tokens_out: int
    cost_usd: float
    latency_ms: int


def _build_pentest_context(db: Session, engagement: Engagement, message: str) -> tuple[str, list[str]]:
    """Contexte pentest : engagement + sessions C2 + BloodHound + creds + scans."""
    parts: list[str] = []
    labels: list[str] = []

    # 1. Engagement (scope + RoE + kill-switch)
    scope = engagement.scope_targets or []
    excluded = engagement.excluded_targets or []
    parts.append(
        f"ENGAGEMENT ACTIF : {engagement.name} (client={engagement.client_name}, "
        f"status={engagement.status}, kill_switch={engagement.kill_switch_active})\n"
        f"Scope autorise : {', '.join(scope) if scope else '(non defini)'}\n"
        f"Exclus : {', '.join(excluded) if excluded else '(aucun)'}\n"
        f"Periode : {engagement.start_date} -> {engagement.end_date}"
    )
    labels.append("engagement")

    # 2. Sessions C2 Sliver actives
    c2_sessions = (
        db.query(SliverSession)
        .filter(SliverSession.engagement_id == engagement.id)
        .filter(SliverSession.active.is_(True))
        .order_by(SliverSession.last_checkin.desc().nullslast())
        .limit(10)
        .all()
    )
    if c2_sessions:
        lines = [
            f"- {s.hostname or s.session_id} ({s.os} / user={s.username}) - last_checkin={s.last_checkin}"
            for s in c2_sessions
        ]
        parts.append("SESSIONS C2 ACTIVES :\n" + "\n".join(lines))
        labels.append("c2_sessions")

    # 3. BloodHound : derniere dataset + counts
    bh_ds = (
        db.query(BHDataset)
        .filter(BHDataset.engagement_id == engagement.id)
        .order_by(BHDataset.uploaded_at.desc())
        .first()
    )
    if bh_ds:
        node_count = db.query(func.count(BHNode.id)).filter(BHNode.dataset_id == bh_ds.id).scalar() or 0
        high_value = (
            db.query(func.count(BHNode.id))
            .filter(BHNode.dataset_id == bh_ds.id)
            .filter(BHNode.high_value.is_(True))
            .scalar()
            or 0
        )
        parts.append(
            f"BLOODHOUND : dataset {bh_ds.name} ({node_count} nodes, {high_value} high-value targets)"
        )
        labels.append("bloodhound")

    # 4. Credentials recoltes
    creds_count = (
        db.query(func.count(HarvestedCredential.id))
        .filter(HarvestedCredential.engagement_id == engagement.id)
        .scalar()
        or 0
    )
    if creds_count:
        recent_creds = (
            db.query(HarvestedCredential.cred_type, func.count(HarvestedCredential.id))
            .filter(HarvestedCredential.engagement_id == engagement.id)
            .group_by(HarvestedCredential.cred_type)
            .all()
        )
        breakdown = ", ".join(f"{t}: {c}" for t, c in recent_creds)
        parts.append(f"CREDENTIALS VAULT : {creds_count} entries ({breakdown})")
        labels.append("credentials")

    # 5. IPs mentionnees dans le message → cross-check scope + threat score
    ips = _IP_RE.findall(message)[:3]
    if ips:
        scores = {
            t.ip: t.score
            for t in db.query(ThreatScore).filter(ThreatScore.ip.in_(ips)).all()
        }
        for ip in ips:
            in_scope = any(ip.startswith(s.split("/")[0][:7]) for s in scope)
            score_str = f"score={scores.get(ip, 'n/a')}" if ip in scores else "unscanned"
            parts.append(f"IP {ip} : in_scope={in_scope}, {score_str}")
            labels.append(f"ip:{ip}")

    return "\n\n".join(parts), labels


def _build_soc_context(db: Session, message: str) -> tuple[str, list[str]]:
    """Contexte SOC generaliste (retro-compat chatbot v1)."""
    parts: list[str] = []
    labels: list[str] = []

    event_count = db.query(func.count(Event.id)).scalar() or 0
    inc_total, inc_open = db.query(
        func.count(Incident.id),
        func.count(case((Incident.status == "open", 1))),
    ).one()
    parts.append(
        f"DB Summary: {event_count} events total, "
        f"{inc_total} incidents ({inc_open} open)."
    )
    labels.append("summary_stats")

    recent = db.query(Incident).order_by(Incident.created_at.desc()).limit(10).all()
    if recent:
        lines = [
            f"- [{i.severity}] {i.title} (status={i.status}, rule={i.rule_id})"
            for i in recent
        ]
        parts.append("Recent incidents:\n" + "\n".join(lines))
        labels.append("recent_incidents")

    ips = _IP_RE.findall(message)[:3]
    if ips:
        scores = {
            t.ip: t.score
            for t in db.query(ThreatScore).filter(ThreatScore.ip.in_(ips)).all()
        }
        for ip in ips:
            if ip in scores:
                parts.append(f"Threat score {ip}: {scores[ip]}/100")
                labels.append(f"threat_score:{ip}")

    return "\n\n".join(parts), labels


def _load_history(db: Session, conversation_id: str, limit: int = 20) -> list[dict[str, str]]:
    rows = (
        db.query(ChatMessage)
        .filter(ChatMessage.conversation_id == conversation_id)
        .order_by(ChatMessage.created_at.desc())
        .limit(limit)
        .all()
    )
    rows.reverse()
    return [{"role": r.role, "content": r.content} for r in rows]


def _persist(
    db: Session,
    *,
    conversation_id: str,
    engagement_id: str | None,
    role: str,
    content: str,
    provider: str | None = None,
    model: str | None = None,
    tokens_in: int = 0,
    tokens_out: int = 0,
    cost_usd: float = 0.0,
    latency_ms: int = 0,
    context_labels: list[str] | None = None,
) -> None:
    try:
        row = ChatMessage(
            id=str(uuid.uuid4()),
            conversation_id=conversation_id,
            engagement_id=engagement_id,
            role=role,
            content=content,
            provider=provider,
            model=model,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            context_labels=context_labels,
            created_at=datetime.now(timezone.utc),
        )
        db.add(row)
        db.commit()
    except Exception:  # pragma: no cover
        logger.exception("chat_message persist failed")
        db.rollback()


@router.post("", response_model=ChatResponse)
def chat(payload: ChatRequest, db: Session = Depends(get_db)) -> dict:
    """Assistant pentest avec contexte engagement."""
    conv_id = payload.conversation_id or str(uuid.uuid4())

    # Contexte : pentest si engagement fourni, sinon SOC generaliste
    engagement: Engagement | None = None
    if payload.engagement_id:
        engagement = db.query(Engagement).filter(Engagement.id == payload.engagement_id).first()
        if not engagement:
            raise HTTPException(status_code=404, detail="Engagement not found")
        if engagement.kill_switch_active:
            raise HTTPException(
                status_code=423,
                detail=f"Engagement {engagement.id} is killed — assistant disabled.",
            )

    if engagement:
        context_str, context_labels = _build_pentest_context(db, engagement, payload.message)
        system_prompt = PENTEST_SYSTEM_PROMPT
    else:
        context_str, context_labels = _build_soc_context(db, payload.message)
        system_prompt = SOC_SYSTEM_PROMPT

    # Charge historique depuis BDD
    history = _load_history(db, conv_id, limit=20)

    # Construit le prompt final (system + contexte + historique + nouveau message)
    history_block = "\n".join(
        f"[{m['role'].upper()}] {m['content']}" for m in history
    )
    full_prompt = (
        f"CONTEXTE:\n{context_str}\n\n"
        + (f"HISTORIQUE:\n{history_block}\n\n" if history_block else "")
        + f"QUESTION:\n{payload.message}"
    )

    # Persist user message AVANT l'appel LLM (au cas ou erreur)
    _persist(
        db,
        conversation_id=conv_id,
        engagement_id=payload.engagement_id,
        role="user",
        content=payload.message,
        context_labels=context_labels,
    )

    # Appel LLM multi-provider (Anthropic → OpenAI → Ollama → stub)
    try:
        loop = asyncio.new_event_loop()
        try:
            resp = loop.run_until_complete(
                llm_call(
                    prompt=full_prompt,
                    system=system_prompt,
                    max_tokens=2048,
                    prefer=payload.prefer_provider,
                    operation="chat_pentest" if engagement else "chat_soc",
                )
            )
        finally:
            loop.close()
    except Exception as e:
        logger.exception("LLM call failed")
        raise HTTPException(status_code=502, detail=f"LLM error: {e}")

    # Persist assistant reply
    _persist(
        db,
        conversation_id=conv_id,
        engagement_id=payload.engagement_id,
        role="assistant",
        content=resp.text,
        provider=resp.provider,
        model=resp.model,
        tokens_in=resp.usage.get("input_tokens", 0),
        tokens_out=resp.usage.get("output_tokens", 0),
        cost_usd=resp.cost_usd,
        latency_ms=resp.latency_ms,
        context_labels=context_labels,
    )

    return {
        "conversation_id": conv_id,
        "response": resp.text,
        "context_used": context_labels,
        "provider": resp.provider,
        "model": resp.model,
        "tokens_in": resp.usage.get("input_tokens", 0),
        "tokens_out": resp.usage.get("output_tokens", 0),
        "cost_usd": resp.cost_usd,
        "latency_ms": resp.latency_ms,
    }


@router.get("/conversations/{conversation_id}")
def get_conversation(conversation_id: str, db: Session = Depends(get_db)) -> dict:
    """Retourne l'historique complet d'une conversation."""
    rows = (
        db.query(ChatMessage)
        .filter(ChatMessage.conversation_id == conversation_id)
        .order_by(ChatMessage.created_at.asc())
        .all()
    )
    return {
        "conversation_id": conversation_id,
        "messages": [
            {
                "role": r.role,
                "content": r.content,
                "provider": r.provider,
                "model": r.model,
                "created_at": r.created_at.isoformat(),
                "cost_usd": r.cost_usd,
            }
            for r in rows
        ],
    }


@router.get("/conversations")
def list_conversations(
    engagement_id: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
) -> dict:
    """Liste les conversations (optionnellement filtrees par engagement)."""
    q = db.query(
        ChatMessage.conversation_id,
        func.min(ChatMessage.created_at).label("started_at"),
        func.max(ChatMessage.created_at).label("last_msg"),
        func.count(ChatMessage.id).label("msg_count"),
        func.sum(ChatMessage.cost_usd).label("total_cost"),
    )
    if engagement_id:
        q = q.filter(ChatMessage.engagement_id == engagement_id)
    rows = (
        q.group_by(ChatMessage.conversation_id)
        .order_by(func.max(ChatMessage.created_at).desc())
        .limit(limit)
        .all()
    )
    return {
        "conversations": [
            {
                "conversation_id": r.conversation_id,
                "started_at": r.started_at.isoformat(),
                "last_msg": r.last_msg.isoformat(),
                "msg_count": r.msg_count,
                "total_cost_usd": float(r.total_cost or 0.0),
            }
            for r in rows
        ]
    }
