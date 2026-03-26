"""API Chatbot SOC — requetes en langage naturel sur les donnees de securite via Ollama."""

from __future__ import annotations

import logging
import re
import uuid
from collections import defaultdict

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.db.session import get_db
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.threat_score import ThreatScore
from apps.api.security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_key)])

# In-memory conversation store
_conversations: dict[str, list[dict[str, str]]] = defaultdict(list)

SYSTEM_PROMPT = """You are a SOC (Security Operations Center) analyst assistant for a Cyber Defense Dashboard.

You have access to the following database schema:
- events: id, ts, source, event_type, severity (low/medium/high/critical), src_ip, dst_ip, username, message
- incidents: id, created_at, status (open/ack/closed), severity, title, description, rule_id, entity_key
- threat_scores: ip, score (0-100), factors_json

Available rules: bruteforce.v1, bruteforce-username.v1, auth-targeted.v1, portscan.v1, anomaly.volume.v1, anomaly.ip.v1, ml.isolation_forest.v1

You analyze the security context provided and give actionable insights.
Be concise and professional. Use bullet points for lists.
Respond in the same language the user uses."""

# Simple IP regex for context extraction
_IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")


class ChatRequest(BaseModel):
    """Requete de chat envoyee par l'utilisateur."""

    message: str
    conversation_id: str | None = None


class ChatResponse(BaseModel):
    """Reponse du chatbot SOC."""

    conversation_id: str
    response: str
    context_used: list[str]


def _build_context(db: Session, message: str) -> tuple[str, list[str]]:
    """Construire un contexte dynamique depuis la base de donnees selon le message utilisateur."""
    parts: list[str] = []
    labels: list[str] = []

    # Always include summary stats
    event_count = db.query(func.count(Event.id)).scalar() or 0
    incident_count = db.query(func.count(Incident.id)).scalar() or 0
    open_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.status == "open")
        .scalar()
        or 0
    )
    parts.append(
        f"DB Summary: {event_count} events total, "
        f"{incident_count} incidents ({open_incidents} open)."
    )
    labels.append("summary_stats")

    # Recent incidents (always useful)
    recent = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .limit(10)
        .all()
    )
    if recent:
        lines = [
            f"- [{i.severity}] {i.title} (status={i.status}, rule={i.rule_id})"
            for i in recent
        ]
        parts.append("Recent incidents:\n" + "\n".join(lines))
        labels.append("recent_incidents")

    # If message mentions an IP, fetch related info
    ips_mentioned = _IP_RE.findall(message)
    for ip in ips_mentioned[:3]:
        ip_events = (
            db.query(Event.event_type, func.count(Event.id))
            .filter(Event.src_ip == ip)
            .group_by(Event.event_type)
            .all()
        )
        if ip_events:
            breakdown = ", ".join(f"{et}: {c}" for et, c in ip_events)
            parts.append(f"Events from {ip}: {breakdown}")
            labels.append(f"ip_detail:{ip}")

        score_row = db.get(ThreatScore, ip)
        if score_row:
            parts.append(f"Threat score for {ip}: {score_row.score}/100")
            labels.append(f"threat_score:{ip}")

    # If message mentions severity keywords, add severity breakdown
    msg_lower = message.lower()
    if any(kw in msg_lower for kw in ["sever", "critical", "high", "urgent"]):
        sev_counts = (
            db.query(Incident.severity, func.count(Incident.id))
            .filter(Incident.status == "open")
            .group_by(Incident.severity)
            .all()
        )
        if sev_counts:
            breakdown = ", ".join(f"{s}: {c}" for s, c in sev_counts)
            parts.append(f"Open incidents by severity: {breakdown}")
            labels.append("severity_breakdown")

    # Top threat IPs
    if any(kw in msg_lower for kw in ["threat", "ip", "danger", "risk", "score"]):
        top_ips = (
            db.query(ThreatScore)
            .order_by(ThreatScore.score.desc())
            .limit(5)
            .all()
        )
        if top_ips:
            lines = [f"- {t.ip}: score {t.score}" for t in top_ips]
            parts.append("Top threat IPs:\n" + "\n".join(lines))
            labels.append("top_threats")

    return "\n\n".join(parts), labels


@router.post("", response_model=ChatResponse)
def chat(payload: ChatRequest, db: Session = Depends(get_db)) -> dict:
    """Discuter avec l'assistant SOC via Ollama (LLM local)."""
    settings = get_settings()

    conv_id = payload.conversation_id or str(uuid.uuid4())

    # Build dynamic context
    context_str, context_labels = _build_context(db, payload.message)

    # Manage conversation history
    history = _conversations[conv_id]
    history.append({"role": "user", "content": payload.message})

    # Build messages for Ollama (system + history)
    ollama_messages = [
        {"role": "system", "content": SYSTEM_PROMPT + "\n\n" + context_str},
        *history[-20:],
    ]

    try:
        resp = httpx.post(
            f"{settings.OLLAMA_BASE_URL}/api/chat",
            json={
                "model": settings.OLLAMA_MODEL,
                "messages": ollama_messages,
                "stream": False,
            },
            timeout=120.0,
        )
        resp.raise_for_status()
        data = resp.json()
        assistant_text = data.get("message", {}).get("content", "")
        if not assistant_text:
            raise ValueError("Empty response from Ollama")
    except httpx.ConnectError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Ollama is not running. Start it with: ollama serve",
        )
    except httpx.HTTPStatusError as e:
        logger.exception("Ollama HTTP error")
        detail = f"Ollama error {e.response.status_code}"
        try:
            detail = e.response.json().get("error", detail)
        except Exception:
            pass
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=detail,
        )
    except Exception as e:
        logger.exception("Ollama request failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"LLM service error: {e}",
        )

    history.append({"role": "assistant", "content": assistant_text})

    # Cap history
    if len(history) > 40:
        _conversations[conv_id] = history[-20:]

    return {
        "conversation_id": conv_id,
        "response": assistant_text,
        "context_used": context_labels,
    }
