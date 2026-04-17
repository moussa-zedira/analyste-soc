"""RAG sur les logs historiques : TF-IDF + cosine similarity (sklearn).

Pas de dépendance externe lourde (pas de FAISS, pas de sentence-transformers).
On indexe les events / incidents en mémoire à la demande, ce qui suffit
largement pour des corpus < 100k documents (latence < 100ms typique).

Pour un index persistant, l'index est rebuild à chaque appel `rag_search` —
ok pour du SOC où le corpus tourne sur quelques heures de logs récents.
Si besoin d'un cache, il suffira d'ajouter un singleton avec invalidation TTL.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sqlalchemy import desc
from sqlalchemy.orm import Session

from apps.api.models.event import Event
from apps.api.models.incident import Incident


@dataclass
class RagDoc:
    id: str
    kind: str  # "event" or "incident"
    text: str
    metadata: dict[str, Any]


def _event_to_doc(e: Event) -> RagDoc:
    text_parts = [
        e.event_type or "",
        e.severity or "",
        e.src_ip or "",
        e.dst_ip or "",
        e.username or "",
        e.message or "",
        e.ti_tags or "",
    ]
    return RagDoc(
        id=e.id,
        kind="event",
        text=" ".join(p for p in text_parts if p),
        metadata={
            "ts": e.ts.isoformat() if e.ts else None,
            "source": e.source,
            "event_type": e.event_type,
            "severity": e.severity,
            "src_ip": e.src_ip,
            "username": e.username,
        },
    )


def _incident_to_doc(i: Incident) -> RagDoc:
    text_parts = [
        i.title or "",
        i.description or "",
        i.severity or "",
        i.status or "",
    ]
    return RagDoc(
        id=i.id,
        kind="incident",
        text=" ".join(p for p in text_parts if p),
        metadata={
            "title": i.title,
            "severity": i.severity,
            "status": i.status,
            "created_at": i.created_at.isoformat() if getattr(i, "created_at", None) else None,
        },
    )


def collect_corpus(
    db: Session,
    include_events: bool = True,
    include_incidents: bool = True,
    lookback_hours: int = 168,
    limit: int = 5000,
) -> list[RagDoc]:
    """Récupère un corpus de docs pour indexation."""
    docs: list[RagDoc] = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    if include_events:
        rows = (
            db.query(Event)
            .filter(Event.ts >= cutoff)
            .order_by(desc(Event.ts))
            .limit(limit)
            .all()
        )
        docs.extend(_event_to_doc(e) for e in rows)

    if include_incidents:
        # Incidents : on ignore le filtre temps car le corpus est petit
        rows_i = db.query(Incident).limit(min(limit, 500)).all()
        docs.extend(_incident_to_doc(i) for i in rows_i)

    return [d for d in docs if d.text.strip()]


def rag_search(
    query: str,
    docs: list[RagDoc],
    top_k: int = 10,
    min_score: float = 0.05,
) -> list[dict[str, Any]]:
    """Indexe le corpus + retourne les top_k docs les plus similaires."""
    if not docs:
        return []
    if not query.strip():
        return []

    corpus_texts = [d.text for d in docs] + [query]
    vec = TfidfVectorizer(
        max_features=10000,
        ngram_range=(1, 2),
        sublinear_tf=True,
        analyzer="word",
        token_pattern=r"\b[A-Za-z0-9_./:\-]+\b",
        lowercase=True,
    )
    matrix = vec.fit_transform(corpus_texts)
    query_vec = matrix[-1]
    doc_matrix = matrix[:-1]
    sims = cosine_similarity(query_vec, doc_matrix).flatten()

    idx_sorted = np.argsort(sims)[::-1]
    out: list[dict[str, Any]] = []
    for idx in idx_sorted[:top_k]:
        score = float(sims[idx])
        if score < min_score:
            break
        d = docs[idx]
        out.append({
            "id": d.id,
            "kind": d.kind,
            "score": round(score, 4),
            "text_preview": d.text[:200] + ("..." if len(d.text) > 200 else ""),
            "metadata": d.metadata,
        })
    return out


def rag_summary(docs: list[RagDoc]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    for d in docs:
        by_kind[d.kind] = by_kind.get(d.kind, 0) + 1
    return {
        "corpus_size": len(docs),
        "by_kind": by_kind,
        "approx_token_count": sum(len(d.text.split()) for d in docs),
    }
