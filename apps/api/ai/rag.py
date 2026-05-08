"""RAG FAISS + sentence-transformers + knowledge base MITRE ATT&CK / CVE / Sigma.

Remplace l'ancien RAG TF-IDF/sklearn. Architecture :
- Index FAISS persistent (`/data/rag/index.faiss`) avec embeddings sentence-transformers.
- Metadata stockees en JSONL (`/data/rag/docs.jsonl`) : une ligne par doc indexe.
- Manifest JSON (`/data/rag/manifest.json`) : versioning + stats par source.
- Embedder singleton (lazy) : SentenceTransformer("all-MiniLM-L6-v2") — 384 dims, 90MB.
- Sources : MITRE ATT&CK (STIX bundle), NVD CVE (feed JSON), Sigma rules (tarball GitHub),
  events/incidents de la DB (compat avec l'ancien flux).

Wrappers de compat : `RagDoc`, `rag_search`, `rag_summary`, `collect_corpus` restent
exposes pour les tests et les routes existants (TF-IDF fallback en memoire quand
l'index FAISS n'est pas disponible ou quand l'appelant passe une liste explicite).
"""

from __future__ import annotations

import io
import json
import logging
import os
import tarfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

import numpy as np
from sqlalchemy import desc
from sqlalchemy.orm import Session

from apps.api.models.event import Event
from apps.api.models.incident import Incident

logger = logging.getLogger(__name__)

# ── Constantes ────────────────────────────────────────────────────────

DEFAULT_INDEX_DIR = os.environ.get("RAG_INDEX_DIR", "/data/rag")
EMBEDDING_MODEL = os.environ.get("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
EMBEDDING_DIM = 384  # all-MiniLM-L6-v2

MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SIGMA_TARBALL_URL = (
    "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.tar.gz"
)


# ── Legacy API (compat) ──────────────────────────────────────────────


@dataclass
class RagDoc:
    """Document legacy utilise par les tests et le fallback in-memory."""

    id: str
    kind: str
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
    text_parts = [i.title or "", i.description or "", i.severity or "", i.status or ""]
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
    """Recupere un corpus de docs pour indexation (compat legacy)."""
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
        rows_i = db.query(Incident).limit(min(limit, 500)).all()
        docs.extend(_incident_to_doc(i) for i in rows_i)

    return [d for d in docs if d.text.strip()]


def rag_summary(docs: list[RagDoc]) -> dict[str, Any]:
    by_kind: dict[str, int] = {}
    for d in docs:
        by_kind[d.kind] = by_kind.get(d.kind, 0) + 1
    return {
        "corpus_size": len(docs),
        "by_kind": by_kind,
        "approx_token_count": sum(len(d.text.split()) for d in docs),
    }


def rag_search(
    query: str,
    docs: list[RagDoc],
    top_k: int = 10,
    min_score: float = 0.05,
) -> list[dict[str, Any]]:
    """Fallback in-memory TF-IDF (compat tests/legacy, pas d'IO).

    Utilise sklearn quand disponible. Ne touche PAS a l'index FAISS.
    """
    if not docs or not query.strip():
        return []

    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
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
    sims = cosine_similarity(matrix[-1], matrix[:-1]).flatten()

    idx_sorted = np.argsort(sims)[::-1]
    out: list[dict[str, Any]] = []
    for idx in idx_sorted[:top_k]:
        score = float(sims[idx])
        if score < min_score:
            break
        d = docs[idx]
        out.append(
            {
                "id": d.id,
                "kind": d.kind,
                "score": round(score, 4),
                "text_preview": d.text[:200] + ("..." if len(d.text) > 200 else ""),
                "metadata": d.metadata,
            }
        )
    return out


# ── Embedder singleton ────────────────────────────────────────────────

_embedder_lock = threading.Lock()
_embedder_instance = None


def _get_embedder():
    """Charge SentenceTransformer une seule fois (singleton thread-safe)."""
    global _embedder_instance
    if _embedder_instance is not None:
        return _embedder_instance
    with _embedder_lock:
        if _embedder_instance is not None:
            return _embedder_instance
        from sentence_transformers import SentenceTransformer

        logger.info("Loading SentenceTransformer model: %s", EMBEDDING_MODEL)
        _embedder_instance = SentenceTransformer(EMBEDDING_MODEL)
        return _embedder_instance


# ── FaissRAG ──────────────────────────────────────────────────────────


class FaissRAG:
    """RAG persistent avec FAISS + sentence-transformers.

    Fichiers :
      - <index_dir>/index.faiss : index FAISS (IndexFlatIP sur vecteurs normalises)
      - <index_dir>/docs.jsonl  : metadata, une ligne par doc (ordre = id FAISS)
      - <index_dir>/manifest.json : version + stats par source + last_updated
    """

    def __init__(self, index_dir: str = DEFAULT_INDEX_DIR):
        self.index_dir = Path(index_dir)
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.index_dir / "index.faiss"
        self.docs_path = self.index_dir / "docs.jsonl"
        self.manifest_path = self.index_dir / "manifest.json"

        self._index = None
        self._docs: list[dict[str, Any]] = []
        self._manifest: dict[str, Any] = {
            "version": 1,
            "sources": {},
        }
        self._lock = threading.Lock()
        self._load()

    # ---- persistance ----

    def _load(self) -> None:
        """Charge index + docs + manifest si presents."""
        if self.manifest_path.exists():
            try:
                self._manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.warning("Cannot read manifest: %s", exc)

        if self.docs_path.exists():
            # NB: splitlines() coupe sur \n mais AUSSI sur \r, \v, \f, U+2028,
            # U+2029 — certains textes de CVE/MITRE contiennent ces separateurs
            # Unicode, ce qui faisait exploser une ligne JSON en plein milieu
            # d'une string et skippait silencieusement TOUT l'index derriere.
            # On lit donc le fichier ligne par ligne (le file iterator respecte
            # uniquement le "\n" reel) et on tolere les lignes individuellement
            # invalides en les skippant avec log WARNING.
            self._docs = []
            n_ok = 0
            n_err = 0
            try:
                with self.docs_path.open("r", encoding="utf-8") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        line = line.rstrip("\r\n")
                        if not line.strip():
                            continue
                        try:
                            self._docs.append(json.loads(line))
                            n_ok += 1
                        except json.JSONDecodeError as je:
                            n_err += 1
                            if n_err <= 3:
                                logger.warning(
                                    "rag_docs_parse_skip line=%d err=%s",
                                    lineno, je,
                                )
            except Exception as exc:
                logger.warning("Cannot read docs.jsonl: %s", exc)
                self._docs = []
            if n_err:
                logger.warning(
                    "rag_docs_load ok=%d skipped=%d", n_ok, n_err
                )

        if self.index_path.exists():
            try:
                import faiss

                self._index = faiss.read_index(str(self.index_path))
            except Exception as exc:
                logger.warning("Cannot load FAISS index: %s", exc)
                self._index = None

    def _save(self) -> None:
        import faiss

        if self._index is not None:
            faiss.write_index(self._index, str(self.index_path))

        with self.docs_path.open("w", encoding="utf-8") as f:
            for d in self._docs:
                f.write(json.dumps(d, ensure_ascii=False) + "\n")

        self._manifest["last_updated"] = datetime.now(timezone.utc).isoformat()
        self.manifest_path.write_text(
            json.dumps(self._manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    # ---- helpers embedding ----

    def _embed(self, texts: list[str]) -> np.ndarray:
        embedder = _get_embedder()
        vecs = embedder.encode(
            texts,
            batch_size=32,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,  # cosine == inner product
        )
        return vecs.astype("float32")

    def _ensure_index(self) -> None:
        if self._index is None:
            import faiss

            self._index = faiss.IndexFlatIP(EMBEDDING_DIM)

    # ---- public API ----

    def add_documents(self, docs: list[dict[str, Any]]) -> int:
        """Ajoute des docs au format {id, source, title?, text, metadata?}.

        Batch-embed + ajout a l'index + append a docs.jsonl.
        Retourne le nombre de docs effectivement ajoutes.
        """
        if not docs:
            return 0
        docs = [d for d in docs if d.get("text", "").strip()]
        if not docs:
            return 0

        with self._lock:
            self._ensure_index()
            vecs = self._embed([d["text"] for d in docs])
            self._index.add(vecs)

            by_source = self._manifest.setdefault("sources", {})
            now = datetime.now(timezone.utc).isoformat()
            for d in docs:
                src = d.get("source", "unknown")
                stats = by_source.setdefault(src, {"count": 0, "last_updated": now})
                stats["count"] = stats.get("count", 0) + 1
                stats["last_updated"] = now
                self._docs.append(
                    {
                        "id": d.get("id"),
                        "source": src,
                        "title": d.get("title"),
                        "text": d["text"],
                        "metadata": d.get("metadata", {}),
                    }
                )

            self._save()
        return len(docs)

    def query(
        self,
        text: str,
        k: int = 5,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Embed text, FAISS search top-k, filtre par metadata (clef=valeur).

        `filters` s'applique sur le doc entier : on matche sur les cles de 1er
        niveau (source, id, title) ET sur metadata.<key>. Exemple :
        `{"source": "mitre"}` ou `{"metadata.level": "high"}`.
        """
        if not text.strip() or self._index is None or self._index.ntotal == 0:
            return []

        # On sur-echantillonne quand un filtre est applique pour en garder k apres filtrage
        search_k = k * 10 if filters else k
        search_k = min(search_k, self._index.ntotal)

        vec = self._embed([text])
        scores, idxs = self._index.search(vec, search_k)

        out: list[dict[str, Any]] = []
        for score, idx in zip(scores[0], idxs[0]):
            if idx < 0 or idx >= len(self._docs):
                continue
            doc = self._docs[idx]
            if filters and not self._match_filters(doc, filters):
                continue
            text_val = doc.get("text", "") or ""
            out.append(
                {
                    "id": doc.get("id"),
                    "source": doc.get("source"),
                    "title": doc.get("title"),
                    "score": round(float(score), 4),
                    "text_preview": text_val[:300] + ("..." if len(text_val) > 300 else ""),
                    "metadata": doc.get("metadata", {}),
                }
            )
            if len(out) >= k:
                break
        return out

    @staticmethod
    def _match_filters(doc: dict[str, Any], filters: dict[str, Any]) -> bool:
        for key, expected in filters.items():
            if key.startswith("metadata."):
                actual = (doc.get("metadata") or {}).get(key[len("metadata.") :])
            else:
                actual = doc.get(key)
            if isinstance(expected, (list, tuple, set)):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def stats(self) -> dict[str, Any]:
        by_source: dict[str, int] = {}
        for d in self._docs:
            by_source[d.get("source", "unknown")] = by_source.get(d.get("source", "unknown"), 0) + 1
        index_size_mb = 0.0
        if self.index_path.exists():
            index_size_mb = round(self.index_path.stat().st_size / (1024 * 1024), 3)
        return {
            "total_docs": len(self._docs),
            "by_source": by_source,
            "last_updated": self._manifest.get("last_updated"),
            "index_size_mb": index_size_mb,
            "index_dir": str(self.index_dir),
            "embedding_model": EMBEDDING_MODEL,
            "embedding_dim": EMBEDDING_DIM,
            "sources_manifest": self._manifest.get("sources", {}),
        }

    def reset(self) -> None:
        """Vide l'index + docs + manifest."""
        with self._lock:
            import faiss

            self._index = faiss.IndexFlatIP(EMBEDDING_DIM)
            self._docs = []
            self._manifest = {"version": 1, "sources": {}}
            if self.index_path.exists():
                self.index_path.unlink()
            if self.docs_path.exists():
                self.docs_path.unlink()
            if self.manifest_path.exists():
                self.manifest_path.unlink()

    def rebuild_from_sources(
        self,
        db: Session | None = None,
        include_mitre: bool = True,
        include_nvd: bool = True,
        include_sigma: bool = True,
        include_db: bool = False,
        nvd_days: int = 30,
    ) -> dict[str, Any]:
        """Vide l'index et re-indexe toutes les sources externes activees.

        Les fetchers sont tolerants aux pannes reseau : si une source echoue,
        elle est skippee et le report le note.
        """
        self.reset()
        report: dict[str, Any] = {"started_at": datetime.now(timezone.utc).isoformat()}

        if include_mitre:
            try:
                docs = _fetch_mitre_attack()
                n = self.add_documents(docs)
                report["mitre"] = {"indexed": n}
            except Exception as exc:
                logger.exception("MITRE fetch failed")
                report["mitre"] = {"error": str(exc)}

        if include_nvd:
            try:
                docs = _fetch_cve_recent(days=nvd_days)
                n = self.add_documents(docs)
                report["nvd"] = {"indexed": n}
            except Exception as exc:
                logger.exception("NVD fetch failed")
                report["nvd"] = {"error": str(exc)}

        if include_sigma:
            try:
                docs = _fetch_sigma_rules()
                n = self.add_documents(docs)
                report["sigma"] = {"indexed": n}
            except Exception as exc:
                logger.exception("Sigma fetch failed")
                report["sigma"] = {"error": str(exc)}

        if include_db and db is not None:
            try:
                docs = _fetch_incidents_events_db(db)
                n = self.add_documents(docs)
                report["db"] = {"indexed": n}
            except Exception as exc:
                logger.exception("DB fetch failed")
                report["db"] = {"error": str(exc)}

        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        report["stats"] = self.stats()
        return report


# ── Source fetchers ──────────────────────────────────────────────────


def _http_get(url: str, timeout: float = 60.0, params: dict | None = None) -> bytes:
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        r = client.get(url, params=params)
        r.raise_for_status()
        return r.content


def _fetch_mitre_attack() -> list[dict[str, Any]]:
    """Telecharge le STIX bundle MITRE ATT&CK Enterprise et extrait les docs."""
    raw = _http_get(MITRE_ATTACK_URL, timeout=120.0)
    bundle = json.loads(raw)
    out: list[dict[str, Any]] = []
    for obj in bundle.get("objects", []):
        otype = obj.get("type")
        if otype not in ("attack-pattern", "intrusion-set"):
            continue
        name = obj.get("name") or ""
        desc = obj.get("description") or ""
        ext_refs = obj.get("external_references") or []
        tid = None
        for ref in ext_refs:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                tid = ref["external_id"]
                break
        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        doc_id = f"mitre-{tid}" if tid else f"mitre-{obj.get('id', '')}"
        out.append(
            {
                "id": doc_id,
                "source": "mitre",
                "title": f"{tid or ''} {name}".strip(),
                "text": f"{name}. {desc}".strip(),
                "metadata": {
                    "tid": tid,
                    "stix_type": otype,
                    "tactics": tactics,
                },
            }
        )
    return out


def _fetch_cve_recent(days: int = 30) -> list[dict[str, Any]]:
    """Telecharge les CVEs NVD publiees dans les N derniers jours."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    # NVD attend un format ISO-8601 avec millisecondes et offset
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    out: list[dict[str, Any]] = []
    start_idx = 0
    page_size = 2000
    while True:
        params = {
            "pubStartDate": start.strftime(fmt),
            "pubEndDate": end.strftime(fmt),
            "resultsPerPage": page_size,
            "startIndex": start_idx,
        }
        raw = _http_get(NVD_CVE_URL, timeout=90.0, params=params)
        data = json.loads(raw)
        vulns = data.get("vulnerabilities", []) or []
        for wrapper in vulns:
            cve = wrapper.get("cve") or {}
            cve_id = cve.get("id") or ""
            descs = cve.get("descriptions") or []
            desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
            cvss = None
            metrics = cve.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                lst = metrics.get(key) or []
                if lst:
                    cvss = (lst[0].get("cvssData") or {}).get("baseScore")
                    break
            text = desc if not cvss else f"{desc} (CVSS {cvss})"
            out.append(
                {
                    "id": f"cve-{cve_id}",
                    "source": "nvd",
                    "title": cve_id,
                    "text": text,
                    "metadata": {
                        "cve_id": cve_id,
                        "cvss": cvss,
                        "published": cve.get("published"),
                    },
                }
            )
        total = int(data.get("totalResults", 0) or 0)
        start_idx += page_size
        if start_idx >= total:
            break
        # NVD rate-limit friendly
        time.sleep(1.0)
    return out


def _fetch_sigma_rules() -> list[dict[str, Any]]:
    """Telecharge le tarball SigmaHQ/sigma et extrait les .yml (rules/)."""
    try:
        import yaml
    except ImportError:
        logger.warning("PyYAML missing — cannot parse Sigma rules")
        return []

    raw = _http_get(SIGMA_TARBALL_URL, timeout=180.0)
    out: list[dict[str, Any]] = []
    bio = io.BytesIO(raw)
    with tarfile.open(fileobj=bio, mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            name = member.name
            if not name.endswith((".yml", ".yaml")):
                continue
            # Ne garder que les regles effectives (dossiers rules*)
            if "/rules" not in name:
                continue
            try:
                fh = tar.extractfile(member)
                if fh is None:
                    continue
                content = fh.read().decode("utf-8", errors="ignore")
                data = yaml.safe_load(content)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            title = data.get("title") or ""
            desc = data.get("description") or ""
            logsource = data.get("logsource") or {}
            detection = data.get("detection") or {}
            text = (
                f"{title}. {desc} "
                f"logsource={json.dumps(logsource, ensure_ascii=False)} "
                f"detection={json.dumps(detection, ensure_ascii=False)}"
            ).strip()
            uid = data.get("id") or name
            out.append(
                {
                    "id": f"sigma-{uid}",
                    "source": "sigma",
                    "title": title,
                    "text": text,
                    "metadata": {
                        "level": data.get("level"),
                        "status": data.get("status"),
                        "logsource": logsource,
                        "tags": data.get("tags") or [],
                        "path": name,
                    },
                }
            )
    return out


def _fetch_incidents_events_db(db: Session, limit: int = 5000) -> list[dict[str, Any]]:
    """Convertit events + incidents recents en docs FAISS."""
    out: list[dict[str, Any]] = []
    cutoff = datetime.now(timezone.utc) - timedelta(hours=168)
    for e in (
        db.query(Event)
        .filter(Event.ts >= cutoff)
        .order_by(desc(Event.ts))
        .limit(limit)
        .all()
    ):
        rag = _event_to_doc(e)
        if not rag.text.strip():
            continue
        out.append(
            {
                "id": f"event-{rag.id}",
                "source": "event",
                "title": rag.metadata.get("event_type"),
                "text": rag.text,
                "metadata": rag.metadata,
            }
        )
    for i in db.query(Incident).limit(500).all():
        rag = _incident_to_doc(i)
        if not rag.text.strip():
            continue
        out.append(
            {
                "id": f"incident-{rag.id}",
                "source": "incident",
                "title": rag.metadata.get("title"),
                "text": rag.text,
                "metadata": rag.metadata,
            }
        )
    return out


# ── Singleton + helper compat ────────────────────────────────────────

_rag_instance: FaissRAG | None = None
_rag_lock = threading.Lock()


def get_rag(index_dir: str | None = None) -> FaissRAG:
    """Singleton FaissRAG pour partager l'index entre requetes."""
    global _rag_instance
    if index_dir is None:
        index_dir = DEFAULT_INDEX_DIR
    if _rag_instance is not None and str(_rag_instance.index_dir) == str(Path(index_dir)):
        return _rag_instance
    with _rag_lock:
        if _rag_instance is None or str(_rag_instance.index_dir) != str(Path(index_dir)):
            _rag_instance = FaissRAG(index_dir)
        return _rag_instance


def retrieve_context(
    query: str,
    k: int = 5,
    filters: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Wrapper compat : recupere le contexte RAG pour une query.

    Tente FAISS (si index present) puis retourne une liste vide sinon.
    Les anciens appelants peuvent utiliser ce helper sans se soucier
    du cycle de vie de l'index.
    """
    try:
        rag = get_rag()
        return rag.query(query, k=k, filters=filters)
    except Exception as exc:
        logger.warning("retrieve_context failed: %s", exc)
        return []
