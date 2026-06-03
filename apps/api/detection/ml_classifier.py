"""Classifieur de severite d'incidents base sur le NLP avec TF-IDF + Random Forest.

Persistence :
- Au boot, tente de charger ``/data/models/ml_classifier_v{MODEL_VERSION}.pkl``.
- Si absent ou stale (> ``MODEL_MAX_AGE_DAYS``) → re-entraînement + persistence.
- Métadonnées dans un sidecar ``.meta.json``.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy.orm import Session

try:
    import joblib
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline

    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False
    Pipeline = None  # type: ignore[assignment,misc]
    joblib = None  # type: ignore[assignment]
    sklearn = None  # type: ignore[assignment]

from apps.api.models.incident import Incident

logger = logging.getLogger(__name__)

MIN_TRAINING_SAMPLES = 50
SEVERITY_LABELS = ["low", "medium", "high", "critical"]

# --- Persistence ----------------------------------------------------------
MODEL_VERSION = "1"
MODEL_DIR = Path(os.environ.get("ML_MODELS_DIR", "/data/models"))
MODEL_PATH = MODEL_DIR / f"ml_classifier_v{MODEL_VERSION}.pkl"
META_PATH = MODEL_DIR / f"ml_classifier_v{MODEL_VERSION}.meta.json"
MODEL_MAX_AGE_DAYS = 7

# Module-level singleton (protected by lock for thread safety)
_lock = threading.Lock()
_classifier: Pipeline | None = None
_classifier_info: dict = {}
_boot_loaded = False


def _model_is_stale(meta: dict) -> bool:
    """True si le modèle est plus vieux que MODEL_MAX_AGE_DAYS."""
    ts = meta.get("timestamp_train")
    if not ts:
        return True
    try:
        trained = datetime.fromisoformat(ts)
    except ValueError:
        return True
    if trained.tzinfo is None:
        trained = trained.replace(tzinfo=UTC)
    return (datetime.now(UTC) - trained) > timedelta(days=MODEL_MAX_AGE_DAYS)


def _load_persisted_classifier() -> bool:
    """Charge le classifieur depuis le disque s'il existe et est valide."""
    global _classifier, _classifier_info
    if not _ML_AVAILABLE:
        return False
    if not MODEL_PATH.exists() or not META_PATH.exists():
        return False
    try:
        meta = json.loads(META_PATH.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("ml_classifier: meta unreadable, will retrain")
        return False
    if _model_is_stale(meta):
        logger.info("ml_classifier: persisted model stale, will retrain")
        return False
    try:
        loaded = joblib.load(MODEL_PATH)
    except Exception:
        logger.exception("ml_classifier: failed to load %s", MODEL_PATH)
        return False
    with _lock:
        _classifier = loaded
        _classifier_info = {**meta, "status": "loaded_from_disk"}
    logger.info(
        "ml_classifier: loaded persisted model from %s (trained %s)",
        MODEL_PATH,
        meta.get("timestamp_train"),
    )
    return True


def _persist_classifier(pipeline, n_samples: int) -> None:
    """Sauve le pipeline + meta sidecar."""
    if not _ML_AVAILABLE:
        return
    try:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(pipeline, MODEL_PATH)
        meta = {
            "timestamp_train": datetime.now(UTC).isoformat(),
            "n_samples_train": n_samples,
            "n_features": getattr(
                pipeline.named_steps.get("tfidf"),
                "max_features",
                None,
            ),
            "model_class": type(pipeline.named_steps.get("clf")).__name__,
            "sklearn_version": getattr(sklearn, "__version__", "unknown"),
            "model_version": MODEL_VERSION,
            "classes": SEVERITY_LABELS,
        }
        META_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        logger.info("ml_classifier: persisted to %s", MODEL_PATH)
    except Exception:
        logger.exception("ml_classifier: failed to persist")


def ensure_classifier_loaded() -> None:
    """Tente de charger le modèle persisté une seule fois au boot."""
    global _boot_loaded
    if _boot_loaded:
        return
    _boot_loaded = True
    _load_persisted_classifier()


def _build_training_data(db: Session) -> tuple[list[str], list[str]]:
    """Construit le corpus de textes et les etiquettes a partir des incidents existants."""
    incidents = db.query(Incident).all()
    texts: list[str] = []
    labels: list[str] = []

    for inc in incidents:
        event_msgs = " ".join(e.message or "" for e in (inc.events or [])[:50])
        text = f"{inc.title} {inc.description} {event_msgs}".strip()
        texts.append(text)
        labels.append(inc.severity)

    return texts, labels


def train_classifier(db: Session, force_retrain: bool = False) -> dict:
    """Entraîne le classifieur (ou réutilise un modèle persisté)."""
    global _classifier, _classifier_info

    if not _ML_AVAILABLE:
        return {"status": "ml_unavailable", "samples": 0, "required": MIN_TRAINING_SAMPLES}

    ensure_classifier_loaded()

    with _lock:
        existing = _classifier
        existing_info = dict(_classifier_info) if _classifier_info else {}

    if not force_retrain and existing is not None and not _model_is_stale(existing_info):
        return {**existing_info, "status": existing_info.get("status", "trained")}

    texts, labels = _build_training_data(db)

    if len(texts) < MIN_TRAINING_SAMPLES:
        return {
            "status": "insufficient_data",
            "samples": len(texts),
            "required": MIN_TRAINING_SAMPLES,
        }

    pipeline = Pipeline(
        [
            ("tfidf", TfidfVectorizer(max_features=500, stop_words="english")),
            ("clf", RandomForestClassifier(n_estimators=100, random_state=42)),
        ]
    )
    pipeline.fit(texts, labels)
    _persist_classifier(pipeline, n_samples=len(texts))

    info = {
        "status": "trained",
        "n_samples_train": len(texts),
        "timestamp_train": datetime.now(UTC).isoformat(),
        "model_class": type(pipeline.named_steps["clf"]).__name__,
        "sklearn_version": getattr(sklearn, "__version__", "unknown"),
        "model_version": MODEL_VERSION,
        "classes": SEVERITY_LABELS,
    }
    with _lock:
        _classifier = pipeline
        _classifier_info = info

    logger.info("NLP classifier trained on %d samples", len(texts))
    return info


def predict_severity(
    title: str,
    description: str,
    event_messages: list[str],
) -> str | None:
    """Predit la severite d'un nouvel incident."""
    ensure_classifier_loaded()
    with _lock:
        clf = _classifier
    if clf is None:
        return None
    text = f"{title} {description} {' '.join(event_messages)}".strip()
    if not text:
        return None
    return str(clf.predict([text])[0])


def classify_incidents(db: Session) -> dict:
    """Entraîne le classifieur (si nécessaire) puis classifie les incidents."""
    train_result = train_classifier(db)
    if train_result.get("status") not in {"trained", "loaded_from_disk"}:
        return {"status": train_result["status"], "incidents_classified": 0}

    incidents = db.query(Incident).filter(Incident.suggested_severity.is_(None)).all()

    classified = 0
    for inc in incidents:
        event_msgs = [e.message or "" for e in (inc.events or [])[:50]]
        predicted = predict_severity(inc.title, inc.description, event_msgs)
        if predicted:
            inc.suggested_severity = predicted
            classified += 1

    db.commit()
    logger.info("Classified %d incidents", classified)
    return {"status": "trained", "incidents_classified": classified}


def retrain(db: Session) -> dict:
    """Force le ré-entraînement et la persistence du classifieur NLP."""
    return train_classifier(db, force_retrain=True)


def get_classifier_info() -> dict:
    """Retourne les informations du classifieur actuel."""
    ensure_classifier_loaded()
    with _lock:
        return dict(_classifier_info) if _classifier_info else {"status": "not_trained"}
