"""Classifieur de severite d'incidents base sur le NLP avec TF-IDF + Random Forest."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

from sqlalchemy.orm import Session

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.pipeline import Pipeline
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False
    Pipeline = None  # type: ignore[assignment,misc]

from apps.api.models.incident import Incident

logger = logging.getLogger(__name__)

MIN_TRAINING_SAMPLES = 50
SEVERITY_LABELS = ["low", "medium", "high", "critical"]

# Module-level singleton (protected by lock for thread safety)
_lock = threading.Lock()
_classifier: Pipeline | None = None
_classifier_info: dict = {}


def _build_training_data(db: Session) -> tuple[list[str], list[str]]:
    """Construit le corpus de textes et les etiquettes a partir des incidents existants.

    texte = titre + " " + description + messages d'evenements concatenes.
    etiquette = incident.severity.
    """
    incidents = db.query(Incident).all()
    texts: list[str] = []
    labels: list[str] = []

    for inc in incidents:
        event_msgs = " ".join(
            e.message or "" for e in (inc.events or [])[:50]
        )
        text = f"{inc.title} {inc.description} {event_msgs}".strip()
        texts.append(text)
        labels.append(inc.severity)

    return texts, labels


def train_classifier(db: Session) -> dict:
    """Entraine le classifieur TF-IDF + Random Forest sur les incidents existants.

    Retourne un dictionnaire d'informations avec le statut.
    """
    global _classifier, _classifier_info

    if not _ML_AVAILABLE:
        return {"status": "ml_unavailable", "samples": 0, "required": MIN_TRAINING_SAMPLES}

    texts, labels = _build_training_data(db)

    if len(texts) < MIN_TRAINING_SAMPLES:
        return {
            "status": "insufficient_data",
            "samples": len(texts),
            "required": MIN_TRAINING_SAMPLES,
        }

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(max_features=500, stop_words="english")),
        ("clf", RandomForestClassifier(n_estimators=100, random_state=42)),
    ])
    pipeline.fit(texts, labels)

    with _lock:
        _classifier = pipeline
        _classifier_info = {
            "status": "trained",
            "n_samples": len(texts),
            "last_trained": datetime.now(timezone.utc).isoformat(),
            "classes": SEVERITY_LABELS,
        }

    logger.info("NLP classifier trained on %d samples", len(texts))
    return _classifier_info


def predict_severity(
    title: str, description: str, event_messages: list[str],
) -> str | None:
    """Predit la severite d'un nouvel incident.

    Retourne la severite predite ou None si le modele n'est pas entraine.
    """
    with _lock:
        clf = _classifier
    if clf is None:
        return None
    text = f"{title} {description} {' '.join(event_messages)}".strip()
    if not text:
        return None
    return str(clf.predict([text])[0])


def classify_incidents(db: Session) -> dict:
    """Entraine le classifieur puis classifie les incidents sans severite suggeree.

    Retourne un dictionnaire de resume.
    """
    train_result = train_classifier(db)
    if train_result.get("status") != "trained":
        return {"status": train_result["status"], "incidents_classified": 0}

    incidents = (
        db.query(Incident)
        .filter(Incident.suggested_severity.is_(None))
        .all()
    )

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


def get_classifier_info() -> dict:
    """Retourne les informations du classifieur actuel."""
    return _classifier_info if _classifier_info else {"status": "not_trained"}
