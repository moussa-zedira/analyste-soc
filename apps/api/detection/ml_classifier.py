"""NLP-based incident severity classifier using TF-IDF + Random Forest."""

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
    """Build text corpus and labels from existing incidents.

    text = title + " " + description + joined event messages
    label = incident.severity
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
    """Train the TF-IDF + Random Forest classifier on existing incidents.

    Returns info dict with status.
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
    """Predict severity for a new incident.

    Returns predicted severity string, or None if model not trained.
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
    """Train classifier, then classify all incidents missing suggested_severity.

    Returns summary dict.
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
    """Return current classifier info."""
    return _classifier_info if _classifier_info else {"status": "not_trained"}
