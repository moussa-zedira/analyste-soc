"""Détection d'anomalies par Isolation Forest sur les vecteurs de caractéristiques par IP.

Persistence :
- Au boot, tente de charger ``/data/models/ml_anomaly_v{MODEL_VERSION}.pkl``.
- Si le fichier est absent ou stale (> ``MODEL_MAX_AGE_DAYS``), re-entraîne et sauve.
- Métadonnées (timestamp_train, n_samples, n_features, model_class, sklearn_version)
  écrites dans un sidecar ``.meta.json``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import func
from sqlalchemy.orm import Session

try:
    import joblib
    import numpy as np
    import sklearn
    from sklearn.ensemble import IsolationForest
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False
    np = None  # type: ignore[assignment]
    joblib = None  # type: ignore[assignment]
    sklearn = None  # type: ignore[assignment]
    IsolationForest = None  # type: ignore[assignment,misc]

from apps.api.broadcast import broadcaster
from apps.api.models.event import Event
from apps.api.models.incident import Incident
from apps.api.models.incident_event import IncidentEvent
from apps.api.notifications.webhook import notify_incident_created

logger = logging.getLogger(__name__)

SEVERITY_MAP = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# --- Persistence ----------------------------------------------------------
MODEL_VERSION = "1"
MODEL_DIR = Path(os.environ.get("ML_MODELS_DIR", "/data/models"))
MODEL_PATH = MODEL_DIR / f"ml_anomaly_v{MODEL_VERSION}.pkl"
META_PATH = MODEL_DIR / f"ml_anomaly_v{MODEL_VERSION}.meta.json"
MODEL_MAX_AGE_DAYS = 7

# Module-level singleton (protected by lock for thread safety)
_ml_lock = threading.Lock()
_model: IsolationForest | None = None
_model_info: dict = {}
_boot_loaded = False


def _model_is_stale(meta: dict) -> bool:
    """Retourne True si les meta indiquent un modele plus vieux que MODEL_MAX_AGE_DAYS."""
    ts = meta.get("timestamp_train")
    if not ts:
        return True
    try:
        trained = datetime.fromisoformat(ts)
    except ValueError:
        return True
    if trained.tzinfo is None:
        trained = trained.replace(tzinfo=timezone.utc)
    age = datetime.now(timezone.utc) - trained
    return age > timedelta(days=MODEL_MAX_AGE_DAYS)


def _load_persisted_model() -> bool:
    """Tente de charger le modèle + meta depuis le disque. Retourne True si réussi."""
    global _model, _model_info
    if not _ML_AVAILABLE:
        return False
    if not MODEL_PATH.exists() or not META_PATH.exists():
        return False
    try:
        meta = json.loads(META_PATH.read_text(encoding="utf-8"))
    except Exception:
        logger.warning("ml_anomaly: meta unreadable, will retrain")
        return False
    if _model_is_stale(meta):
        logger.info("ml_anomaly: persisted model stale (>%d days), will retrain", MODEL_MAX_AGE_DAYS)
        return False
    try:
        loaded = joblib.load(MODEL_PATH)
    except Exception:
        logger.exception("ml_anomaly: failed to load %s", MODEL_PATH)
        return False
    with _ml_lock:
        _model = loaded
        _model_info = {**meta, "status": "loaded_from_disk"}
    logger.info("ml_anomaly: loaded persisted model from %s (trained %s)",
                MODEL_PATH, meta.get("timestamp_train"))
    return True


def _persist_model(model, n_samples: int, n_features: int) -> None:
    """Sauve le modèle + meta sidecar sur disque."""
    if not _ML_AVAILABLE:
        return
    try:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        meta = {
            "timestamp_train": datetime.now(timezone.utc).isoformat(),
            "n_samples_train": n_samples,
            "n_features": n_features,
            "model_class": type(model).__name__,
            "sklearn_version": getattr(sklearn, "__version__", "unknown"),
            "model_version": MODEL_VERSION,
        }
        META_PATH.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        logger.info("ml_anomaly: persisted model to %s", MODEL_PATH)
    except Exception:
        logger.exception("ml_anomaly: failed to persist model")


def ensure_model_loaded() -> None:
    """Tente de charger le modèle persisté une seule fois au boot."""
    global _boot_loaded
    if _boot_loaded:
        return
    _boot_loaded = True
    _load_persisted_model()


def _build_feature_vectors(
    db: Session, window_minutes: int = 60,
) -> tuple["np.ndarray", list[str], dict[str, list[str]]]:
    """Construit les vecteurs de caracteristiques par IP a partir des evenements recents.

    Caracteristiques par src_ip :
      0: nombre d'evenements, 1: types distincts, 2: IP destinations distinctes,
      3: score de severite moyen, 4: etendue temporelle en secondes.

    Retourne (matrice_features, liste_ip, ids_evenements_par_ip).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=window_minutes)

    rows = (
        db.query(
            Event.src_ip,
            func.count(Event.id).label("event_count"),
            func.count(func.distinct(Event.event_type)).label("distinct_types"),
            func.count(func.distinct(Event.dst_ip)).label("distinct_dst"),
            func.min(Event.ts).label("min_ts"),
            func.max(Event.ts).label("max_ts"),
        )
        .filter(Event.ts >= cutoff, Event.src_ip.isnot(None))
        .group_by(Event.src_ip)
        .all()
    )

    if not rows:
        return np.array([]), [], {}

    sev_rows = (
        db.query(Event.src_ip, Event.severity, func.count(Event.id))
        .filter(Event.ts >= cutoff, Event.src_ip.isnot(None))
        .group_by(Event.src_ip, Event.severity)
        .all()
    )
    sev_sum: dict[str, float] = {}
    sev_cnt: dict[str, int] = {}
    for ip, sev, cnt in sev_rows:
        sev_sum[ip] = sev_sum.get(ip, 0) + SEVERITY_MAP.get(sev, 1) * cnt
        sev_cnt[ip] = sev_cnt.get(ip, 0) + cnt

    eid_rows = (
        db.query(Event.src_ip, Event.id)
        .filter(Event.ts >= cutoff, Event.src_ip.isnot(None))
        .all()
    )
    ip_event_ids: dict[str, list[str]] = {}
    for ip, eid in eid_rows:
        ip_event_ids.setdefault(ip, []).append(eid)

    features = []
    ips = []
    for r in rows:
        ip = r.src_ip
        time_spread = 0.0
        if r.min_ts and r.max_ts:
            time_spread = (r.max_ts - r.min_ts).total_seconds()
        avg_sev = sev_sum.get(ip, 1) / max(sev_cnt.get(ip, 1), 1)

        features.append([
            r.event_count,
            r.distinct_types,
            r.distinct_dst,
            avg_sev,
            time_spread,
        ])
        ips.append(ip)

    return np.array(features, dtype=np.float64), ips, ip_event_ids


def _create_ml_incident(
    db: Session,
    ip: str,
    anomaly_score: float,
    features: list[float],
    event_ids: list[str],
    now: datetime,
) -> bool:
    """Cree un incident pour une anomalie detectee par ML."""
    bucket = now.strftime("%Y-%m-%dT%H:%M")
    dedup_hash = hashlib.sha256(
        f"ml.isolation_forest.v1|{ip}|{bucket}".encode()
    ).hexdigest()

    if db.query(Incident.id).filter(Incident.dedup_hash == dedup_hash).first():
        return False

    if anomaly_score < -0.5:
        severity = "critical"
    elif anomaly_score < -0.3:
        severity = "high"
    else:
        severity = "medium"

    incident_id = str(uuid.uuid4())
    title = f"ML Anomaly: suspicious behavior from {ip}"
    description = (
        f"Isolation Forest detected anomalous behavior from {ip}. "
        f"Anomaly score: {anomaly_score:.3f}. "
        f"Features: events={features[0]:.0f}, types={features[1]:.0f}, "
        f"dst_ips={features[2]:.0f}, avg_sev={features[3]:.1f}, "
        f"time_spread={features[4]:.0f}s."
    )

    incident = Incident(
        id=incident_id, created_at=now, updated_at=now,
        status="open", severity=severity, title=title, description=description,
        rule_id="ml.isolation_forest.v1", entity_key=f"src_ip:{ip}",
        start_ts=now - timedelta(hours=1), end_ts=now, dedup_hash=dedup_hash,
    )
    db.add(incident)
    db.flush()

    for eid in event_ids[:100]:
        db.add(IncidentEvent(incident_id=incident_id, event_id=eid))
    db.flush()

    notify_incident_created(
        incident_id=incident_id, title=title, severity=severity,
        description=description, rule_id="ml.isolation_forest.v1",
        entity_key=f"src_ip:{ip}", status="open", created_at=now.isoformat(),
    )

    broadcaster.publish({
        "type": "new_incident",
        "payload": {
            "id": incident_id, "title": title, "severity": severity,
            "rule_id": "ml.isolation_forest.v1", "entity_key": f"src_ip:{ip}",
            "status": "open", "created_at": now.isoformat(),
        },
    })

    logger.info("Created ML anomaly incident %s for IP %s (score=%.3f)", incident_id, ip, anomaly_score)
    return True


def train_and_detect(
    db: Session,
    contamination: float = 0.05,
    window_minutes: int = 60,
    force_retrain: bool = False,
) -> dict:
    """Entraine (ou réutilise) l'Isolation Forest et signale les anomalies.

    Si un modèle persisté valide existe et que ``force_retrain`` est False,
    il est réutilisé et l'inference se fait sans re-entraînement.
    Sinon : entraînement complet + persistence sur disque.
    """
    global _model, _model_info

    if not _ML_AVAILABLE:
        return {
            "anomalies_detected": 0,
            "incidents_created": 0,
            "samples_analyzed": 0,
            "error": "ML libraries (numpy/sklearn/joblib) not available on this system",
        }

    ensure_model_loaded()

    X, ips, ip_event_ids = _build_feature_vectors(db, window_minutes)

    if len(ips) < 10:
        return {
            "anomalies_detected": 0,
            "incidents_created": 0,
            "samples_analyzed": len(ips),
            "error": "Not enough data (need >= 10 distinct IPs)",
        }

    # Decide whether to retrain
    with _ml_lock:
        existing_model = _model
        existing_info = dict(_model_info) if _model_info else {}

    needs_train = (
        force_retrain
        or existing_model is None
        or _model_is_stale(existing_info)
        or existing_info.get("n_features") != int(X.shape[1])
    )

    if needs_train:
        model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )
        predictions = model.fit_predict(X)
        scores = model.decision_function(X)
        _persist_model(model, n_samples=len(ips), n_features=int(X.shape[1]))
        info = {
            "timestamp_train": datetime.now(timezone.utc).isoformat(),
            "n_samples_train": len(ips),
            "n_features": int(X.shape[1]),
            "model_class": type(model).__name__,
            "sklearn_version": getattr(sklearn, "__version__", "unknown"),
            "model_version": MODEL_VERSION,
            "contamination": contamination,
            "status": "trained",
        }
        with _ml_lock:
            _model = model
            _model_info = info
    else:
        model = existing_model
        predictions = model.predict(X)
        scores = model.decision_function(X)

    now = datetime.now(timezone.utc)
    anomalies_detected = 0
    incidents_created = 0

    for i, (pred, score) in enumerate(zip(predictions, scores)):
        if pred == -1:
            anomalies_detected += 1
            ip = ips[i]
            eids = ip_event_ids.get(ip, [])
            if _create_ml_incident(db, ip, float(score), X[i].tolist(), eids, now):
                incidents_created += 1

    db.commit()

    summary = {
        "anomalies_detected": anomalies_detected,
        "incidents_created": incidents_created,
        "samples_analyzed": len(ips),
        "model_reused": not needs_train,
    }
    logger.info("ML detection finished: %s", summary)
    return summary


def detect_anomalies(db: Session) -> dict:
    """Alias public pour ``train_and_detect`` — utilisé par les tests d'import."""
    return train_and_detect(db)


def retrain(db: Session, contamination: float = 0.05, window_minutes: int = 60) -> dict:
    """Force le ré-entraînement et la persistence du modèle Isolation Forest."""
    return train_and_detect(
        db,
        contamination=contamination,
        window_minutes=window_minutes,
        force_retrain=True,
    )


def get_model_info() -> dict:
    """Retourne les informations du modele actuel ou le statut non entraine."""
    ensure_model_loaded()
    with _ml_lock:
        return dict(_model_info) if _model_info else {"status": "not_trained"}
