"""Stack d'observabilite : metriques metier + tracing OTel.

Le module standardise les compteurs/histogrammes specifiques au SOC
(incidents, alertes, audit, auth) en complement des metriques HTTP
expose par prometheus_fastapi_instrumentator.
"""

from apps.api.observability.metrics import (
    incidents_created_total,
    incidents_transitioned_total,
    alerts_emitted_total,
    audit_writes_total,
    auth_attempts_total,
    celery_task_duration_seconds,
    detection_rule_matches_total,
    record_login,
    record_incident_created,
    record_incident_transition,
    record_alert,
    record_audit_write,
    record_rule_match,
)
from apps.api.observability.tracing import setup_tracing, get_tracer, traced

# Force l'import des metriques Threat Intel pour qu'elles soient enregistrees
# dans le default registry Prometheus (sinon elles n'apparaissent dans
# /metrics qu'apres le premier appel a un provider).
from apps.api.threat_intel import observability as _ti_observability  # noqa: F401

__all__ = [
    "incidents_created_total",
    "incidents_transitioned_total",
    "alerts_emitted_total",
    "audit_writes_total",
    "auth_attempts_total",
    "celery_task_duration_seconds",
    "detection_rule_matches_total",
    "record_login",
    "record_incident_created",
    "record_incident_transition",
    "record_alert",
    "record_audit_write",
    "record_rule_match",
    "setup_tracing",
    "get_tracer",
    "traced",
]
