"""Metriques Prometheus metier (au-dela du HTTP standard).

Tous les compteurs/histogrammes sont declares au niveau module pour etre
reutilisables sans risque de double-enregistrement (Prometheus leve sinon).
Les helpers ``record_*`` masquent les details d'instrumentation aux
appelants pour garder les routes lisibles.
"""

from __future__ import annotations

from prometheus_client import Counter, Histogram

# ─────────────────────────────────────────────────────────────────────
# Authentification
# ─────────────────────────────────────────────────────────────────────
auth_attempts_total = Counter(
    "soc_auth_attempts_total",
    "Tentatives d'authentification, par resultat et type d'evenement.",
    labelnames=("event", "result"),
)


def record_login(event: str, success: bool) -> None:
    """event in {login, refresh, logout, register}; success -> ok|fail."""
    auth_attempts_total.labels(event=event, result="ok" if success else "fail").inc()


# ─────────────────────────────────────────────────────────────────────
# Incidents
# ─────────────────────────────────────────────────────────────────────
incidents_created_total = Counter(
    "soc_incidents_created_total",
    "Incidents crees par severite et regle source.",
    labelnames=("severity", "rule_id"),
)

incidents_transitioned_total = Counter(
    "soc_incidents_transitioned_total",
    "Transitions de statut d'incident (open -> ack -> resolved -> closed).",
    labelnames=("from_status", "to_status"),
)


def record_incident_created(severity: str, rule_id: str | None) -> None:
    incidents_created_total.labels(severity=severity, rule_id=rule_id or "unknown").inc()


def record_incident_transition(from_status: str, to_status: str) -> None:
    incidents_transitioned_total.labels(from_status=from_status, to_status=to_status).inc()


# ─────────────────────────────────────────────────────────────────────
# Alerting (notifications sortantes)
# ─────────────────────────────────────────────────────────────────────
alerts_emitted_total = Counter(
    "soc_alerts_emitted_total",
    "Alertes emises vers un canal externe (slack, email, webhook...).",
    labelnames=("channel", "result"),
)


def record_alert(channel: str, success: bool) -> None:
    alerts_emitted_total.labels(channel=channel, result="ok" if success else "fail").inc()


# ─────────────────────────────────────────────────────────────────────
# Audit append-only (pentest)
# ─────────────────────────────────────────────────────────────────────
audit_writes_total = Counter(
    "soc_audit_writes_total",
    "Ecritures dans la chaine d'audit pentest (append-only).",
    labelnames=("action", "success"),
)


def record_audit_write(action: str, success: bool) -> None:
    audit_writes_total.labels(action=action, success="true" if success else "false").inc()


# ─────────────────────────────────────────────────────────────────────
# Detection engineering (Sigma/correlation — branche en Vague 8)
# ─────────────────────────────────────────────────────────────────────
detection_rule_matches_total = Counter(
    "soc_detection_rule_matches_total",
    "Matchs de regles de detection (Sigma + correlation).",
    labelnames=("engine", "rule_id", "severity"),
)


def record_rule_match(engine: str, rule_id: str, severity: str) -> None:
    detection_rule_matches_total.labels(engine=engine, rule_id=rule_id, severity=severity).inc()


# ─────────────────────────────────────────────────────────────────────
# Celery — duree d'execution (autoretry inclus)
# ─────────────────────────────────────────────────────────────────────
celery_task_duration_seconds = Histogram(
    "soc_celery_task_duration_seconds",
    "Duree d'execution des taches Celery par nom et resultat.",
    labelnames=("task", "result"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600),
)
