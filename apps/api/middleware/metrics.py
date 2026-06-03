"""Middleware de métriques Prometheus et compteurs personnalisés."""

from __future__ import annotations

from prometheus_client import Counter, Gauge

# Custom application metrics
incidents_created_total = Counter(
    "siem_incidents_created_total",
    "Total incidents created",
    ["severity"],
)

detection_rules_evaluated_total = Counter(
    "siem_detection_rules_evaluated_total",
    "Total detection rule evaluations",
)

active_websocket_connections = Gauge(
    "siem_active_websocket_connections",
    "Number of active WebSocket connections",
)

celery_tasks_total = Counter(
    "siem_celery_tasks_total",
    "Total Celery tasks executed",
    ["task_name", "status"],
)

events_ingested_total = Counter(
    "siem_events_ingested_total",
    "Total events ingested",
    ["severity"],
)
