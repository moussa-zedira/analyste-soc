"""HTTP client for posting events and triggering rules."""

from __future__ import annotations

import requests

from apps.agent.config import ANOMALY_RUN_URL, EVENTS_URL, HEADERS, RULES_RUN_URL


def post_event(event_data: dict) -> dict | None:
    """POST a single event to /events. Returns response JSON or None."""
    try:
        resp = requests.post(EVENTS_URL, json=event_data, headers=HEADERS, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as exc:
        print(f"[ERROR] POST /events failed: {exc}")
        return None


def trigger_rules() -> dict | None:
    """POST /rules/run to trigger the detection engine."""
    try:
        resp = requests.post(RULES_RUN_URL, json={}, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        rules = result.get("rules_evaluated", "?")
        created = result.get("incidents_created", "?")
        print(f"[RULES] Evaluated: {rules}, Incidents created: {created}")
        return result
    except requests.RequestException as exc:
        print(f"[ERROR] POST /rules/run failed: {exc}")
        return None


def trigger_anomaly() -> dict | None:
    """POST /anomaly/run to trigger anomaly detection."""
    try:
        resp = requests.post(ANOMALY_RUN_URL, json={}, headers=HEADERS, timeout=10)
        resp.raise_for_status()
        result = resp.json()
        vol = result.get("volume_metrics_evaluated", "?")
        ips = result.get("ip_metrics_evaluated", "?")
        created = result.get("incidents_created", "?")
        print(f"[ANOMALY] Volume: {vol}, IPs: {ips}, Incidents: {created}")
        return result
    except requests.RequestException as exc:
        print(f"[ERROR] POST /anomaly/run failed: {exc}")
        return None
