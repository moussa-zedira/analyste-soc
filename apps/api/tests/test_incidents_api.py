"""Tests d'integration des endpoints incidents (list/detail/transitions)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.integration


def _make_incident(db_session, *, severity: str = "high", status: str = "open"):
    """Insere un incident de test directement en DB."""
    from apps.api.models.incident import Incident

    now = datetime.now(UTC)
    inc = Incident(
        id=f"inc-{uuid.uuid4().hex[:8]}",
        created_at=now,
        updated_at=now,
        status=status,
        severity=severity,
        title="Brute force detected",
        description="multi-source brute force",
        rule_id="bruteforce.v1",
        entity_key=f"src=10.0.0.{uuid.uuid4().int % 250 + 1}",
        start_ts=now - timedelta(minutes=5),
        end_ts=now,
        dedup_hash=uuid.uuid4().hex,
    )
    db_session.add(inc)
    db_session.commit()
    return inc


def _login_role(api_client, role: str) -> dict[str, str]:
    """Inscrit + login un user du role demande, retourne les headers."""
    n = uuid.uuid4().hex[:6]
    api_client.post(
        "/auth/register",
        json={
            "username": f"u-{n}",
            "email": f"u-{n}@t.local",
            "password": "Pwd-" + n,
            "role": role,
        },
    )
    r = api_client.post("/auth/login", json={"username": f"u-{n}", "password": "Pwd-" + n})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_list_incidents_returns_array(api_client, db_session, auth_headers):
    """GET /incidents renvoie une liste filtrable et paginee."""
    _make_incident(db_session, severity="high")
    _make_incident(db_session, severity="low")

    r = api_client.get("/incidents", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)
    assert len(data) >= 2


def test_list_incidents_filter_by_severity(api_client, db_session, auth_headers):
    """Le filtre ?severity=high ne renvoie que les hauts."""
    _make_incident(db_session, severity="high")
    _make_incident(db_session, severity="low")

    r = api_client.get("/incidents?severity=high", headers=auth_headers)
    assert r.status_code == 200
    assert all(i["severity"] == "high" for i in r.json())


def test_get_incident_404_for_unknown(api_client, auth_headers):
    """GET /incidents/{id} inconnu -> 404."""
    r = api_client.get("/incidents/missing-id", headers=auth_headers)
    assert r.status_code == 404


def test_patch_incident_transition_open_to_ack(api_client, db_session):
    """PATCH valide open->ack si role lead+."""
    inc = _make_incident(db_session, status="open")
    headers = _login_role(api_client, role="lead")
    r = api_client.patch(f"/incidents/{inc.id}", headers=headers, json={"status": "ack"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "ack"


def test_patch_incident_invalid_transition_returns_422(api_client, db_session):
    """closed -> ack n'est PAS dans VALID_TRANSITIONS -> 422."""
    inc = _make_incident(db_session, status="closed")
    headers = _login_role(api_client, role="lead")
    r = api_client.patch(f"/incidents/{inc.id}", headers=headers, json={"status": "ack"})
    assert r.status_code == 422


def test_patch_incident_requires_lead_role(api_client, db_session):
    """Un analyst ne doit pas pouvoir patcher (RoleChecker(lead))."""
    inc = _make_incident(db_session)
    headers = _login_role(api_client, role="analyst")
    r = api_client.patch(f"/incidents/{inc.id}", headers=headers, json={"status": "ack"})
    assert r.status_code == 403
