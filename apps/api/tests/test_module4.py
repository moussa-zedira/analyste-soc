"""Module 4 tests — bruteforce detection, dedup, incidents API.

Utilise les fixtures globales du conftest (Postgres + Redis) plutot que
SQLite : le schema de la plateforme utilise JSONB partout, incompatibles
avec SQLite.
"""

from __future__ import annotations

import os
import uuid

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth() -> dict:
    return {"X-API-Key": os.environ["API_KEY"]}


def _register_and_login(api_client: TestClient, *, role: str) -> dict:
    """Inscrire un utilisateur au role donne et retourner les en-tetes JWT."""
    suffix = uuid.uuid4().hex[:8]
    username = f"{role}_{suffix}"
    api_client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "AdminPass1!",
            "role": role,
        },
    )
    resp = api_client.post(
        "/auth/login",
        json={"username": username, "password": "AdminPass1!"},
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "X-API-Key": os.environ["API_KEY"]}


def _create_auth_fail_events(
    client: TestClient,
    ip: str,
    count: int,
    username: str = "admin",
) -> list[str]:
    """Helper: create `count` auth.fail events for the given IP."""
    ids = []
    for i in range(count):
        resp = client.post(
            "/events",
            json={
                "source": "sshd",
                "event_type": "auth.fail",
                "severity": "medium",
                "src_ip": ip,
                "username": username if i % 2 == 0 else f"user{i}",
                "message": f"Failed password for {username}",
            },
            headers=_auth(),
        )
        assert resp.status_code == 201, resp.text
        ids.append(resp.json()["id"])
    return ids


# ---------------------------------------------------------------------------
# Test 1: bruteforce detection creates an incident
# ---------------------------------------------------------------------------


def test_bruteforce_creates_incident(api_client: TestClient):
    """10+ auth.fail from same IP within 2 min => 1 incident."""
    _create_auth_fail_events(api_client, ip="10.0.0.1", count=12)

    resp = api_client.post(
        "/rules/run", json={}, headers=_register_and_login(api_client, role="admin")
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["rules_evaluated"] >= 1
    assert data["incidents_created"] >= 1

    # Verify incident via API
    resp = api_client.get("/incidents", headers=_auth())
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) >= 1

    bf_incidents = [
        i for i in incidents if i["rule_id"] in ("bruteforce.v1", "auth-targeted.v1")
    ]
    assert bf_incidents, f"no bruteforce incident in {[i['rule_id'] for i in incidents]}"
    inc = bf_incidents[0]
    assert inc["severity"] in ("high", "critical")
    assert inc["status"] == "open"
    assert "src_ip:" in inc["entity_key"]
    assert "10.0.0.1" in inc["title"]


# ---------------------------------------------------------------------------
# Test 2: dedup — second run creates no new incidents
# ---------------------------------------------------------------------------


def test_dedup_no_duplicate_incidents(api_client: TestClient):
    """Running rules twice on the same events must not create duplicates."""
    _create_auth_fail_events(api_client, ip="10.0.0.2", count=15)

    admin = _register_and_login(api_client, role="admin")
    resp1 = api_client.post("/rules/run", json={}, headers=admin)
    created_first = resp1.json()["incidents_created"]
    assert created_first >= 1

    resp2 = api_client.post("/rules/run", json={}, headers=admin)
    created_second = resp2.json()["incidents_created"]
    assert created_second == 0


# ---------------------------------------------------------------------------
# Test 3: incidents API — pagination, filters, detail with events
# ---------------------------------------------------------------------------


def test_incidents_api_pagination_filters_detail(api_client: TestClient):
    """Test list pagination, severity filter, and detail with linked events."""
    _create_auth_fail_events(api_client, ip="192.168.1.10", count=12)
    _create_auth_fail_events(api_client, ip="192.168.1.20", count=12)
    api_client.post(
        "/rules/run", json={}, headers=_register_and_login(api_client, role="admin")
    )

    # List all incidents
    resp = api_client.get("/incidents", headers=_auth())
    all_incidents = resp.json()
    assert len(all_incidents) >= 2

    # Pagination: limit=1
    resp = api_client.get("/incidents?limit=1&offset=0", headers=_auth())
    assert len(resp.json()) == 1

    # Filter by severity
    resp = api_client.get("/incidents?severity=high", headers=_auth())
    for inc in resp.json():
        assert inc["severity"] == "high"

    # Filter by status
    resp = api_client.get("/incidents?status_filter=open", headers=_auth())
    for inc in resp.json():
        assert inc["status"] == "open"

    # Detail with events
    incident_id = all_incidents[0]["id"]
    resp = api_client.get(f"/incidents/{incident_id}", headers=_auth())
    assert resp.status_code == 200
    detail = resp.json()
    assert "events" in detail
    assert len(detail["events"]) >= 1

    # 404 for unknown incident
    resp = api_client.get(f"/incidents/{uuid.uuid4()}", headers=_auth())
    assert resp.status_code == 404
