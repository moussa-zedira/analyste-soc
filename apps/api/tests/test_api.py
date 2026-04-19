"""Tests des endpoints API — events, auth, incidents.

Utilise les fixtures globales du conftest (Postgres + Redis testcontainers
ou via TEST_DATABASE_URL / TEST_REDIS_URL). Evite SQLite : le schema contient
des colonnes JSONB (sso_providers, incidents, etc.) incompatibles avec SQLite.
"""

from __future__ import annotations

import os
import uuid

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth() -> dict:
    """Header X-API-Key base sur l'API_KEY genere par le conftest."""
    return {"X-API-Key": os.environ["API_KEY"]}


def _sample_event(**overrides) -> dict:
    """Retourner un payload d'evenement valide avec surcharges optionnelles."""
    base = {
        "source": "firewall",
        "event_type": "intrusion.attempt",
        "severity": "high",
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.5",
        "username": "attacker",
        "message": "Tentative d'intrusion detectee",
    }
    base.update(overrides)
    return base


def _register_and_login(api_client: TestClient, *, role: str) -> dict:
    """Inscrire un utilisateur au role donne et retourner les en-tetes JWT."""
    suffix = uuid.uuid4().hex[:8]
    username = f"{role}_{suffix}"
    api_client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": "S3cur3Pass!",
            "role": role,
        },
    )
    resp = api_client.post(
        "/auth/login",
        json={"username": username, "password": "S3cur3Pass!"},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "X-API-Key": os.environ["API_KEY"]}


def _create_incident_via_rules(api_client: TestClient) -> str:
    """Creer un incident via le moteur de regles et retourner son identifiant."""
    for _ in range(12):
        api_client.post(
            "/events",
            json={
                "source": "sshd",
                "event_type": "auth.fail",
                "severity": "medium",
                "src_ip": "10.0.0.99",
                "username": "admin",
                "message": "Failed password for admin",
            },
            headers=_auth(),
        )
    admin_headers = _register_and_login(api_client, role="admin")
    resp = api_client.post("/rules/run", json={}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["incidents_created"] >= 1

    resp = api_client.get("/incidents", headers=_auth())
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) >= 1
    return incidents[0]["id"]


# ---------------------------------------------------------------------------
# Events API
# ---------------------------------------------------------------------------


def test_create_event(api_client: TestClient):
    """Creer un evenement valide doit retourner 201 avec les donnees."""
    resp = api_client.post("/events", json=_sample_event(), headers=_auth())
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["source"] == "firewall"
    assert data["severity"] == "high"
    assert data["event_type"] == "intrusion.attempt"


def test_create_event_missing_fields(api_client: TestClient):
    """Creer un evenement sans champ obligatoire doit retourner 422."""
    payload = {"source": "firewall"}  # manque event_type et severity
    resp = api_client.post("/events", json=payload, headers=_auth())
    assert resp.status_code == 422


def test_list_events(api_client: TestClient):
    """Lister les evenements doit retourner une liste."""
    api_client.post("/events", json=_sample_event(), headers=_auth())
    api_client.post(
        "/events",
        json=_sample_event(source="ids", severity="low"),
        headers=_auth(),
    )
    resp = api_client.get("/events", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 2


def test_list_events_pagination(api_client: TestClient):
    """Lister avec limit=1 doit retourner exactement 1 evenement."""
    api_client.post("/events", json=_sample_event(), headers=_auth())
    api_client.post(
        "/events",
        json=_sample_event(source="ids"),
        headers=_auth(),
    )
    resp = api_client.get("/events?limit=1", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1


def test_list_events_filter_severity(api_client: TestClient):
    """Filtrer par severity=high ne doit retourner que les evenements high."""
    api_client.post("/events", json=_sample_event(severity="high"), headers=_auth())
    api_client.post("/events", json=_sample_event(severity="low"), headers=_auth())
    api_client.post("/events", json=_sample_event(severity="medium"), headers=_auth())

    resp = api_client.get("/events?severity=high", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    for event in data:
        assert event["severity"] == "high"


def test_get_event_detail(api_client: TestClient):
    """Recuperer un evenement par son identifiant doit retourner l'evenement."""
    resp = api_client.post("/events", json=_sample_event(), headers=_auth())
    event_id = resp.json()["id"]

    resp = api_client.get(f"/events/{event_id}", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == event_id
    assert data["source"] == "firewall"


def test_get_event_not_found(api_client: TestClient):
    """Recuperer un evenement inexistant doit retourner 404."""
    fake_id = str(uuid.uuid4())
    resp = api_client.get(f"/events/{fake_id}", headers=_auth())
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_no_api_key_returns_401(api_client: TestClient):
    """Une requete sans cle API ni JWT doit retourner 401.

    Le fixture api_client ajoute par defaut la cle API aux headers du client :
    on cree un nouveau client sans pour reproduire le cas reel.
    """
    # Retire explicitement la cle API par defaut injectee par la fixture.
    headers_backup = dict(api_client.headers)
    api_client.headers.pop("X-API-Key", None)
    try:
        resp = api_client.get("/events")
        assert resp.status_code == 401
    finally:
        api_client.headers.update(headers_backup)


def test_wrong_api_key_returns_401(api_client: TestClient):
    """Une requete avec une mauvaise cle API doit retourner 401."""
    headers_backup = dict(api_client.headers)
    api_client.headers.pop("X-API-Key", None)
    try:
        resp = api_client.get("/events", headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401
    finally:
        api_client.headers.update(headers_backup)


# ---------------------------------------------------------------------------
# Incidents API
# ---------------------------------------------------------------------------


def test_update_incident_status(api_client: TestClient):
    """Mettre a jour le statut d'un incident doit changer son statut."""
    incident_id = _create_incident_via_rules(api_client)
    headers = _register_and_login(api_client, role="lead")

    # Transition open -> ack
    resp = api_client.patch(
        f"/incidents/{incident_id}",
        json={"status": "ack"},
        headers=headers,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "ack"

    # Transition ack -> closed
    resp = api_client.patch(
        f"/incidents/{incident_id}",
        json={"status": "closed"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "closed"


def test_update_incident_not_found(api_client: TestClient):
    """Mettre a jour un incident inexistant doit retourner 404."""
    headers = _register_and_login(api_client, role="lead")
    fake_id = str(uuid.uuid4())
    resp = api_client.patch(
        f"/incidents/{fake_id}",
        json={"status": "ack"},
        headers=headers,
    )
    assert resp.status_code == 404
