"""Tests des endpoints API — events, auth, incidents."""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.db.base import Base

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEST_API_KEY = "test-key-api"


@pytest.fixture(autouse=True)
def _set_env():
    """Injecter la cle API de test pour que security.py la prenne en compte."""
    old_key = os.environ.get("API_KEY")
    old_env = os.environ.get("ENV")
    os.environ["API_KEY"] = TEST_API_KEY
    os.environ["ENV"] = "dev"

    from apps.api.config import get_settings
    get_settings.cache_clear()

    yield

    if old_key is None:
        os.environ.pop("API_KEY", None)
    else:
        os.environ["API_KEY"] = old_key
    if old_env is None:
        os.environ.pop("ENV", None)
    else:
        os.environ["ENV"] = old_env
    get_settings.cache_clear()


@pytest.fixture()
def client():
    """TestClient avec une base SQLite en memoire par test."""
    from apps.api.db.session import get_db
    from apps.api.routes import events, incidents, rules, auth as auth_router

    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestSessionLocal = sessionmaker(
        bind=test_engine, autocommit=False, autoflush=False,
    )

    def _override_db():
        db = TestSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app = FastAPI()
    app.include_router(events.router, prefix="/events", tags=["events"])
    app.include_router(rules.router, prefix="/rules", tags=["rules"])
    app.include_router(incidents.router, prefix="/incidents", tags=["incidents"])
    app.include_router(auth_router.router, prefix="/auth", tags=["auth"])
    app.dependency_overrides[get_db] = _override_db

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


def _auth() -> dict:
    return {"X-API-Key": TEST_API_KEY}


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


def _create_incident_via_rules(client: TestClient) -> str:
    """Creer un incident via le moteur de regles et retourner son identifiant."""
    for _ in range(12):
        client.post(
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
    admin_headers = _get_admin_jwt(client)
    resp = client.post("/rules/run", json={}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["incidents_created"] >= 1

    resp = client.get("/incidents", headers=_auth())
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) >= 1
    return incidents[0]["id"]


def _get_admin_jwt(client: TestClient) -> dict:
    """Inscrire un utilisateur admin et retourner les en-tetes d'autorisation JWT."""
    client.post(
        "/auth/register",
        json={
            "username": "admin_user",
            "email": "admin@example.com",
            "password": "S3cur3Pass!",
            "role": "admin",
        },
    )
    resp = client.post(
        "/auth/login",
        json={"username": "admin_user", "password": "S3cur3Pass!"},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "X-API-Key": TEST_API_KEY}


def _get_lead_jwt(client: TestClient) -> dict:
    """Inscrire un utilisateur lead et retourner les en-tetes d'autorisation JWT."""
    client.post(
        "/auth/register",
        json={
            "username": "lead_user",
            "email": "lead@example.com",
            "password": "S3cur3Pass!",
            "role": "lead",
        },
    )
    resp = client.post(
        "/auth/login",
        json={"username": "lead_user", "password": "S3cur3Pass!"},
    )
    assert resp.status_code == 200
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "X-API-Key": TEST_API_KEY}


# ---------------------------------------------------------------------------
# Events API
# ---------------------------------------------------------------------------


def test_create_event(client: TestClient):
    """Creer un evenement valide doit retourner 201 avec les donnees."""
    resp = client.post("/events", json=_sample_event(), headers=_auth())
    assert resp.status_code == 201
    data = resp.json()
    assert "id" in data
    assert data["source"] == "firewall"
    assert data["severity"] == "high"
    assert data["event_type"] == "intrusion.attempt"


def test_create_event_missing_fields(client: TestClient):
    """Creer un evenement sans champ obligatoire doit retourner 422."""
    payload = {"source": "firewall"}  # manque event_type et severity
    resp = client.post("/events", json=payload, headers=_auth())
    assert resp.status_code == 422


def test_list_events(client: TestClient):
    """Lister les evenements doit retourner une liste."""
    client.post("/events", json=_sample_event(), headers=_auth())
    client.post(
        "/events",
        json=_sample_event(source="ids", severity="low"),
        headers=_auth(),
    )
    resp = client.get("/events", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 2


def test_list_events_pagination(client: TestClient):
    """Lister avec limit=1 doit retourner exactement 1 evenement."""
    client.post("/events", json=_sample_event(), headers=_auth())
    client.post(
        "/events",
        json=_sample_event(source="ids"),
        headers=_auth(),
    )
    resp = client.get("/events?limit=1", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1


def test_list_events_filter_severity(client: TestClient):
    """Filtrer par severity=high ne doit retourner que les evenements high."""
    client.post("/events", json=_sample_event(severity="high"), headers=_auth())
    client.post("/events", json=_sample_event(severity="low"), headers=_auth())
    client.post("/events", json=_sample_event(severity="medium"), headers=_auth())

    resp = client.get("/events?severity=high", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 1
    for event in data:
        assert event["severity"] == "high"


def test_get_event_detail(client: TestClient):
    """Recuperer un evenement par son identifiant doit retourner l'evenement."""
    resp = client.post("/events", json=_sample_event(), headers=_auth())
    event_id = resp.json()["id"]

    resp = client.get(f"/events/{event_id}", headers=_auth())
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == event_id
    assert data["source"] == "firewall"


def test_get_event_not_found(client: TestClient):
    """Recuperer un evenement inexistant doit retourner 404."""
    fake_id = str(uuid.uuid4())
    resp = client.get(f"/events/{fake_id}", headers=_auth())
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


def test_no_api_key_returns_401(client: TestClient):
    """Une requete sans cle API ni JWT doit retourner 401."""
    resp = client.get("/events")
    assert resp.status_code == 401


def test_wrong_api_key_returns_401(client: TestClient):
    """Une requete avec une mauvaise cle API doit retourner 401."""
    resp = client.get("/events", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Incidents API
# ---------------------------------------------------------------------------


def test_update_incident_status(client: TestClient):
    """Mettre a jour le statut d'un incident doit changer son statut."""
    incident_id = _create_incident_via_rules(client)
    headers = _get_lead_jwt(client)

    # Transition open -> ack
    resp = client.patch(
        f"/incidents/{incident_id}",
        json={"status": "ack"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ack"

    # Transition ack -> closed
    resp = client.patch(
        f"/incidents/{incident_id}",
        json={"status": "closed"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "closed"


def test_update_incident_not_found(client: TestClient):
    """Mettre a jour un incident inexistant doit retourner 404."""
    headers = _get_lead_jwt(client)
    fake_id = str(uuid.uuid4())
    resp = client.patch(
        f"/incidents/{fake_id}",
        json={"status": "ack"},
        headers=headers,
    )
    assert resp.status_code == 404
