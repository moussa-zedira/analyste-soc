"""Module 4 tests — bruteforce detection, dedup, incidents API."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from apps.api.db.base import Base

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

TEST_API_KEY = "test-key-module4"


@pytest.fixture(autouse=True)
def _set_env():
    """Inject test API key so security.py picks it up."""
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
    """TestClient with a fresh in-memory SQLite DB per test."""
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


def _get_admin_jwt(client: TestClient) -> dict:
    """Inscrire un admin et retourner les en-tetes JWT."""
    client.post(
        "/auth/register",
        json={
            "username": "admin_test",
            "email": "admin@test.com",
            "password": "AdminPass1!",
            "role": "admin",
        },
    )
    resp = client.post(
        "/auth/login",
        json={"username": "admin_test", "password": "AdminPass1!"},
    )
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}", "X-API-Key": TEST_API_KEY}


def _create_auth_fail_events(
    client: TestClient,
    ip: str,
    count: int,
    interval_seconds: int = 5,
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


def test_bruteforce_creates_incident(client: TestClient):
    """10+ auth.fail from same IP within 2 min => 1 incident."""
    _create_auth_fail_events(client, ip="10.0.0.1", count=12)

    resp = client.post("/rules/run", json={}, headers=_get_admin_jwt(client))
    assert resp.status_code == 200
    data = resp.json()
    assert data["rules_evaluated"] >= 1
    assert data["incidents_created"] >= 1

    # Verify incident via API
    resp = client.get("/incidents", headers=_auth())
    assert resp.status_code == 200
    incidents = resp.json()
    assert len(incidents) >= 1

    inc = incidents[0]
    assert inc["severity"] in ("high", "critical")
    assert inc["status"] == "open"
    assert inc["rule_id"] in ("bruteforce.v1", "auth-targeted.v1")
    assert "src_ip:" in inc["entity_key"]
    assert "10.0.0.1" in inc["title"]


# ---------------------------------------------------------------------------
# Test 2: dedup — second run creates no new incidents
# ---------------------------------------------------------------------------


def test_dedup_no_duplicate_incidents(client: TestClient):
    """Running rules twice on the same events must not create duplicates."""
    _create_auth_fail_events(client, ip="10.0.0.2", count=15)

    admin = _get_admin_jwt(client)
    resp1 = client.post("/rules/run", json={}, headers=admin)
    created_first = resp1.json()["incidents_created"]
    assert created_first >= 1

    resp2 = client.post("/rules/run", json={}, headers=admin)
    created_second = resp2.json()["incidents_created"]
    assert created_second == 0


# ---------------------------------------------------------------------------
# Test 3: incidents API — pagination, filters, detail with events
# ---------------------------------------------------------------------------


def test_incidents_api_pagination_filters_detail(client: TestClient):
    """Test list pagination, severity filter, and detail with linked events."""
    _create_auth_fail_events(client, ip="192.168.1.10", count=12)
    _create_auth_fail_events(client, ip="192.168.1.20", count=12)
    client.post("/rules/run", json={}, headers=_get_admin_jwt(client))

    # List all incidents
    resp = client.get("/incidents", headers=_auth())
    all_incidents = resp.json()
    assert len(all_incidents) >= 2

    # Pagination: limit=1
    resp = client.get("/incidents?limit=1&offset=0", headers=_auth())
    assert len(resp.json()) == 1

    # Filter by severity
    resp = client.get("/incidents?severity=high", headers=_auth())
    for inc in resp.json():
        assert inc["severity"] == "high"

    # Filter by status
    resp = client.get("/incidents?status_filter=open", headers=_auth())
    for inc in resp.json():
        assert inc["status"] == "open"

    # Detail with events
    incident_id = all_incidents[0]["id"]
    resp = client.get(f"/incidents/{incident_id}", headers=_auth())
    assert resp.status_code == 200
    detail = resp.json()
    assert "events" in detail
    assert len(detail["events"]) >= 1

    # 404 for unknown incident
    resp = client.get(f"/incidents/{uuid.uuid4()}", headers=_auth())
    assert resp.status_code == 404
