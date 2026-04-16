"""Tests d'integration auth : register, login, refresh, logout, revocation."""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


def _new_user_payload(role: str = "analyst") -> dict:
    """Genere un payload register unique."""
    n = uuid.uuid4().hex[:8]
    return {
        "username": f"u-{n}",
        "email": f"u-{n}@test.local",
        "password": "S3cret-" + n,
        "role": role,
    }


def _register_and_login(client, role: str = "analyst") -> tuple[dict, dict]:
    """Inscrit un user puis login. Retourne (payload, token_pair)."""
    payload = _new_user_payload(role=role)
    r = client.post("/auth/register", json=payload)
    assert r.status_code == 201, r.text
    r = client.post(
        "/auth/login", json={"username": payload["username"], "password": payload["password"]}
    )
    assert r.status_code == 200, r.text
    return payload, r.json()


def test_register_creates_user_and_login_returns_pair(api_client):
    """Register reussi -> 201 ; login renvoie access + refresh."""
    _, tokens = _register_and_login(api_client)
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    assert tokens["access_token"] != tokens["refresh_token"]


def test_register_duplicate_returns_409(api_client):
    """Un username deja pris -> 409 conflict."""
    payload = _new_user_payload()
    assert api_client.post("/auth/register", json=payload).status_code == 201
    r = api_client.post("/auth/register", json=payload)
    assert r.status_code == 409


def test_login_wrong_password_returns_401(api_client):
    """Mauvais mot de passe = 401 sans details."""
    payload, _ = _register_and_login(api_client)
    r = api_client.post(
        "/auth/login", json={"username": payload["username"], "password": "nope"}
    )
    assert r.status_code == 401


def test_me_returns_current_user(api_client):
    """/auth/me renvoie le user du JWT."""
    payload, tokens = _register_and_login(api_client)
    r = api_client.get(
        "/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert r.status_code == 200
    assert r.json()["username"] == payload["username"]


def test_me_rejects_refresh_token(api_client):
    """Un refresh ne doit PAS etre accepte comme access (verification du claim type)."""
    _, tokens = _register_and_login(api_client)
    r = api_client.get(
        "/auth/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"}
    )
    assert r.status_code == 401


def test_refresh_rotates_tokens(api_client):
    """/auth/refresh renvoie une nouvelle paire et revoque l'ancien refresh."""
    _, tokens = _register_and_login(api_client)
    r = api_client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200, r.text
    new_tokens = r.json()
    assert new_tokens["access_token"] != tokens["access_token"]
    assert new_tokens["refresh_token"] != tokens["refresh_token"]

    # Le precedent refresh est revoque -> 401 sur reuse.
    r2 = api_client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert r2.status_code == 401


def test_logout_revokes_access_token(api_client):
    """Apres logout, le meme access token est rejete par /me."""
    _, tokens = _register_and_login(api_client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    assert api_client.get("/auth/me", headers=headers).status_code == 200

    r = api_client.post(
        "/auth/logout",
        headers=headers,
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert r.status_code == 204

    assert api_client.get("/auth/me", headers=headers).status_code == 401


def test_role_hierarchy_enforced_on_admin_routes(api_client):
    """Un analyst ne peut pas atteindre /admin (qui exige role admin)."""
    _, tokens = _register_and_login(api_client, role="analyst")
    r = api_client.get(
        "/admin/users", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert r.status_code in (401, 403)
