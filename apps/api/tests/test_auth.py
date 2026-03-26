"""Tests d'authentification et de sécurité — JWT, mots de passe, clé API."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from jose import jwt, JWTError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_API_KEY = "test-key-auth"
TEST_JWT_SECRET = "test-jwt-secret"
TEST_JWT_ALGORITHM = "HS256"

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _set_env():
    """Injecte les variables d'environnement de test et vide le cache Settings."""
    old_vals = {}
    env_vars = {
        "API_KEY": TEST_API_KEY,
        "ENV": "dev",
        "JWT_SECRET_KEY": TEST_JWT_SECRET,
        "JWT_ALGORITHM": TEST_JWT_ALGORITHM,
        "JWT_EXPIRE_MINUTES": "30",
        "DATABASE_URL": "sqlite:///:memory:",
    }
    for key, value in env_vars.items():
        old_vals[key] = os.environ.get(key)
        os.environ[key] = value

    from apps.api.config import get_settings
    get_settings.cache_clear()

    yield

    for key, old in old_vals.items():
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Tests — mots de passe
# ---------------------------------------------------------------------------


def test_hash_and_verify_password():
    """Vérifie qu'un mot de passe haché peut être validé avec le mot de passe original."""
    from apps.api.auth import hash_password, verify_password

    plain = "S3cur3P@ssw0rd!"
    hashed = hash_password(plain)

    assert hashed != plain
    assert verify_password(plain, hashed) is True


def test_verify_wrong_password():
    """Vérifie qu'un mot de passe incorrect est rejeté lors de la vérification."""
    from apps.api.auth import hash_password, verify_password

    hashed = hash_password("correct-password")

    assert verify_password("wrong-password", hashed) is False


# ---------------------------------------------------------------------------
# Tests — JWT
# ---------------------------------------------------------------------------


def test_create_and_decode_token():
    """Vérifie la création et le décodage d'un jeton JWT avec le claim 'sub'."""
    from apps.api.auth import create_access_token, decode_token

    user_id = "user-abc-123"
    token = create_access_token({"sub": user_id})

    payload = decode_token(token)
    assert payload["sub"] == user_id
    assert "exp" in payload


def test_decode_expired_token():
    """Vérifie qu'un jeton JWT expiré lève une erreur lors du décodage."""
    expired_payload = {
        "sub": "user-expired",
        "exp": datetime.now(timezone.utc) - timedelta(hours=1),
    }
    token = jwt.encode(expired_payload, TEST_JWT_SECRET, algorithm=TEST_JWT_ALGORITHM)

    from apps.api.auth import decode_token

    with pytest.raises(JWTError):
        decode_token(token)


# ---------------------------------------------------------------------------
# Tests — clé API (security.require_api_key)
# ---------------------------------------------------------------------------


@pytest.fixture()
def security_app():
    """Application FastAPI minimale protégée par require_api_key."""
    from apps.api.security import require_api_key

    app = FastAPI()

    @app.get("/protected")
    def protected(request=None):
        require_api_key(request)
        return {"ok": True}

    # Use dependency injection properly
    from fastapi import Depends, Request

    @app.get("/dep-protected")
    def dep_protected(_: None = Depends(require_api_key)):
        return {"ok": True}

    with TestClient(app) as c:
        yield c


def test_require_api_key_valid(security_app: TestClient):
    """Vérifie qu'une clé API valide permet l'accès à la ressource protégée."""
    resp = security_app.get(
        "/dep-protected",
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_require_api_key_invalid(security_app: TestClient):
    """Vérifie qu'une clé API invalide retourne une erreur 401."""
    resp = security_app.get(
        "/dep-protected",
        headers={"X-API-Key": "mauvaise-cle"},
    )
    assert resp.status_code == 401


def test_require_api_key_jwt(security_app: TestClient):
    """Vérifie qu'un jeton JWT Bearer valide permet l'accès sans clé API."""
    from apps.api.auth import create_access_token

    token = create_access_token({"sub": "user-jwt"})
    resp = security_app.get(
        "/dep-protected",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


# ---------------------------------------------------------------------------
# Tests — hiérarchie des rôles
# ---------------------------------------------------------------------------


def test_role_hierarchy():
    """Vérifie que la hiérarchie des rôles respecte l'ordre analyst < lead < admin."""
    from apps.api.auth import ROLE_HIERARCHY

    assert ROLE_HIERARCHY["analyst"] < ROLE_HIERARCHY["lead"]
    assert ROLE_HIERARCHY["lead"] < ROLE_HIERARCHY["admin"]
    assert ROLE_HIERARCHY["analyst"] < ROLE_HIERARCHY["admin"]
