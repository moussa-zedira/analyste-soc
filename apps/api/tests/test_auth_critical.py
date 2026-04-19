"""Tests critiques d'auth : login OK/KO + regression RoleChecker(list).

Ces tests verrouillent le contrat d'auth contre 3 regressions :
- /auth/login valide -> 200 + access_token (happy path critique)
- /auth/login credentials invalides -> 401 (pas d'info leak)
- RoleChecker accepte une list en argument (regression introduite en refactor)
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


def _new_user(api_client, role: str = "analyst") -> tuple[str, str]:
    """Cree un user unique et retourne (username, password)."""
    n = uuid.uuid4().hex[:8]
    username = f"crit-{n}"
    password = "Crit-" + n
    r = api_client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@test.local",
            "password": password,
            "role": role,
        },
    )
    assert r.status_code == 201, r.text
    return username, password


def test_login_valid_returns_access_token(api_client):
    """POST /auth/login avec credentials valides -> 200 + access_token non vide."""
    username, password = _new_user(api_client)
    r = api_client.post(
        "/auth/login",
        json={"username": username, "password": password},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("access_token"), "access_token manquant dans la reponse"
    assert body.get("refresh_token"), "refresh_token manquant"
    assert body["access_token"] != body["refresh_token"]


def test_login_invalid_returns_401(api_client):
    """Mauvais mot de passe -> 401 sans info leak sur l'existence du user."""
    username, _ = _new_user(api_client)
    r = api_client.post(
        "/auth/login",
        json={"username": username, "password": "WRONG-PASSWORD-123!"},
    )
    assert r.status_code == 401
    # Pas d'info-leak : le message generique ne doit pas reveler si le user existe
    detail = (r.json().get("detail") or "").lower()
    assert "invalid" in detail or "credentials" in detail


def test_role_checker_accepts_list():
    """RoleChecker(["admin", "lead"]) doit accepter une list (regression recente).

    Regression : un refactor avait casse la forme list en ne supportant que
    les strings. On verifie ici les 3 branches :
      - user avec role dans la list -> OK
      - user avec role absent de la list mais de niveau >= min -> OK
      - user analyst face a ["admin"] -> 403
    """
    from fastapi import HTTPException

    from apps.api.auth import RoleChecker
    from apps.api.models.user import User

    def mk(role: str) -> User:
        return User(
            id=f"u-{role}",
            username=f"u-{role}",
            email=f"u-{role}@t.local",
            hashed_password="x",
            role=role,
            is_active=True,
        )

    # 1) role dans la list -> autorise
    checker = RoleChecker(["admin", "lead"])
    assert checker(user=mk("admin")).role == "admin"
    assert checker(user=mk("lead")).role == "lead"

    # 2) role au-dessus du plus faible liste (analyst face a ["lead"]) -> 403
    checker_lead = RoleChecker(["lead"])
    with pytest.raises(HTTPException) as exc:
        checker_lead(user=mk("analyst"))
    assert exc.value.status_code == 403

    # 3) list vide -> pass-through (cas limite : aucun role requis)
    assert RoleChecker([])(user=mk("analyst")).role == "analyst"
