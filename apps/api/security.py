"""Dépendance de vérification par clé API et JWT pour FastAPI."""

from __future__ import annotations

import hmac
from typing import Iterable, Optional

from fastapi import HTTPException, Request, status

from apps.api.config import get_settings


def _decode_jwt(token: str) -> Optional[dict]:
    """Decode a JWT or return None if invalid."""
    settings = get_settings()
    try:
        from jose import jwt, JWTError

        return jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except (JWTError, Exception):
        return None


def _check_api_key(request: Request) -> bool:
    settings = get_settings()
    provided_key: str = request.headers.get(settings.API_KEY_HEADER, "")
    if not provided_key:
        return False
    expected_key: str = settings.effective_api_key
    return hmac.compare_digest(
        provided_key.encode("utf-8"),
        expected_key.encode("utf-8"),
    )


def _extract_jwt_payload(request: Request) -> Optional[dict]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return _decode_jwt(auth_header[7:])


def require_api_key(request: Request) -> None:
    """Dépendance FastAPI qui impose l'authentification.

    Accepte soit X-API-Key (service-à-service), soit Authorization: Bearer <JWT>.
    Utilise une comparaison à temps constant pour la clé API.
    """
    if _check_api_key(request):
        return
    if _extract_jwt_payload(request) is not None:
        return

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
    )


def require_roles(*roles: str):
    """Dependency factory: enforce that the JWT bearer holds one of `roles`.

    The shared API key (service-a-service) is accepted as full-admin for
    automation purposes. Pour un endpoint user-facing, exiger explicitement
    un JWT en passant ``api_key_allowed=False`` via require_roles_strict.
    """
    allowed = frozenset(roles)

    def _dep(request: Request) -> None:
        if _check_api_key(request):
            return  # service-to-service traffic = trusted
        payload = _extract_jwt_payload(request)
        if payload is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
            )
        role = payload.get("role", "")
        if role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{role}' not authorized (requires one of {sorted(allowed)})",
            )

    return _dep


def require_admin(request: Request) -> None:
    """Shortcut: only admin users (or service API key) allowed."""
    return require_roles("admin")(request)

