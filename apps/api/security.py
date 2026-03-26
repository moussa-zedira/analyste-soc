"""Dépendance de vérification par clé API et JWT pour FastAPI."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

from apps.api.config import get_settings


def require_api_key(request: Request) -> None:
    """Dépendance FastAPI qui impose l'authentification.

    Accepte soit X-API-Key (service-à-service), soit Authorization: Bearer <JWT>.
    Utilise une comparaison à temps constant pour la clé API.
    """
    settings = get_settings()

    # Try API key first
    provided_key: str = request.headers.get(settings.API_KEY_HEADER, "")
    if provided_key:
        expected_key: str = settings.effective_api_key
        if hmac.compare_digest(
            provided_key.encode("utf-8"),
            expected_key.encode("utf-8"),
        ):
            return  # Authenticated via API key

    # Try JWT Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            from jose import jwt, JWTError

            jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
            return  # Authenticated via JWT
        except (JWTError, Exception):
            pass

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized",
    )
