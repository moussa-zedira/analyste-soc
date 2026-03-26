"""API key and JWT verification dependency for FastAPI."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

from apps.api.config import get_settings


def require_api_key(request: Request) -> None:
    """FastAPI dependency that enforces authentication.

    Accepts EITHER:
    - X-API-Key header (legacy / service-to-service)
    - Authorization: Bearer <JWT> header (user auth)

    Uses constant-time comparison for API key to prevent timing attacks.
    For JWT, delegates to jose for verification.
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
