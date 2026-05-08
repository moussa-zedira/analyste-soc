"""Verification d'ID tokens OIDC (RS256 via JWKS distant)."""

from __future__ import annotations

import logging
import time

import httpx
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError

logger = logging.getLogger(__name__)


_JWKS_CACHE: dict[str, tuple[float, dict]] = {}
_JWKS_TTL = 86400.0  # 24h


async def _fetch_jwks(jwks_uri: str) -> dict:
    now = time.monotonic()
    cached = _JWKS_CACHE.get(jwks_uri)
    if cached and (now - cached[0]) < _JWKS_TTL:
        return cached[1]
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(jwks_uri)
        r.raise_for_status()
        doc = r.json()
    if not isinstance(doc, dict) or "keys" not in doc:
        raise ValueError(f"Invalid JWKS document at {jwks_uri}")
    _JWKS_CACHE[jwks_uri] = (now, doc)
    return doc


def _select_key(jwks: dict, kid: str | None) -> dict:
    keys = jwks.get("keys", [])
    if kid:
        for k in keys:
            if k.get("kid") == kid:
                return k
    if len(keys) == 1:
        return keys[0]
    raise ValueError(f"No JWKS key matches kid={kid!r}")


async def verify_id_token(
    id_token: str,
    issuer: str,
    audience: str,
    jwks_uri: str,
    leeway: int = 30,
) -> dict:
    """Verifie un ID token OIDC: signature, iss, aud, exp/nbf.

    - Telecharge JWKS (cache 24h),
    - Selectionne la cle via kid de l'en-tete,
    - Decode RS256 et impose les claims iss/aud,
    - Retourne les claims dict.

    Leve ``ValueError`` ou ``jose.JWTError`` en cas d'echec.
    """
    try:
        unverified_header = jwt.get_unverified_header(id_token)
    except JWTError as e:
        raise ValueError(f"Invalid JWT header: {e}") from e

    kid = unverified_header.get("kid")
    alg = unverified_header.get("alg", "RS256")
    if alg not in ("RS256", "RS384", "RS512", "ES256", "ES384"):
        raise ValueError(f"Disallowed JWT alg: {alg}")

    jwks = await _fetch_jwks(jwks_uri)
    key = _select_key(jwks, kid)

    try:
        claims = jwt.decode(
            id_token,
            key,
            algorithms=[alg],
            audience=audience,
            issuer=issuer.rstrip("/"),
            options={"verify_at_hash": False, "leeway": leeway},
        )
    except ExpiredSignatureError as e:
        raise ValueError(f"id_token expired: {e}") from e
    except JWTClaimsError as e:
        raise ValueError(f"id_token claim mismatch: {e}") from e
    except JWTError as e:
        raise ValueError(f"id_token signature invalid: {e}") from e

    return claims
