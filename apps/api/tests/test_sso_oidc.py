"""Tests smoke OIDC : PKCE helpers + discovery + verification."""

from __future__ import annotations

import base64
import hashlib
import re
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from jose import jwt

from apps.api.sso import verify as verify_mod
from apps.api.sso.oidc_client import (
    code_challenge,
    discover_oidc,
    gen_code_verifier,
)

PKCE_RE = re.compile(r"^[A-Za-z0-9._~-]+$")


def test_gen_code_verifier_length_and_charset():
    for length in (43, 64, 128):
        v = gen_code_verifier(length)
        assert len(v) == length
        assert PKCE_RE.match(v), f"verifier non URL-safe: {v!r}"


def test_gen_code_verifier_invalid_length():
    with pytest.raises(ValueError):
        gen_code_verifier(42)
    with pytest.raises(ValueError):
        gen_code_verifier(129)


def test_code_challenge_s256_known_vector():
    # RFC 7636 Appendix B: example test vector
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert code_challenge(verifier) == expected


def test_code_challenge_matches_manual_sha256():
    v = gen_code_verifier(64)
    digest = hashlib.sha256(v.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    assert code_challenge(v) == expected


@pytest.mark.asyncio
async def test_discover_oidc_parses_mock(monkeypatch):
    sample_doc = {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
        "token_endpoint": "https://idp.example.com/oauth2/token",
        "userinfo_endpoint": "https://idp.example.com/oauth2/userinfo",
        "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
    }

    captured = {}

    class _MockResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return sample_doc

    class _MockClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url):
            captured["url"] = url
            return _MockResp()

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)
    # Bypass cache : utilise un issuer unique
    issuer = f"https://idp-{int(time.time() * 1000)}.example.com"
    doc = await discover_oidc(issuer)

    assert doc["token_endpoint"] == sample_doc["token_endpoint"]
    assert captured["url"] == f"{issuer}/.well-known/openid-configuration"


@pytest.mark.asyncio
async def test_discover_oidc_strips_trailing_slash(monkeypatch):
    sample_doc = {
        "issuer": "https://idp.example.com",
        "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
        "token_endpoint": "https://idp.example.com/oauth2/token",
        "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
    }

    captured = {}

    class _MockResp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return sample_doc

    class _MockClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return None

        async def get(self, url):
            captured["url"] = url
            return _MockResp()

    monkeypatch.setattr(httpx, "AsyncClient", _MockClient)
    issuer = f"https://idp-slash-{int(time.time() * 1000)}.example.com/"
    await discover_oidc(issuer)
    assert captured["url"].endswith("/.well-known/openid-configuration")
    assert "//.well-known" not in captured["url"]


@pytest.mark.asyncio
async def test_verify_id_token_rejects_expired(monkeypatch):
    """Token RS256 expire -> ValueError."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        pytest.skip("cryptography not available")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    public_numbers = private_key.public_key().public_numbers()

    def _b64u_uint(n: int) -> str:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    jwk = {
        "kty": "RSA",
        "kid": "test-kid-1",
        "use": "sig",
        "alg": "RS256",
        "n": _b64u_uint(public_numbers.n),
        "e": _b64u_uint(public_numbers.e),
    }

    issuer = "https://idp.test"
    audience = "test-client-id"

    now = datetime.now(UTC)
    expired_claims = {
        "iss": issuer,
        "aud": audience,
        "sub": "user-123",
        "email": "u@test",
        "iat": int((now - timedelta(hours=2)).timestamp()),
        "exp": int((now - timedelta(hours=1)).timestamp()),
    }
    id_token = jwt.encode(
        expired_claims,
        pem_priv.decode("ascii"),
        algorithm="RS256",
        headers={"kid": "test-kid-1"},
    )

    async def _mock_fetch_jwks(jwks_uri: str):
        return {"keys": [jwk]}

    monkeypatch.setattr(verify_mod, "_fetch_jwks", _mock_fetch_jwks)

    with pytest.raises(ValueError, match="expired"):
        await verify_mod.verify_id_token(
            id_token=id_token,
            issuer=issuer,
            audience=audience,
            jwks_uri="https://idp.test/jwks",
            leeway=0,
        )


@pytest.mark.asyncio
async def test_verify_id_token_accepts_valid(monkeypatch):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        pytest.skip("cryptography not available")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pubn = private_key.public_key().public_numbers()

    def _b64u_uint(n: int) -> str:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

    jwk = {
        "kty": "RSA",
        "kid": "k2",
        "use": "sig",
        "alg": "RS256",
        "n": _b64u_uint(pubn.n),
        "e": _b64u_uint(pubn.e),
    }

    issuer = "https://idp.test"
    audience = "client-xyz"
    now = datetime.now(UTC)
    claims = {
        "iss": issuer,
        "aud": audience,
        "sub": "user-1",
        "email": "u@example.com",
        "email_verified": True,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
        "groups": ["sec-admins"],
    }
    id_token = jwt.encode(
        claims,
        pem_priv.decode("ascii"),
        algorithm="RS256",
        headers={"kid": "k2"},
    )

    async def _mock_fetch_jwks(jwks_uri: str):
        return {"keys": [jwk]}

    monkeypatch.setattr(verify_mod, "_fetch_jwks", _mock_fetch_jwks)

    out = await verify_mod.verify_id_token(
        id_token=id_token,
        issuer=issuer,
        audience=audience,
        jwks_uri="https://idp.test/jwks",
    )
    assert out["sub"] == "user-1"
    assert out["groups"] == ["sec-admins"]
