"""Client OIDC + helpers PKCE.

Default scope OIDC = "openid email profile".
Pour recuperer les groupes :
  - Azure AD : ajouter "openid profile email" et configurer "groups" claim dans le manifest
    (alternative: "User.Read.All" via Microsoft Graph, mais hors PKCE pur).
  - Google Workspace : la liste de groupes n'est pas dans l'id_token ;
    requiert l'API Admin SDK (hors scope OIDC).
  - Okta : ajouter "groups" au scope + configurer le claim dans l'authorization server.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from urllib.parse import urlencode

import httpx

from apps.api.models.sso import SSOProvider

logger = logging.getLogger(__name__)


_DISCOVERY_CACHE: dict[str, tuple[float, dict]] = {}
_DISCOVERY_TTL = 3600.0  # 1h


def _normalize_issuer(issuer_url: str) -> str:
    return issuer_url.rstrip("/")


async def discover_oidc(issuer_url: str) -> dict:
    """GET {issuer}/.well-known/openid-configuration. Cache 1h."""
    issuer = _normalize_issuer(issuer_url)
    now = time.monotonic()
    cached = _DISCOVERY_CACHE.get(issuer)
    if cached and (now - cached[0]) < _DISCOVERY_TTL:
        return cached[1]

    url = f"{issuer}/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(url)
        r.raise_for_status()
        doc = r.json()

    if not isinstance(doc, dict) or "authorization_endpoint" not in doc:
        raise ValueError(f"Invalid OIDC discovery document at {url}")

    _DISCOVERY_CACHE[issuer] = (now, doc)
    return doc


# Alias historique (compat tests)
discover = discover_oidc


def gen_code_verifier(length: int = 64) -> str:
    """Genere un PKCE code_verifier URL-safe (43 a 128 chars).

    RFC 7636 sec 4.1: 43 <= length <= 128, alphabet [A-Z a-z 0-9 - . _ ~].
    secrets.token_urlsafe(n) produit ceil(4n/3) chars dans [A-Z a-z 0-9 - _].
    """
    if not 43 <= length <= 128:
        raise ValueError("code_verifier length must be in [43, 128]")
    n_bytes = (length * 3) // 4 + 1
    raw = secrets.token_urlsafe(n_bytes)
    return raw[:length]


def code_challenge(verifier: str) -> str:
    """SHA256 base64url no-pad du verifier (PKCE S256, RFC 7636 sec 4.2)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


class OIDCClient:
    """Client OIDC PKCE pour un SSOProvider donne."""

    def __init__(self, provider: SSOProvider) -> None:
        self.provider = provider
        self._discovery: dict | None = None

    async def _ensure_discovery(self) -> dict:
        if self._discovery is None:
            self._discovery = await discover_oidc(self.provider.issuer_url)
        return self._discovery

    async def authorize_url(self, state: str, code_verifier: str, redirect_uri: str) -> str:
        """Construit l'URL d'authorize avec PKCE S256."""
        disco = await self._ensure_discovery()
        params = {
            "response_type": "code",
            "client_id": self.provider.client_id,
            "redirect_uri": redirect_uri,
            "scope": self.provider.scopes or "openid email profile",
            "state": state,
            "code_challenge": code_challenge(code_verifier),
            "code_challenge_method": "S256",
        }
        return f"{disco['authorization_endpoint']}?{urlencode(params)}"

    async def exchange_code(self, code: str, code_verifier: str, redirect_uri: str) -> dict:
        """POST token endpoint -> {access_token, id_token, refresh_token?, ...}."""
        disco = await self._ensure_discovery()
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.provider.client_id,
            "client_secret": self.provider.client_secret,
            "code_verifier": code_verifier,
        }
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                disco["token_endpoint"],
                data=data,
                headers={"Accept": "application/json"},
            )
            if r.status_code >= 400:
                logger.warning(
                    "sso_token_exchange_failed",
                    extra={
                        "provider_id": self.provider.id,
                        "status": r.status_code,
                    },
                )
                r.raise_for_status()
            return r.json()

    async def fetch_userinfo(self, access_token: str) -> dict:
        """GET userinfo_endpoint avec Bearer access_token."""
        disco = await self._ensure_discovery()
        userinfo_url = disco.get("userinfo_endpoint")
        if not userinfo_url:
            return {}
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            r.raise_for_status()
            return r.json()
