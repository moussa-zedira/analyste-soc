"""Module SSO OIDC : Azure AD, Google Workspace, Okta, generic OIDC.

Implementation:
- PKCE (S256) flow obligatoire (sec a l'etat de l'art)
- Verification ID token RS256 via JWKS distant cache
- JIT user provisioning + role mapping via groups claim
- Etat PKCE single-use stocke dans Redis (TTL 5 min)
"""

from __future__ import annotations

from apps.api.sso.oidc_client import (
    OIDCClient,
    code_challenge,
    discover_oidc,
    gen_code_verifier,
)
from apps.api.sso.provisioning import provision_or_update_user
from apps.api.sso.verify import verify_id_token

__all__ = [
    "OIDCClient",
    "discover_oidc",
    "verify_id_token",
    "provision_or_update_user",
    "gen_code_verifier",
    "code_challenge",
]
