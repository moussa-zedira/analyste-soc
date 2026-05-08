"""Routes SSO OIDC: discovery providers, login flow PKCE, callback, admin CRUD.

Le login flow (GET providers, login, callback) est PUBLIC : pas de require_api_key.
La gestion des providers (POST/PUT/DELETE) exige require_admin.
"""

from __future__ import annotations

import json
import logging
import secrets
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from apps.api.auth import create_access_token, create_refresh_token
from apps.api.cache import get_redis_client
from apps.api.config import get_settings
from apps.api.db.session import get_db
from apps.api.middleware.rate_limit import limiter
from apps.api.models.sso import SSOProvider
from apps.api.security import require_admin
from apps.api.sso import (
    OIDCClient,
    discover_oidc,
    gen_code_verifier,
    provision_or_update_user,
    verify_id_token,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth/sso", tags=["SSO"])


_STATE_PREFIX = "sso:state:"


class SSOProviderPublic(BaseModel):
    """Vue publique : pas de client_secret."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    provider_type: str
    name: str
    enabled: bool


class SSOProviderAdmin(BaseModel):
    """Vue admin : client_secret masque."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    provider_type: str
    name: str
    issuer_url: str
    client_id: str
    client_secret: str = Field(default="***")
    scopes: str
    enabled: bool
    allowed_domains: list | None = None
    default_role: str
    group_to_role_mapping: dict | None = None
    created_at: datetime
    updated_at: datetime


class SSOProviderCreate(BaseModel):
    provider_type: str
    name: str
    issuer_url: str
    client_id: str
    client_secret: str
    scopes: str = "openid email profile"
    enabled: bool = True
    allowed_domains: list[str] | None = None
    default_role: str = "analyst"
    group_to_role_mapping: dict[str, str] | None = None


class SSOProviderUpdate(BaseModel):
    name: str | None = None
    issuer_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: str | None = None
    enabled: bool | None = None
    allowed_domains: list[str] | None = None
    default_role: str | None = None
    group_to_role_mapping: dict[str, str] | None = None


class SSOLoginInit(BaseModel):
    authorize_url: str
    state: str


class SSOCallbackResult(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    email: str
    role: str


def _to_admin_view(p: SSOProvider) -> SSOProviderAdmin:
    return SSOProviderAdmin(
        id=p.id,
        provider_type=p.provider_type,
        name=p.name,
        issuer_url=p.issuer_url,
        client_id=p.client_id,
        client_secret="***",
        scopes=p.scopes,
        enabled=p.enabled,
        allowed_domains=p.allowed_domains,
        default_role=p.default_role,
        group_to_role_mapping=p.group_to_role_mapping,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


def _redirect_uri_for(provider_id: str) -> str:
    base = get_settings().SSO_REDIRECT_BASE_URL.rstrip("/")
    return f"{base}/auth/sso/{provider_id}/callback"


def _store_state(state: str, code_verifier: str, provider_id: str) -> None:
    settings = get_settings()
    payload = json.dumps({"v": code_verifier, "p": provider_id})
    r = get_redis_client()
    if r is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO state store (Redis) unavailable",
        )
    r.setex(_STATE_PREFIX + state, settings.SSO_STATE_TTL_SECONDS, payload)


def _consume_state(state: str) -> dict:
    r = get_redis_client()
    if r is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="SSO state store (Redis) unavailable",
        )
    raw = r.get(_STATE_PREFIX + state)
    if raw is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired SSO state",
        )
    r.delete(_STATE_PREFIX + state)
    try:
        return json.loads(raw)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Corrupt SSO state",
        ) from e


# ---------------------------------------------------------------------------
# Public login flow
# ---------------------------------------------------------------------------


@router.get("/providers", response_model=list[SSOProviderPublic])
def list_providers_public(db: Session = Depends(get_db)) -> list[SSOProvider]:
    """Liste publique : champs strictement non-sensibles."""
    return db.query(SSOProvider).filter(SSOProvider.enabled.is_(True)).all()


@router.get("/{provider_id}/login", response_model=SSOLoginInit)
@limiter.limit("20/minute")
async def sso_login_init(
    request: Request,
    provider_id: str,
    db: Session = Depends(get_db),
) -> SSOLoginInit:
    """Construit l'URL d'authorize PKCE et stocke (state, code_verifier) en Redis."""
    provider = db.get(SSOProvider, provider_id)
    if provider is None or not provider.enabled:
        raise HTTPException(status_code=404, detail="SSO provider not found")

    state = secrets.token_urlsafe(32)
    code_verifier = gen_code_verifier(64)
    _store_state(state, code_verifier, provider_id)

    client = OIDCClient(provider)
    try:
        url = await client.authorize_url(
            state=state,
            code_verifier=code_verifier,
            redirect_uri=_redirect_uri_for(provider_id),
        )
    except Exception as e:
        logger.exception("sso_authorize_url_failed")
        raise HTTPException(status_code=502, detail=f"OIDC discovery failed: {e}")

    return SSOLoginInit(authorize_url=url, state=state)


@router.get("/{provider_id}/callback", response_model=SSOCallbackResult)
@limiter.limit("10/minute")
async def sso_callback(
    request: Request,
    provider_id: str,
    code: str,
    state: str,
    db: Session = Depends(get_db),
) -> SSOCallbackResult:
    """Callback IdP : exchange code -> verify id_token -> provision -> JWT local."""
    state_data = _consume_state(state)
    if state_data.get("p") != provider_id:
        raise HTTPException(status_code=400, detail="State/provider mismatch")
    code_verifier = state_data.get("v", "")

    provider = db.get(SSOProvider, provider_id)
    if provider is None or not provider.enabled:
        raise HTTPException(status_code=404, detail="SSO provider not found")

    client = OIDCClient(provider)
    try:
        token_resp = await client.exchange_code(
            code=code,
            code_verifier=code_verifier,
            redirect_uri=_redirect_uri_for(provider_id),
        )
    except Exception as e:
        logger.warning("sso_exchange_code_failed", extra={"provider_id": provider_id})
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {e}")

    id_token = token_resp.get("id_token")
    access_token = token_resp.get("access_token", "")
    if not id_token:
        raise HTTPException(status_code=400, detail="Missing id_token from IdP")

    discovery = await discover_oidc(provider.issuer_url)
    try:
        claims = await verify_id_token(
            id_token=id_token,
            issuer=discovery.get("issuer", provider.issuer_url),
            audience=provider.client_id,
            jwks_uri=discovery["jwks_uri"],
        )
    except Exception as e:
        logger.warning(
            "sso_id_token_invalid",
            extra={"provider_id": provider_id, "err": str(e)[:200]},
        )
        raise HTTPException(status_code=401, detail=f"id_token verification failed: {e}")

    raw_userinfo: dict | None = None
    if access_token and "groups" not in claims:
        try:
            raw_userinfo = await client.fetch_userinfo(access_token)
            if raw_userinfo and "groups" in raw_userinfo and "groups" not in claims:
                claims["groups"] = raw_userinfo["groups"]
        except Exception:
            logger.debug("sso_userinfo_fetch_failed", extra={"provider_id": provider_id})

    try:
        user = provision_or_update_user(db, claims, provider, raw_userinfo=raw_userinfo)
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))

    logger.info(
        "sso_login_success",
        extra={
            "provider_id": provider_id,
            "sub": claims.get("sub"),
            "email": user.email,
            "user_id": user.id,
            "role": user.role,
        },
    )

    jwt_claims = {"sub": user.id, "role": user.role}
    return SSOCallbackResult(
        access_token=create_access_token(jwt_claims),
        refresh_token=create_refresh_token(jwt_claims),
        token_type="bearer",
        user_id=user.id,
        email=user.email,
        role=user.role,
    )


# ---------------------------------------------------------------------------
# Admin CRUD
# ---------------------------------------------------------------------------


@router.post(
    "/providers",
    response_model=SSOProviderAdmin,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_admin)],
)
def create_provider(
    payload: SSOProviderCreate,
    db: Session = Depends(get_db),
) -> SSOProviderAdmin:
    if payload.provider_type not in ("azure", "google", "okta", "generic_oidc"):
        raise HTTPException(status_code=400, detail="Invalid provider_type")
    if payload.default_role not in ("analyst", "lead", "admin"):
        raise HTTPException(status_code=400, detail="Invalid default_role")

    now = datetime.now(UTC)
    provider = SSOProvider(
        id=str(uuid.uuid4()),
        provider_type=payload.provider_type,
        name=payload.name,
        issuer_url=payload.issuer_url.rstrip("/"),
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        scopes=payload.scopes,
        enabled=payload.enabled,
        allowed_domains=payload.allowed_domains,
        default_role=payload.default_role,
        group_to_role_mapping=payload.group_to_role_mapping,
        created_at=now,
        updated_at=now,
    )
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return _to_admin_view(provider)


@router.get(
    "/providers/{provider_id}",
    response_model=SSOProviderAdmin,
    dependencies=[Depends(require_admin)],
)
def get_provider_admin(provider_id: str, db: Session = Depends(get_db)) -> SSOProviderAdmin:
    provider = db.get(SSOProvider, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    return _to_admin_view(provider)


@router.put(
    "/providers/{provider_id}",
    response_model=SSOProviderAdmin,
    dependencies=[Depends(require_admin)],
)
def update_provider(
    provider_id: str,
    payload: SSOProviderUpdate,
    db: Session = Depends(get_db),
) -> SSOProviderAdmin:
    provider = db.get(SSOProvider, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="SSO provider not found")

    data = payload.model_dump(exclude_unset=True)
    if "default_role" in data and data["default_role"] not in ("analyst", "lead", "admin"):
        raise HTTPException(status_code=400, detail="Invalid default_role")
    if "issuer_url" in data and isinstance(data["issuer_url"], str):
        data["issuer_url"] = data["issuer_url"].rstrip("/")

    for k, v in data.items():
        setattr(provider, k, v)
    provider.updated_at = datetime.now(UTC)
    db.add(provider)
    db.commit()
    db.refresh(provider)
    return _to_admin_view(provider)


@router.delete(
    "/providers/{provider_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_admin)],
)
def delete_provider(provider_id: str, db: Session = Depends(get_db)) -> None:
    provider = db.get(SSOProvider, provider_id)
    if provider is None:
        raise HTTPException(status_code=404, detail="SSO provider not found")
    db.delete(provider)
    db.commit()
