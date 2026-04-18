"""JIT user provisioning + role mapping depuis claims OIDC."""

from __future__ import annotations

import json
import logging
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from apps.api.auth import hash_password
from apps.api.models.sso import SSOProvider, SSOSession
from apps.api.models.user import User

logger = logging.getLogger(__name__)


_VALID_ROLES = ("analyst", "lead", "admin")


def _extract_groups(claims: dict) -> list[str]:
    raw = claims.get("groups") or claims.get("roles") or []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(g) for g in raw if g]
    return []


def _resolve_role(groups: list[str], provider: SSOProvider) -> str:
    mapping = provider.group_to_role_mapping or {}
    for g in groups:
        role = mapping.get(g)
        if role in _VALID_ROLES:
            return role
    default = provider.default_role or "analyst"
    return default if default in _VALID_ROLES else "analyst"


def _email_allowed(email: str, provider: SSOProvider) -> bool:
    domains = provider.allowed_domains or []
    if not domains:
        return True
    if "@" not in email:
        return False
    domain = email.rsplit("@", 1)[1].lower()
    return domain in {d.lower() for d in domains}


def _username_from_email(email: str) -> str:
    base = email.split("@", 1)[0] if "@" in email else email
    return base.replace(" ", "_")[:255] or f"sso_{uuid.uuid4().hex[:8]}"


def provision_or_update_user(
    db: Session,
    claims: dict,
    provider: SSOProvider,
    raw_userinfo: dict | None = None,
) -> User:
    """Resoud ou cree l'utilisateur local a partir de claims OIDC.

    Lookup chain :
    1. SSOSession (provider_id, sub) -> user existant -> update last_login + groups.
    2. Sinon, controle email_verified + allowed_domains.
    3. Lookup User par email (link compte local) -> reuse + nouvelle SSOSession.
    4. Sinon, JIT create User avec role calcule.
    """
    sub = claims.get("sub", "")
    email = (claims.get("email") or "").lower()
    groups = _extract_groups(claims)

    if not sub:
        raise ValueError("OIDC claims missing 'sub'")

    session = (
        db.query(SSOSession)
        .filter(SSOSession.provider_id == provider.id, SSOSession.id_token_sub == sub)
        .first()
    )

    now = datetime.now(timezone.utc)

    if session is not None:
        user = db.get(User, session.user_id)
        if user is None:
            db.delete(session)
            db.flush()
        else:
            session.last_login = now
            session.id_token_groups = groups
            if email:
                session.id_token_email = email
            if raw_userinfo is not None:
                session.raw_userinfo_json = json.dumps(raw_userinfo)
            db.add(session)
            db.commit()
            db.refresh(user)
            logger.info(
                "sso_login_existing",
                extra={
                    "provider_id": provider.id,
                    "sub": sub,
                    "email": email,
                    "user_id": user.id,
                },
            )
            return user

    if not email:
        raise ValueError("OIDC claims missing 'email'")
    email_verified = claims.get("email_verified")
    if email_verified is False:
        raise ValueError("Email not verified by IdP")
    if not _email_allowed(email, provider):
        raise ValueError(f"Email domain not in allowed_domains: {email}")

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        username = _username_from_email(email)
        existing = db.query(User).filter(User.username == username).first()
        if existing is not None:
            username = f"{username}_{uuid.uuid4().hex[:6]}"
        user = User(
            id=str(uuid.uuid4()),
            username=username,
            email=email,
            hashed_password=hash_password(secrets.token_urlsafe(32)),
            role=_resolve_role(groups, provider),
            is_active=True,
            created_at=now,
        )
        db.add(user)
        db.flush()
        logger.info(
            "sso_jit_provisioned",
            extra={
                "provider_id": provider.id,
                "sub": sub,
                "email": email,
                "user_id": user.id,
                "role": user.role,
            },
        )
    else:
        logger.info(
            "sso_linked_existing_user",
            extra={
                "provider_id": provider.id,
                "sub": sub,
                "email": email,
                "user_id": user.id,
            },
        )

    new_session = SSOSession(
        id=str(uuid.uuid4()),
        user_id=user.id,
        provider_id=provider.id,
        id_token_sub=sub,
        id_token_email=email,
        id_token_groups=groups,
        last_login=now,
        expires_at=None,
        raw_userinfo_json=json.dumps(raw_userinfo) if raw_userinfo is not None else None,
    )
    db.add(new_session)
    db.commit()
    db.refresh(user)
    return user
