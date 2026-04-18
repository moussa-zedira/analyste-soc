"""Modeles SSO OIDC : providers + sessions.

Couvre Azure AD, Google Workspace, Okta et tout IdP OIDC standard.
JIT user provisioning + role mapping via groups claim.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class SSOProvider(Base):
    """Configuration d'un IdP OIDC (Azure / Google / Okta / generic)."""

    __tablename__ = "sso_providers"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    provider_type: Mapped[str] = mapped_column(Text)  # azure | google | okta | generic_oidc
    name: Mapped[str] = mapped_column(Text, unique=True)
    issuer_url: Mapped[str] = mapped_column(Text)
    client_id: Mapped[str] = mapped_column(Text)
    client_secret: Mapped[str] = mapped_column(Text)
    scopes: Mapped[str] = mapped_column(Text, default="openid email profile")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_domains: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    default_role: Mapped[str] = mapped_column(Text, default="analyst")
    group_to_role_mapping: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)
    )


class SSOSession(Base):
    """Trace d'une session SSO etablie : lien user <-> sub IdP."""

    __tablename__ = "sso_sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[str] = mapped_column(
        Text, ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    provider_id: Mapped[str] = mapped_column(
        Text, ForeignKey("sso_providers.id", ondelete="CASCADE")
    )
    id_token_sub: Mapped[str] = mapped_column(Text)
    id_token_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    id_token_groups: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    last_login: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    raw_userinfo_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        UniqueConstraint("provider_id", "id_token_sub", name="uq_sso_session_provider_sub"),
        Index("ix_sso_session_user", "user_id"),
        Index("ix_sso_session_last_login", "last_login"),
    )
