"""016 SSO providers + sessions (OIDC PKCE).

Revision ID: 016
Revises: 015
Create Date: 2026-04-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def _has_table(conn, table: str) -> bool:
    res = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
    ), {"t": table}).first()
    return res is not None


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "sso_providers"):
        op.create_table(
            "sso_providers",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("provider_type", sa.Text(), nullable=False),
            sa.Column("name", sa.Text(), nullable=False, unique=True),
            sa.Column("issuer_url", sa.Text(), nullable=False),
            sa.Column("client_id", sa.Text(), nullable=False),
            sa.Column("client_secret", sa.Text(), nullable=False),
            sa.Column("scopes", sa.Text(), nullable=False, server_default="openid email profile"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("allowed_domains", JSONB(), nullable=True),
            sa.Column("default_role", sa.Text(), nullable=False, server_default="analyst"),
            sa.Column("group_to_role_mapping", JSONB(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )

    if not _has_table(bind, "sso_sessions"):
        op.create_table(
            "sso_sessions",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("user_id", sa.Text(), nullable=False),
            sa.Column("provider_id", sa.Text(), nullable=False),
            sa.Column("id_token_sub", sa.Text(), nullable=False),
            sa.Column("id_token_email", sa.Text(), nullable=True),
            sa.Column("id_token_groups", JSONB(), nullable=True),
            sa.Column("last_login", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("raw_userinfo_json", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["provider_id"], ["sso_providers.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("provider_id", "id_token_sub", name="uq_sso_session_provider_sub"),
        )
        op.create_index("ix_sso_session_user", "sso_sessions", ["user_id"])
        op.create_index("ix_sso_session_last_login", "sso_sessions", ["last_login"])


def downgrade() -> None:
    op.drop_index("ix_sso_session_last_login", table_name="sso_sessions")
    op.drop_index("ix_sso_session_user", table_name="sso_sessions")
    op.drop_table("sso_sessions")
    op.drop_table("sso_providers")
