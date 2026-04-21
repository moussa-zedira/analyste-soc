"""024 User API keys (V4.7e Profile per-user API keys).

Table user_api_keys : clés scopées par utilisateur avec hash stocké.

Revision ID: 024
Revises: 023
Create Date: 2026-04-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "024"
down_revision = "023"
branch_labels = None
depends_on = None


def _has_table(conn, table: str) -> bool:
    res = conn.execute(
        sa.text("SELECT 1 FROM information_schema.tables WHERE table_name = :t"),
        {"t": table},
    ).first()
    return res is not None


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "user_api_keys"):
        op.create_table(
            "user_api_keys",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "user_id",
                sa.Text(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                nullable=False,
                index=True,
            ),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("prefix", sa.Text(), nullable=False),
            sa.Column("hashed_key", sa.Text(), nullable=False, unique=True),
            sa.Column("scopes", sa.Text(), nullable=False, server_default="read"),
            sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        )
        op.create_index(
            "ix_user_api_keys_user_id_created", "user_api_keys", ["user_id", "created_at"]
        )


def downgrade() -> None:
    op.drop_index("ix_user_api_keys_user_id_created", table_name="user_api_keys")
    op.drop_table("user_api_keys")
