"""025 User TOTP 2FA (V4.7e Profile 2FA).

Ajoute totp_secret + totp_enabled sur la table users.

Revision ID: 025
Revises: 024
Create Date: 2026-04-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def _has_column(conn, table: str, column: str) -> bool:
    res = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.columns WHERE table_name = :t AND column_name = :c"
        ),
        {"t": table, "c": column},
    ).first()
    return res is not None


def upgrade() -> None:
    bind = op.get_bind()
    if not _has_column(bind, "users", "totp_secret"):
        op.add_column("users", sa.Column("totp_secret", sa.Text(), nullable=True))
    if not _has_column(bind, "users", "totp_enabled"):
        op.add_column(
            "users",
            sa.Column(
                "totp_enabled", sa.Boolean(), nullable=False, server_default=sa.text("false")
            ),
        )


def downgrade() -> None:
    op.drop_column("users", "totp_enabled")
    op.drop_column("users", "totp_secret")
