"""023 User preferences (V4.7e Profile per-user settings).

Table user_preferences : notifications, layout, timezone par utilisateur.

Revision ID: 023
Revises: 022
Create Date: 2026-04-21
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "023"
down_revision = "022"
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

    if not _has_table(bind, "user_preferences"):
        op.create_table(
            "user_preferences",
            sa.Column(
                "user_id",
                sa.Text(),
                sa.ForeignKey("users.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("notif_email", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("notif_browser", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("notif_critical_only", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("default_layout", sa.Text(), nullable=False, server_default="grid"),
            sa.Column("timezone", sa.Text(), nullable=False, server_default="UTC"),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    op.drop_table("user_preferences")
