"""022 Chat messages persistance (V4.8 Assistant pentest).

Table chat_messages : historique assistant par engagement, multi-provider.

Revision ID: 022
Revises: 021
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "022"
down_revision = "021"
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

    if not _has_table(bind, "chat_messages"):
        op.create_table(
            "chat_messages",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("conversation_id", sa.Text(), nullable=False),
            sa.Column(
                "engagement_id",
                sa.Text(),
                sa.ForeignKey("engagements.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "user_id",
                sa.Text(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("role", sa.Text(), nullable=False),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("provider", sa.Text(), nullable=True),
            sa.Column("model", sa.Text(), nullable=True),
            sa.Column("tokens_in", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("tokens_out", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("cost_usd", sa.Float(), nullable=False, server_default="0"),
            sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("context_labels", JSONB(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_chat_messages_conversation_id", "chat_messages", ["conversation_id"]
        )
        op.create_index(
            "ix_chat_conv_ts", "chat_messages", ["conversation_id", "created_at"]
        )
        op.create_index(
            "ix_chat_engagement_ts", "chat_messages", ["engagement_id", "created_at"]
        )


def downgrade() -> None:
    op.drop_index("ix_chat_engagement_ts", table_name="chat_messages")
    op.drop_index("ix_chat_conv_ts", table_name="chat_messages")
    op.drop_index("ix_chat_messages_conversation_id", table_name="chat_messages")
    op.drop_table("chat_messages")
