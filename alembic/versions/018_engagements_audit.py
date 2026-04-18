"""018 Engagements + members + signed audit log.

Revision ID: 018
Revises: 017
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def _has_table(conn, table: str) -> bool:
    res = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
    ), {"t": table}).first()
    return res is not None


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "engagements"):
        op.create_table(
            "engagements",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("client_name", sa.Text(), nullable=False),
            sa.Column(
                "status", sa.Text(), nullable=False, server_default="draft"
            ),
            sa.Column("scope_targets", JSONB(), nullable=True),
            sa.Column("excluded_targets", JSONB(), nullable=True),
            sa.Column("start_date", sa.DateTime(timezone=True), nullable=True),
            sa.Column("end_date", sa.DateTime(timezone=True), nullable=True),
            sa.Column("roe_document_path", sa.Text(), nullable=True),
            sa.Column(
                "kill_switch_active",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("created_by", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.Column("mitre_tactics_authorized", JSONB(), nullable=True),
            sa.ForeignKeyConstraint(
                ["created_by"], ["users.id"], ondelete="SET NULL"
            ),
        )
        op.create_index("ix_engagements_status", "engagements", ["status"])
        op.create_index(
            "ix_engagements_client_name", "engagements", ["client_name"]
        )

    if not _has_table(bind, "engagement_members"):
        op.create_table(
            "engagement_members",
            sa.Column("engagement_id", sa.Text(), nullable=False),
            sa.Column("user_id", sa.Text(), nullable=False),
            sa.Column(
                "role", sa.Text(), nullable=False, server_default="operator"
            ),
            sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(
                ["engagement_id"], ["engagements.id"], ondelete="CASCADE"
            ),
            sa.ForeignKeyConstraint(
                ["user_id"], ["users.id"], ondelete="CASCADE"
            ),
            sa.PrimaryKeyConstraint(
                "engagement_id", "user_id", name="pk_engagement_members"
            ),
        )
        op.create_index(
            "ix_engagement_members_user", "engagement_members", ["user_id"]
        )

    if not _has_table(bind, "operator_audit_log"):
        op.create_table(
            "operator_audit_log",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("engagement_id", sa.Text(), nullable=True),
            sa.Column("user_id", sa.Text(), nullable=True),
            sa.Column("action_type", sa.Text(), nullable=False),
            sa.Column("target", sa.Text(), nullable=False, server_default=""),
            sa.Column("command", sa.Text(), nullable=False, server_default=""),
            sa.Column(
                "result_summary",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
            sa.Column("signature", sa.Text(), nullable=False),
            sa.Column(
                "in_scope",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("true"),
            ),
            sa.ForeignKeyConstraint(
                ["engagement_id"], ["engagements.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["user_id"], ["users.id"], ondelete="SET NULL"
            ),
        )
        op.create_index(
            "ix_audit_engagement_ts",
            "operator_audit_log",
            ["engagement_id", "timestamp"],
        )
        op.create_index(
            "ix_audit_action_type", "operator_audit_log", ["action_type"]
        )
        op.create_index(
            "ix_audit_user", "operator_audit_log", ["user_id"]
        )


def downgrade() -> None:
    op.drop_index("ix_audit_user", table_name="operator_audit_log")
    op.drop_index("ix_audit_action_type", table_name="operator_audit_log")
    op.drop_index("ix_audit_engagement_ts", table_name="operator_audit_log")
    op.drop_table("operator_audit_log")
    op.drop_index(
        "ix_engagement_members_user", table_name="engagement_members"
    )
    op.drop_table("engagement_members")
    op.drop_index("ix_engagements_client_name", table_name="engagements")
    op.drop_index("ix_engagements_status", table_name="engagements")
    op.drop_table("engagements")
