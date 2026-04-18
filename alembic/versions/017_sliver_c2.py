"""017 Sliver C2: sessions, implant builds, commands.

Revision ID: 017
Revises: 016
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def _has_table(conn, table: str) -> bool:
    res = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
    ), {"t": table}).first()
    return res is not None


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "sliver_sessions"):
        op.create_table(
            "sliver_sessions",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("name", sa.Text(), nullable=False, server_default=""),
            sa.Column("hostname", sa.Text(), nullable=False, server_default=""),
            sa.Column("username", sa.Text(), nullable=False, server_default=""),
            sa.Column("os", sa.Text(), nullable=False, server_default=""),
            sa.Column("arch", sa.Text(), nullable=False, server_default=""),
            sa.Column("transport", sa.Text(), nullable=False, server_default=""),
            sa.Column("remote_address", sa.Text(), nullable=False, server_default=""),
            sa.Column("pid", sa.Integer(), nullable=False, server_default="0"),
            sa.Column(
                "active",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("true"),
            ),
            sa.Column("first_contact", sa.DateTime(timezone=True), nullable=True),
            sa.Column("last_checkin", sa.DateTime(timezone=True), nullable=True),
            sa.Column("engagement_id", sa.Text(), nullable=True),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        )
        op.create_index(
            "ix_sliver_sessions_active", "sliver_sessions", ["active"]
        )
        op.create_index(
            "ix_sliver_sessions_engagement",
            "sliver_sessions",
            ["engagement_id"],
        )

    if not _has_table(bind, "sliver_implant_builds"):
        op.create_table(
            "sliver_implant_builds",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("os", sa.Text(), nullable=False),
            sa.Column("arch", sa.Text(), nullable=False),
            sa.Column("format", sa.Text(), nullable=False),
            sa.Column("c2_url", sa.Text(), nullable=False),
            sa.Column(
                "sleep_seconds",
                sa.Integer(),
                nullable=False,
                server_default="60",
            ),
            sa.Column(
                "jitter_pct", sa.Integer(), nullable=False, server_default="20"
            ),
            sa.Column("build_path", sa.Text(), nullable=True),
            sa.Column(
                "size_bytes", sa.Integer(), nullable=False, server_default="0"
            ),
            sa.Column("engagement_id", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("created_by", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(
                ["created_by"], ["users.id"], ondelete="SET NULL"
            ),
        )
        op.create_index(
            "ix_sliver_builds_created_at",
            "sliver_implant_builds",
            ["created_at"],
        )
        op.create_index(
            "ix_sliver_builds_engagement",
            "sliver_implant_builds",
            ["engagement_id"],
        )

    if not _has_table(bind, "sliver_commands"):
        op.create_table(
            "sliver_commands",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("session_id", sa.Text(), nullable=False),
            sa.Column("engagement_id", sa.Text(), nullable=True),
            sa.Column("command", sa.Text(), nullable=False),
            sa.Column("output", sa.Text(), nullable=False, server_default=""),
            sa.Column(
                "status", sa.Text(), nullable=False, server_default="pending"
            ),
            sa.Column("executed_by", sa.Text(), nullable=True),
            sa.Column("executed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.ForeignKeyConstraint(
                ["session_id"],
                ["sliver_sessions.id"],
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["executed_by"], ["users.id"], ondelete="SET NULL"
            ),
        )
        op.create_index(
            "ix_sliver_commands_session_executed",
            "sliver_commands",
            ["session_id", "executed_at"],
        )


def downgrade() -> None:
    op.drop_index(
        "ix_sliver_commands_session_executed", table_name="sliver_commands"
    )
    op.drop_table("sliver_commands")
    op.drop_index(
        "ix_sliver_builds_engagement", table_name="sliver_implant_builds"
    )
    op.drop_index(
        "ix_sliver_builds_created_at", table_name="sliver_implant_builds"
    )
    op.drop_table("sliver_implant_builds")
    op.drop_index(
        "ix_sliver_sessions_engagement", table_name="sliver_sessions"
    )
    op.drop_index("ix_sliver_sessions_active", table_name="sliver_sessions")
    op.drop_table("sliver_sessions")
