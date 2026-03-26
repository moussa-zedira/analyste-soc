"""Ajout des tables scan_history et audit_logs.

Revision ID: 002
Revises: 001
Create Date: 2026-03-26
"""

from alembic import op
import sqlalchemy as sa

revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_history",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("target", sa.Text(), nullable=False),
        sa.Column("target_type", sa.Text(), nullable=False),
        sa.Column("resolved_ip", sa.Text(), nullable=True),
        sa.Column("result_json", sa.Text(), server_default="{}"),
        sa.Column("security_score", sa.Integer(), server_default="0"),
        sa.Column("open_ports_count", sa.Integer(), server_default="0"),
        sa.Column("scan_duration_ms", sa.Integer(), server_default="0"),
        sa.Column("scanned_by", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_scan_history_target", "scan_history", ["target"])
    op.create_index("ix_scan_history_created_at", "scan_history", ["created_at"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("user_id", sa.Text(), nullable=True),
        sa.Column("username", sa.Text(), nullable=True),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("target", sa.Text(), nullable=True),
        sa.Column("details", sa.Text(), server_default="{}"),
        sa.Column("ip_address", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("scan_history")
