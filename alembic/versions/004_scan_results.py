"""Ajout de la table scan_results pour la persistence du lab pentest.

Revision ID: 004
Revises: 003
Create Date: 2026-03-27
"""

from alembic import op
import sqlalchemy as sa

revision = "004"
down_revision = "003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_results",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("module_id", sa.String(), nullable=False),
        sa.Column("target", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), server_default="internal"),
        sa.Column("status", sa.String(), server_default="completed"),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), server_default="0"),
        sa.Column("findings_count", sa.Integer(), server_default="0"),
        sa.Column("severity_max", sa.String(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
    )
    op.create_index("ix_scan_results_module_id", "scan_results", ["module_id"])
    op.create_index("ix_scan_results_created_at", "scan_results", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_scan_results_created_at", table_name="scan_results")
    op.drop_index("ix_scan_results_module_id", table_name="scan_results")
    op.drop_table("scan_results")
