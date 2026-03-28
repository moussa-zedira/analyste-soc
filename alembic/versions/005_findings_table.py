"""Ajout de la table findings pour les resultats unifies du pentest.

Revision ID: 005
Revises: 004
Create Date: 2026-03-28
"""

from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("module", sa.String(), nullable=True),
        sa.Column("finding_type", sa.String(), nullable=True),
        sa.Column("severity", sa.String(), nullable=True),
        sa.Column("title", sa.String(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("target", sa.String(), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("exploitable", sa.Boolean(), server_default="0"),
        sa.Column("exploited", sa.Boolean(), server_default="0"),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cwe_id", sa.String(), nullable=True),
        sa.Column("mitre_technique", sa.String(), nullable=True),
        sa.Column("raw_data", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )
    op.create_index("ix_findings_session_id", "findings", ["session_id"])
    op.create_index("ix_findings_module", "findings", ["module"])
    op.create_index("ix_findings_finding_type", "findings", ["finding_type"])


def downgrade() -> None:
    op.drop_index("ix_findings_finding_type", table_name="findings")
    op.drop_index("ix_findings_module", table_name="findings")
    op.drop_index("ix_findings_session_id", table_name="findings")
    op.drop_table("findings")
