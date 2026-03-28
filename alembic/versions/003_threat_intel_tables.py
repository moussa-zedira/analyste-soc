"""Ajout des tables ti_cache et sigma_rules, colonnes TI sur events.

Revision ID: 003
Revises: 002
Create Date: 2026-03-26
"""

from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Table ti_cache
    op.create_table(
        "ti_cache",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("indicator", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("risk_score", sa.Integer(), server_default="0"),
        sa.Column("is_malicious", sa.Boolean(), server_default="false"),
        sa.Column("categories_json", sa.Text(), nullable=True),
        sa.Column("tags_json", sa.Text(), nullable=True),
        sa.Column("total_reports", sa.Integer(), server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_ti_cache_indicator", "ti_cache", ["indicator"])

    # Table sigma_rules
    op.create_table(
        "sigma_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("level", sa.Text(), server_default="medium"),
        sa.Column("yaml_content", sa.Text(), nullable=False),
        sa.Column("compiled_json", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), server_default="true"),
        sa.Column("author", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Colonnes TI sur events
    op.add_column("events", sa.Column("ti_score", sa.Integer(), nullable=True))
    op.add_column("events", sa.Column("ti_tags", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("events", "ti_tags")
    op.drop_column("events", "ti_score")
    op.drop_table("sigma_rules")
    op.drop_index("ix_ti_cache_indicator", table_name="ti_cache")
    op.drop_table("ti_cache")
