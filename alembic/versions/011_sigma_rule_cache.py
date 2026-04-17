"""Sigma rule cache table — cache des regles SigmaHQ chargees via /sigma/sync.

Revision ID: 011
Revises: 010
Create Date: 2026-04-17
"""

from alembic import op
import sqlalchemy as sa


revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sigma_rule_cache",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("level", sa.Text(), nullable=False, server_default="medium"),
        sa.Column("status", sa.Text(), nullable=True),
        sa.Column("author", sa.Text(), nullable=True),
        sa.Column("logsource_product", sa.Text(), nullable=True),
        sa.Column("logsource_category", sa.Text(), nullable=True),
        sa.Column("logsource_service", sa.Text(), nullable=True),
        sa.Column("yaml_source", sa.Text(), nullable=False),
        sa.Column("lucene_query", sa.Text(), nullable=True),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("source_path", sa.Text(), nullable=True),
        sa.Column(
            "imported_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.UniqueConstraint("rule_id", name="uq_sigma_rule_cache_rule_id"),
    )
    op.create_index("ix_sigma_rule_cache_rule_id", "sigma_rule_cache", ["rule_id"])
    op.create_index("ix_sigma_rule_cache_level", "sigma_rule_cache", ["level"])
    op.create_index("ix_sigma_rule_cache_enabled", "sigma_rule_cache", ["enabled"])
    op.create_index(
        "ix_sigma_rule_cache_logsource_product",
        "sigma_rule_cache",
        ["logsource_product"],
    )
    op.create_index(
        "ix_sigma_rule_cache_logsource_category",
        "sigma_rule_cache",
        ["logsource_category"],
    )
    op.create_index(
        "ix_sigma_cache_level_enabled",
        "sigma_rule_cache",
        ["level", "enabled"],
    )


def downgrade() -> None:
    op.drop_index("ix_sigma_cache_level_enabled", table_name="sigma_rule_cache")
    op.drop_index(
        "ix_sigma_rule_cache_logsource_category", table_name="sigma_rule_cache"
    )
    op.drop_index(
        "ix_sigma_rule_cache_logsource_product", table_name="sigma_rule_cache"
    )
    op.drop_index("ix_sigma_rule_cache_enabled", table_name="sigma_rule_cache")
    op.drop_index("ix_sigma_rule_cache_level", table_name="sigma_rule_cache")
    op.drop_index("ix_sigma_rule_cache_rule_id", table_name="sigma_rule_cache")
    op.drop_table("sigma_rule_cache")
