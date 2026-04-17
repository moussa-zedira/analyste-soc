"""AI cost log table — tracking LLM usage/cost per call.

Revision ID: 010
Revises: 009
Create Date: 2026-04-17
"""

from alembic import op
import sqlalchemy as sa


revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_cost_log",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("provider", sa.Text(), nullable=False, index=True),
        sa.Column("model", sa.Text(), nullable=False, index=True),
        sa.Column("operation", sa.Text(), nullable=False, index=True),
        sa.Column("tokens_in", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tokens_out", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cost_usd_in", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("cost_usd_out", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column(
            "cost_usd_total",
            sa.Float(),
            nullable=False,
            server_default="0.0",
            index=True,
        ),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "success",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
            index=True,
        ),
        sa.Column("error_msg", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_ai_cost_provider_ts",
        "ai_cost_log",
        ["provider", "ts"],
    )


def downgrade() -> None:
    op.drop_index("ix_ai_cost_provider_ts", table_name="ai_cost_log")
    op.drop_table("ai_cost_log")
