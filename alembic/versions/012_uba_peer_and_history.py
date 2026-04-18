"""UBA peer-group + score history — colonnes peer_group_id, peer_deviation,
previous_score et score_history sur uba_baselines.

Revision ID: 012
Revises: 011
Create Date: 2026-04-17
"""

from alembic import op
import sqlalchemy as sa


revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "uba_baselines",
        sa.Column("previous_score", sa.Float(), nullable=True),
    )
    op.add_column(
        "uba_baselines",
        sa.Column(
            "score_history",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'"),
        ),
    )
    op.add_column(
        "uba_baselines",
        sa.Column("peer_group_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "uba_baselines",
        sa.Column("peer_deviation", sa.Float(), nullable=True),
    )
    op.create_index(
        "ix_uba_baselines_peer_group_id",
        "uba_baselines",
        ["peer_group_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_uba_baselines_peer_group_id", table_name="uba_baselines")
    op.drop_column("uba_baselines", "peer_deviation")
    op.drop_column("uba_baselines", "peer_group_id")
    op.drop_column("uba_baselines", "score_history")
    op.drop_column("uba_baselines", "previous_score")
