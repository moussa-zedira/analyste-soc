"""019 BloodHound dataset/nodes/edges (V4.5).

Revision ID: 019
Revises: 018
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def _has_table(conn, table: str) -> bool:
    res = conn.execute(
        sa.text(
            "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
        ),
        {"t": table},
    ).first()
    return res is not None


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "bh_datasets"):
        op.create_table(
            "bh_datasets",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column(
                "source_filename",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column("engagement_id", sa.Text(), nullable=True),
            sa.Column(
                "bh_schema_version",
                sa.Integer(),
                nullable=False,
                server_default="5",
            ),
            sa.Column(
                "nodes_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "edges_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column("uploaded_by", sa.Text(), nullable=True),
            sa.Column(
                "uploaded_at", sa.DateTime(timezone=True), nullable=False
            ),
            sa.Column(
                "notes", sa.Text(), nullable=False, server_default=""
            ),
            sa.ForeignKeyConstraint(
                ["engagement_id"], ["engagements.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["uploaded_by"], ["users.id"], ondelete="SET NULL"
            ),
        )
        op.create_index(
            "ix_bh_datasets_engagement", "bh_datasets", ["engagement_id"]
        )
        op.create_index(
            "ix_bh_datasets_uploaded_at", "bh_datasets", ["uploaded_at"]
        )

    if not _has_table(bind, "bh_nodes"):
        op.create_table(
            "bh_nodes",
            sa.Column(
                "id",
                sa.Integer(),
                primary_key=True,
                autoincrement=True,
            ),
            sa.Column("dataset_id", sa.Text(), nullable=False),
            sa.Column("sid", sa.Text(), nullable=False),
            sa.Column("object_type", sa.Text(), nullable=False),
            sa.Column(
                "name", sa.Text(), nullable=False, server_default=""
            ),
            sa.Column(
                "domain", sa.Text(), nullable=False, server_default=""
            ),
            sa.Column(
                "high_value",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("props", JSONB(), nullable=True),
            sa.ForeignKeyConstraint(
                ["dataset_id"], ["bh_datasets.id"], ondelete="CASCADE"
            ),
            sa.UniqueConstraint(
                "dataset_id", "sid", name="uq_bh_nodes_dataset_sid"
            ),
        )
        op.create_index(
            "ix_bh_nodes_dataset_type",
            "bh_nodes",
            ["dataset_id", "object_type"],
        )
        op.create_index(
            "ix_bh_nodes_dataset_name",
            "bh_nodes",
            ["dataset_id", "name"],
        )
        op.create_index(
            "ix_bh_nodes_high_value",
            "bh_nodes",
            ["dataset_id", "high_value"],
        )

    if not _has_table(bind, "bh_edges"):
        op.create_table(
            "bh_edges",
            sa.Column(
                "id",
                sa.Integer(),
                primary_key=True,
                autoincrement=True,
            ),
            sa.Column("dataset_id", sa.Text(), nullable=False),
            sa.Column("source_sid", sa.Text(), nullable=False),
            sa.Column("target_sid", sa.Text(), nullable=False),
            sa.Column("edge_type", sa.Text(), nullable=False),
            sa.Column("props", JSONB(), nullable=True),
            sa.ForeignKeyConstraint(
                ["dataset_id"], ["bh_datasets.id"], ondelete="CASCADE"
            ),
        )
        op.create_index(
            "ix_bh_edges_source",
            "bh_edges",
            ["dataset_id", "source_sid"],
        )
        op.create_index(
            "ix_bh_edges_target",
            "bh_edges",
            ["dataset_id", "target_sid"],
        )
        op.create_index(
            "ix_bh_edges_type",
            "bh_edges",
            ["dataset_id", "edge_type"],
        )


def downgrade() -> None:
    op.drop_index("ix_bh_edges_type", table_name="bh_edges")
    op.drop_index("ix_bh_edges_target", table_name="bh_edges")
    op.drop_index("ix_bh_edges_source", table_name="bh_edges")
    op.drop_table("bh_edges")
    op.drop_index("ix_bh_nodes_high_value", table_name="bh_nodes")
    op.drop_index("ix_bh_nodes_dataset_name", table_name="bh_nodes")
    op.drop_index("ix_bh_nodes_dataset_type", table_name="bh_nodes")
    op.drop_table("bh_nodes")
    op.drop_index("ix_bh_datasets_uploaded_at", table_name="bh_datasets")
    op.drop_index("ix_bh_datasets_engagement", table_name="bh_datasets")
    op.drop_table("bh_datasets")
