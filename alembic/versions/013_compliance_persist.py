"""Compliance persistence : assessments, attestations, remediations.

Revision ID: 013
Revises: 012
Create Date: 2026-04-17
"""

from alembic import op
import sqlalchemy as sa


revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "compliance_assessments",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("framework_id", sa.Text(), nullable=False, index=True),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("coverage_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("controls_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("by_status", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("snapshot", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("triggered_by", sa.Text(), nullable=False, server_default="manual"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_compliance_assessments_fid_at",
        "compliance_assessments",
        ["framework_id", "assessed_at"],
    )

    op.create_table(
        "compliance_attestations",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("framework_id", sa.Text(), nullable=False, index=True),
        sa.Column("control_id", sa.Text(), nullable=False, index=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="manual_ok", index=True),
        sa.Column("attested_by", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("evidence_urls", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_compliance_attestations_fwk_ctrl",
        "compliance_attestations",
        ["framework_id", "control_id"],
    )

    op.create_table(
        "compliance_remediations",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("framework_id", sa.Text(), nullable=False, index=True),
        sa.Column("control_id", sa.Text(), nullable=False, index=True),
        sa.Column("severity", sa.Text(), nullable=False, server_default="med", index=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("assigned_to", sa.Text(), nullable=True, index=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="open", index=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("compliance_remediations")
    op.drop_index("ix_compliance_attestations_fwk_ctrl", table_name="compliance_attestations")
    op.drop_table("compliance_attestations")
    op.drop_index("ix_compliance_assessments_fid_at", table_name="compliance_assessments")
    op.drop_table("compliance_assessments")
