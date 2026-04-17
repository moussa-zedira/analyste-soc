"""UBA baselines + Case Management tables.

Revision ID: 009
Revises: 008
Create Date: 2026-04-17
"""

from alembic import op
import sqlalchemy as sa


revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── UBA ─────────────────────────────────────────────────────────────
    op.create_table(
        "uba_baselines",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("entity_type", sa.Text(), nullable=False, index=True),
        sa.Column("entity_key", sa.Text(), nullable=False, index=True),
        sa.Column("total_events", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hours", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("event_types", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("geos", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("src_ips", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("user_agents", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("current_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("score_reasons", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, index=True),
    )
    op.create_index(
        "ix_uba_entity_unique",
        "uba_baselines",
        ["entity_type", "entity_key"],
        unique=True,
    )

    # ── Cases ───────────────────────────────────────────────────────────
    op.create_table(
        "cases",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.Text(), nullable=False, server_default="open", index=True),
        sa.Column("priority", sa.Text(), nullable=False, server_default="medium", index=True),
        sa.Column("severity", sa.Text(), nullable=False, server_default="medium"),
        sa.Column("assignee_id", sa.Text(), nullable=True, index=True),
        sa.Column("assignee_username", sa.Text(), nullable=True),
        sa.Column("sla_response_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("sla_resolution_minutes", sa.Integer(), nullable=False, server_default="480"),
        sa.Column("sla_responded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sla_breached", sa.Boolean(), nullable=False, server_default=sa.text("false"), index=True),
        sa.Column("incident_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("related_iocs", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("tags", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("resolution", sa.Text(), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "case_evidence",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("case_id", sa.Text(), nullable=False, index=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("sha256", sa.Text(), nullable=True, index=True),
        sa.Column("extra", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("collected_by", sa.Text(), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("custody_chain", sa.JSON(), nullable=False, server_default="[]"),
    )

    op.create_table(
        "case_timeline",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("case_id", sa.Text(), nullable=False, index=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("actor_id", sa.Text(), nullable=True),
        sa.Column("actor_username", sa.Text(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_table("case_timeline")
    op.drop_table("case_evidence")
    op.drop_table("cases")
    op.drop_index("ix_uba_entity_unique", table_name="uba_baselines")
    op.drop_table("uba_baselines")
