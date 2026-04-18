"""015 outbound integrations + incident tickets.

Revision ID: 015
Revises: 014
Create Date: 2026-04-17
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def _has_table(conn, table: str) -> bool:
    res = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
    ), {"t": table}).first()
    return res is not None


def upgrade() -> None:
    bind = op.get_bind()

    if not _has_table(bind, "outbound_integrations"):
        op.create_table(
            "outbound_integrations",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("integration_type", sa.Text(), nullable=False),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("config_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("severity_min", sa.Text(), nullable=False, server_default="high"),
            sa.Column("auto_sync_status", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(
            "ix_outbound_integrations_type_enabled",
            "outbound_integrations",
            ["integration_type", "enabled"],
        )

    if not _has_table(bind, "incident_tickets"):
        op.create_table(
            "incident_tickets",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("incident_id", sa.Text(), nullable=False),
            sa.Column("integration_id", sa.Text(), nullable=False),
            sa.Column("external_ticket_id", sa.Text(), nullable=True),
            sa.Column("external_url", sa.Text(), nullable=True),
            sa.Column("ticket_status", sa.Text(), nullable=True),
            sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("synced_attempts", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="CASCADE"),
            sa.ForeignKeyConstraint(["integration_id"], ["outbound_integrations.id"], ondelete="CASCADE"),
            sa.UniqueConstraint("incident_id", "integration_id", name="uq_incident_integration"),
        )
        op.create_index("ix_incident_tickets_incident_id", "incident_tickets", ["incident_id"])
        op.create_index("ix_incident_tickets_integration_id", "incident_tickets", ["integration_id"])
        op.create_index("ix_incident_tickets_last_synced_at", "incident_tickets", ["last_synced_at"])


def downgrade() -> None:
    op.drop_index("ix_incident_tickets_last_synced_at", table_name="incident_tickets")
    op.drop_index("ix_incident_tickets_integration_id", table_name="incident_tickets")
    op.drop_index("ix_incident_tickets_incident_id", table_name="incident_tickets")
    op.drop_table("incident_tickets")
    op.drop_index("ix_outbound_integrations_type_enabled", table_name="outbound_integrations")
    op.drop_table("outbound_integrations")
