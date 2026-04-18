"""014 alert_fingerprint table for dedup.

Revision ID: 014
Revises: 013
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def _has_table(conn, table: str) -> bool:
    res = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.tables WHERE table_name = :t"
    ), {"t": table}).first()
    return res is not None


def _has_column(conn, table: str, column: str) -> bool:
    res = conn.execute(sa.text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = :t AND column_name = :c"
    ), {"t": table, "c": column}).first()
    return res is not None


def upgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "alert_channels") and not _has_column(bind, "alert_channels", "updated_at"):
        op.add_column("alert_channels", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))

    if not _has_table(bind, "alert_rules"):
        op.create_table(
            "alert_rules",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("description", sa.Text(), nullable=False, server_default=""),
            sa.Column("conditions_json", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("channel_id", sa.Text(), nullable=False),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("priority", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        )
    elif not _has_column(bind, "alert_rules", "updated_at"):
        op.add_column("alert_rules", sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))

    op.create_table(
        "alert_fingerprints",
        sa.Column("fingerprint", sa.String(64), primary_key=True),
        sa.Column("rule_id", sa.Text(), nullable=True),
        sa.Column("entity_key", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("suppressed_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_incident_id", sa.Text(), nullable=True),
    )
    op.create_index("ix_alert_fp_last_seen", "alert_fingerprints", ["last_seen"])
    op.create_index("ix_alert_fp_suppressed_until", "alert_fingerprints", ["suppressed_until"])


def downgrade() -> None:
    op.drop_index("ix_alert_fp_suppressed_until", table_name="alert_fingerprints")
    op.drop_index("ix_alert_fp_last_seen", table_name="alert_fingerprints")
    op.drop_table("alert_fingerprints")
