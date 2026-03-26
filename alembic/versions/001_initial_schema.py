"""Initial schema — all existing tables plus User and AlertChannel.

Revision ID: 001
Revises: None
Create Date: 2026-03-04
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Events
    op.create_table(
        "events",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("event_type", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("src_ip", sa.Text(), nullable=True),
        sa.Column("dst_ip", sa.Text(), nullable=True),
        sa.Column("username", sa.Text(), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("raw", sa.Text(), nullable=True),
    )
    op.create_index("ix_events_ts", "events", ["ts"])
    op.create_index("ix_events_event_type_ts", "events", ["event_type", "ts"])
    op.create_index("ix_events_src_ip_ts", "events", ["src_ip", "ts"])

    # Incidents
    op.create_table(
        "incidents",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("entity_key", sa.Text(), nullable=False),
        sa.Column("start_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dedup_hash", sa.Text(), unique=True, nullable=False),
        sa.Column("suggested_severity", sa.Text(), nullable=True),
    )
    op.create_index("ix_incidents_created_at", "incidents", ["created_at"])
    op.create_index("ix_incidents_severity", "incidents", ["severity"])
    op.create_index("ix_incidents_entity_key", "incidents", ["entity_key"])

    # Incident-Event association
    op.create_table(
        "incident_events",
        sa.Column("incident_id", sa.Text(), sa.ForeignKey("incidents.id"), primary_key=True),
        sa.Column("event_id", sa.Text(), sa.ForeignKey("events.id"), primary_key=True),
    )

    # Rule Checkpoints
    op.create_table(
        "rule_checkpoints",
        sa.Column("rule_id", sa.Text(), primary_key=True),
        sa.Column("last_ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Anomaly Baselines
    op.create_table(
        "anomaly_baselines",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("metric_type", sa.Text(), nullable=False),
        sa.Column("metric_key", sa.Text(), nullable=False),
        sa.Column("count", sa.Integer(), default=0, nullable=False),
        sa.Column("mean", sa.Float(), default=0.0, nullable=False),
        sa.Column("variance", sa.Float(), default=0.0, nullable=False),
        sa.Column("last_value", sa.Float(), default=0.0, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_anomaly_baselines_metric_type", "anomaly_baselines", ["metric_type"])
    op.create_index("ix_anomaly_baselines_metric_key", "anomaly_baselines", ["metric_key"])

    # Threat Scores
    op.create_table(
        "threat_scores",
        sa.Column("ip", sa.Text(), primary_key=True),
        sa.Column("score", sa.Float(), default=0.0, nullable=False),
        sa.Column("factors_json", sa.Text(), default="{}", nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # Whitelist
    op.create_table(
        "whitelist",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("entry_type", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), default="", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("enabled", sa.Boolean(), default=True, nullable=False),
    )

    # Users (RBAC)
    op.create_table(
        "users",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("username", sa.Text(), unique=True, nullable=False),
        sa.Column("email", sa.Text(), unique=True, nullable=False),
        sa.Column("hashed_password", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), default="analyst", nullable=False),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    # Alert Channels
    op.create_table(
        "alert_channels",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("channel_type", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("config_json", sa.Text(), default="{}", nullable=False),
        sa.Column("enabled", sa.Boolean(), default=True, nullable=False),
        sa.Column("min_severity", sa.Text(), default="high", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("alert_channels")
    op.drop_table("users")
    op.drop_table("whitelist")
    op.drop_table("threat_scores")
    op.drop_table("anomaly_baselines")
    op.drop_table("rule_checkpoints")
    op.drop_table("incident_events")
    op.drop_table("incidents")
    op.drop_table("events")
