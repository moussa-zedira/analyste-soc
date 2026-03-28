"""SOAR engine tables — playbooks, executions, step results.

Revision ID: 005_soar
Revises: 004
Create Date: 2026-03-29
"""

from alembic import op
import sqlalchemy as sa

revision = "005_soar"
down_revision = "004_scan_results"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "soar_playbooks",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("name", sa.Text, nullable=False, index=True),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("category", sa.Text, server_default="custom", index=True),
        sa.Column("trigger_type", sa.Text, server_default="manual"),
        sa.Column("trigger_config", sa.JSON, nullable=True),
        sa.Column("definition", sa.JSON, nullable=False),
        sa.Column("enabled", sa.Boolean, server_default="true"),
        sa.Column("builtin", sa.Boolean, server_default="false"),
        sa.Column("version", sa.Integer, server_default="1"),
        sa.Column("tags", sa.JSON, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Text, server_default="system"),
    )

    op.create_table(
        "soar_executions",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("playbook_id", sa.Text, nullable=False, index=True),
        sa.Column("playbook_name", sa.Text, server_default=""),
        sa.Column("status", sa.Text, server_default="pending", index=True),
        sa.Column("trigger", sa.Text, server_default="manual"),
        sa.Column("input_data", sa.JSON, nullable=True),
        sa.Column("variables", sa.JSON, nullable=True),
        sa.Column("result", sa.JSON, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("dry_run", sa.Boolean, server_default="false"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Float, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.Text, server_default="system"),
        sa.Column("celery_task_id", sa.Text, nullable=True),
        sa.Column("incident_id", sa.Text, nullable=True),
    )

    op.create_table(
        "soar_step_results",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("execution_id", sa.Text, nullable=False, index=True),
        sa.Column("step_name", sa.Text, nullable=False),
        sa.Column("step_index", sa.Integer, nullable=False),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("status", sa.Text, server_default="pending"),
        sa.Column("input_params", sa.JSON, nullable=True),
        sa.Column("output", sa.JSON, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.Float, nullable=True),
        sa.Column("skipped", sa.Boolean, server_default="false"),
        sa.Column("skip_reason", sa.Text, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("soar_step_results")
    op.drop_table("soar_executions")
    op.drop_table("soar_playbooks")
