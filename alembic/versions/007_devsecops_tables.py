"""DevSecOps CI/CD scanner tables.

Revision ID: 007
Revises: 006
Create Date: 2026-03-29
"""

from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "devsecops_projects",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False, index=True),
        sa.Column("repo_url", sa.String(1024), nullable=True),
        sa.Column("branch", sa.String(255), server_default="main"),
        sa.Column("language", sa.String(64), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("config", sa.JSON(), nullable=True),
        sa.Column("last_scan_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "devsecops_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("devsecops_projects.id"), nullable=True, index=True),
        sa.Column("scan_type", sa.String(32), nullable=False, index=True),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("finished_at", sa.DateTime(), nullable=True),
        sa.Column("findings_count", sa.Integer(), server_default="0"),
        sa.Column("critical_count", sa.Integer(), server_default="0"),
        sa.Column("high_count", sa.Integer(), server_default="0"),
        sa.Column("medium_count", sa.Integer(), server_default="0"),
        sa.Column("low_count", sa.Integer(), server_default="0"),
        sa.Column("quality_gate_passed", sa.Boolean(), nullable=True),
        sa.Column("trigger", sa.String(64), server_default="manual"),
        sa.Column("meta", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "devsecops_findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("devsecops_runs.id"), nullable=False, index=True),
        sa.Column("scan_type", sa.String(32), nullable=False, index=True),
        sa.Column("severity", sa.String(16), nullable=False, index=True),
        sa.Column("cwe_id", sa.String(32), nullable=True),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("code_snippet", sa.Text(), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("false_positive", sa.Boolean(), server_default="0"),
        sa.Column("resolved", sa.Boolean(), server_default="0"),
        sa.Column("raw_data", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )

    op.create_table(
        "devsecops_quality_gates",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("devsecops_projects.id"), nullable=True, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("max_critical", sa.Integer(), server_default="0"),
        sa.Column("max_high", sa.Integer(), server_default="5"),
        sa.Column("max_medium", sa.Integer(), nullable=True),
        sa.Column("no_secrets", sa.Boolean(), server_default="1"),
        sa.Column("custom_rules", sa.JSON(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="1"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("devsecops_quality_gates")
    op.drop_table("devsecops_findings")
    op.drop_table("devsecops_runs")
    op.drop_table("devsecops_projects")
