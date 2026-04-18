"""020 GoPhish workflow enrichi (V4.6).

Tables phishing_campaigns / phishing_targets / phishing_results.

Revision ID: 020
Revises: 019
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "020"
down_revision = "019"
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

    if not _has_table(bind, "phishing_campaigns"):
        op.create_table(
            "phishing_campaigns",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("name", sa.Text(), nullable=False),
            sa.Column("engagement_id", sa.Text(), nullable=True),
            sa.Column(
                "gophish_campaign_id", sa.Integer(), nullable=True
            ),
            sa.Column(
                "status",
                sa.Text(),
                nullable=False,
                server_default="draft",
            ),
            sa.Column(
                "template_name",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "landing_url",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "sent_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "opened_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "clicked_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "submitted_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "email_failed_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "launched_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column(
                "completed_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column("created_by", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "mitre_technique",
                sa.Text(),
                nullable=False,
                server_default="T1566.001",
            ),
            sa.Column(
                "notes",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "last_synced_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.ForeignKeyConstraint(
                ["engagement_id"], ["engagements.id"], ondelete="SET NULL"
            ),
            sa.ForeignKeyConstraint(
                ["created_by"], ["users.id"], ondelete="SET NULL"
            ),
        )
        op.create_index(
            "ix_phishing_campaigns_engagement",
            "phishing_campaigns",
            ["engagement_id"],
        )
        op.create_index(
            "ix_phishing_campaigns_status",
            "phishing_campaigns",
            ["status"],
        )
        op.create_index(
            "ix_phishing_campaigns_created_at",
            "phishing_campaigns",
            ["created_at"],
        )

    if not _has_table(bind, "phishing_targets"):
        op.create_table(
            "phishing_targets",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("campaign_id", sa.Text(), nullable=False),
            sa.Column("email", sa.Text(), nullable=False),
            sa.Column(
                "first_name",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "last_name",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "position",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "group_name",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "last_status",
                sa.Text(),
                nullable=False,
                server_default="pending",
            ),
            sa.Column(
                "opened_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column(
                "clicked_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column(
                "submitted_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.ForeignKeyConstraint(
                ["campaign_id"],
                ["phishing_campaigns.id"],
                ondelete="CASCADE",
            ),
        )
        op.create_index(
            "ix_phishing_targets_campaign_email",
            "phishing_targets",
            ["campaign_id", "email"],
        )
        op.create_index(
            "ix_phishing_targets_last_status",
            "phishing_targets",
            ["campaign_id", "last_status"],
        )

    if not _has_table(bind, "phishing_results"):
        op.create_table(
            "phishing_results",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column("campaign_id", sa.Text(), nullable=False),
            sa.Column("target_id", sa.Text(), nullable=True),
            sa.Column("event_type", sa.Text(), nullable=False),
            sa.Column(
                "ip_address",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "user_agent",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column("payload", JSONB(), nullable=True),
            sa.Column(
                "ts",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.ForeignKeyConstraint(
                ["campaign_id"],
                ["phishing_campaigns.id"],
                ondelete="CASCADE",
            ),
            sa.ForeignKeyConstraint(
                ["target_id"],
                ["phishing_targets.id"],
                ondelete="SET NULL",
            ),
        )
        op.create_index(
            "ix_phishing_results_campaign_ts",
            "phishing_results",
            ["campaign_id", "ts"],
        )
        op.create_index(
            "ix_phishing_results_campaign_event",
            "phishing_results",
            ["campaign_id", "event_type"],
        )


def downgrade() -> None:
    op.drop_index(
        "ix_phishing_results_campaign_event", table_name="phishing_results"
    )
    op.drop_index(
        "ix_phishing_results_campaign_ts", table_name="phishing_results"
    )
    op.drop_table("phishing_results")
    op.drop_index(
        "ix_phishing_targets_last_status", table_name="phishing_targets"
    )
    op.drop_index(
        "ix_phishing_targets_campaign_email", table_name="phishing_targets"
    )
    op.drop_table("phishing_targets")
    op.drop_index(
        "ix_phishing_campaigns_created_at", table_name="phishing_campaigns"
    )
    op.drop_index(
        "ix_phishing_campaigns_status", table_name="phishing_campaigns"
    )
    op.drop_index(
        "ix_phishing_campaigns_engagement", table_name="phishing_campaigns"
    )
    op.drop_table("phishing_campaigns")
