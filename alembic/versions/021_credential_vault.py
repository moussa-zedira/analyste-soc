"""021 Credential vault + exfil transfers (V4.7 Lot A).

Tables harvested_credentials / exfil_transfers.

Revision ID: 021
Revises: 020
Create Date: 2026-04-18
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


revision = "021"
down_revision = "020"
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

    if not _has_table(bind, "harvested_credentials"):
        op.create_table(
            "harvested_credentials",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "engagement_id",
                sa.Text(),
                sa.ForeignKey("engagements.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("source", sa.Text(), nullable=False),
            sa.Column("cred_type", sa.Text(), nullable=False),
            sa.Column(
                "target", sa.Text(), nullable=False, server_default=""
            ),
            sa.Column(
                "identifier", sa.Text(), nullable=False, server_default=""
            ),
            sa.Column("fingerprint", sa.Text(), nullable=False),
            sa.Column("data", JSONB(), nullable=True),
            sa.Column(
                "mitre_technique",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column(
                "harvested_by",
                sa.Text(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "harvested_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column("notes", sa.Text(), nullable=False, server_default=""),
            sa.UniqueConstraint(
                "engagement_id",
                "fingerprint",
                name="uq_cred_engagement_fp",
            ),
        )
        op.create_index(
            "ix_credential_engagement",
            "harvested_credentials",
            ["engagement_id"],
        )
        op.create_index(
            "ix_credential_type", "harvested_credentials", ["cred_type"]
        )
        op.create_index(
            "ix_credential_harvested_at",
            "harvested_credentials",
            ["harvested_at"],
        )

    if not _has_table(bind, "exfil_transfers"):
        op.create_table(
            "exfil_transfers",
            sa.Column("id", sa.Text(), primary_key=True),
            sa.Column(
                "engagement_id",
                sa.Text(),
                sa.ForeignKey("engagements.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("channel", sa.Text(), nullable=False),
            sa.Column("destination", sa.Text(), nullable=False),
            sa.Column(
                "object_key", sa.Text(), nullable=False, server_default=""
            ),
            sa.Column(
                "size_bytes",
                sa.BigInteger(),
                nullable=False,
                server_default="0",
            ),
            sa.Column(
                "content_type",
                sa.Text(),
                nullable=False,
                server_default="",
            ),
            sa.Column("sha256", sa.Text(), nullable=False, server_default=""),
            sa.Column(
                "status",
                sa.Text(),
                nullable=False,
                server_default="pending",
            ),
            sa.Column("error", sa.Text(), nullable=False, server_default=""),
            sa.Column(
                "mitre_technique",
                sa.Text(),
                nullable=False,
                server_default="T1537",
            ),
            sa.Column(
                "initiated_by",
                sa.Text(),
                sa.ForeignKey("users.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "started_at",
                sa.DateTime(timezone=True),
                nullable=False,
            ),
            sa.Column(
                "completed_at",
                sa.DateTime(timezone=True),
                nullable=True,
            ),
            sa.Column("response_meta", JSONB(), nullable=True),
        )
        op.create_index(
            "ix_exfil_engagement", "exfil_transfers", ["engagement_id"]
        )
        op.create_index("ix_exfil_status", "exfil_transfers", ["status"])
        op.create_index("ix_exfil_channel", "exfil_transfers", ["channel"])
        op.create_index(
            "ix_exfil_started_at", "exfil_transfers", ["started_at"]
        )


def downgrade() -> None:
    bind = op.get_bind()
    if _has_table(bind, "exfil_transfers"):
        op.drop_index("ix_exfil_started_at", table_name="exfil_transfers")
        op.drop_index("ix_exfil_channel", table_name="exfil_transfers")
        op.drop_index("ix_exfil_status", table_name="exfil_transfers")
        op.drop_index("ix_exfil_engagement", table_name="exfil_transfers")
        op.drop_table("exfil_transfers")
    if _has_table(bind, "harvested_credentials"):
        op.drop_index(
            "ix_credential_harvested_at", table_name="harvested_credentials"
        )
        op.drop_index("ix_credential_type", table_name="harvested_credentials")
        op.drop_index(
            "ix_credential_engagement", table_name="harvested_credentials"
        )
        op.drop_table("harvested_credentials")
