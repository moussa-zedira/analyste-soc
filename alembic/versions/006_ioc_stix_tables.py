"""Tables IOC, relations, sightings, feeds, collections STIX/TAXII.

Revision ID: 006
Revises: 005
Create Date: 2026-03-29
"""

from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── IOCs ──
    op.create_table(
        "iocs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("state", sa.String(20), server_default="active"),
        sa.Column("confidence", sa.Integer(), server_default="50"),
        sa.Column("tlp", sa.String(20), server_default="AMBER"),
        sa.Column("source", sa.String(255), server_default="manual"),
        sa.Column("tags_json", sa.Text(), nullable=True),
        sa.Column("mitre_techniques_json", sa.Text(), nullable=True),
        sa.Column("kill_chain_phase", sa.String(64), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("stix_id", sa.String(128), nullable=True, unique=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expiry", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_iocs_type", "iocs", ["type"])
    op.create_index("ix_iocs_value", "iocs", ["value"])
    op.create_index("ix_iocs_state", "iocs", ["state"])

    # ── IOC Relationships ──
    op.create_table(
        "ioc_relationships",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("source_ioc_id", sa.Integer(), sa.ForeignKey("iocs.id", ondelete="CASCADE")),
        sa.Column("target_ioc_id", sa.Integer(), sa.ForeignKey("iocs.id", ondelete="CASCADE")),
        sa.Column("relationship_type", sa.String(64), nullable=False),
        sa.Column("confidence", sa.Integer(), server_default="50"),
        sa.Column("stix_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_iocrel_src", "ioc_relationships", ["source_ioc_id"])
    op.create_index("ix_iocrel_tgt", "ioc_relationships", ["target_ioc_id"])

    # ── IOC Sightings ──
    op.create_table(
        "ioc_sightings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ioc_id", sa.Integer(), sa.ForeignKey("iocs.id", ondelete="CASCADE")),
        sa.Column("event_id", sa.String(128), nullable=True),
        sa.Column("source", sa.String(255), server_default="internal"),
        sa.Column("count", sa.Integer(), server_default="1"),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_iocsight_ioc", "ioc_sightings", ["ioc_id"])

    # ── Threat Feeds ──
    op.create_table(
        "threat_feeds",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), unique=True, nullable=False),
        sa.Column("url", sa.Text(), nullable=False),
        sa.Column("feed_type", sa.String(32), nullable=False),
        sa.Column("interval_minutes", sa.Integer(), server_default="60"),
        sa.Column("enabled", sa.Boolean(), server_default="1"),
        sa.Column("auth_type", sa.String(32), nullable=True),
        sa.Column("auth_config_json", sa.Text(), nullable=True),
        sa.Column("default_tlp", sa.String(20), server_default="AMBER"),
        sa.Column("default_confidence", sa.Integer(), server_default="50"),
        sa.Column("config_json", sa.Text(), nullable=True),
        sa.Column("last_poll", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("ioc_count", sa.Integer(), server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )

    # ── STIX Collections ──
    op.create_table(
        "stix_collections",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("collection_id", sa.String(128), unique=True, nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("can_read", sa.Boolean(), server_default="1"),
        sa.Column("can_write", sa.Boolean(), server_default="0"),
        sa.Column("media_types_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_stixcol_cid", "stix_collections", ["collection_id"])

    # ── STIX Objects ──
    op.create_table(
        "stix_objects",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("collection_id", sa.String(128), sa.ForeignKey("stix_collections.collection_id", ondelete="CASCADE")),
        sa.Column("stix_id", sa.String(128), nullable=False),
        sa.Column("stix_type", sa.String(64), nullable=False),
        sa.Column("spec_version", sa.String(8), server_default="2.1"),
        sa.Column("stix_version", sa.String(64), nullable=True),
        sa.Column("object_json", sa.Text(), nullable=False),
        sa.Column("added", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_stixobj_col", "stix_objects", ["collection_id"])
    op.create_index("ix_stixobj_sid", "stix_objects", ["stix_id"])
    op.create_index("ix_stixobj_type", "stix_objects", ["stix_type"])


def downgrade() -> None:
    op.drop_table("stix_objects")
    op.drop_table("stix_collections")
    op.drop_table("threat_feeds")
    op.drop_table("ioc_sightings")
    op.drop_table("ioc_relationships")
    op.drop_table("iocs")
