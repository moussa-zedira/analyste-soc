"""Modeles BloodHound dataset (V4.5).

Importe les dumps BloodHound CE v5 (graphe AD) en DB pour les correler
avec les sessions Sliver actives et suggerer des chemins d'attaque
THEORIQUES (read-only, jamais d'execution implicite).

Trois tables :
- bh_datasets : un dump = un graphe (lie eventuellement a un engagement)
- bh_nodes    : User / Computer / Group / Domain / OU / GPO
- bh_edges    : MemberOf / AdminTo / HasSession / GenericAll / WriteDacl /
                ForceChangePassword / AddMember / CanRDP / CanPSRemote /
                ExecuteDCOM / AllowedToDelegate / Owns / WriteOwner / ...
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class BHDataset(Base):
    """Un dump BloodHound importe (zip BH v5 -> nodes + edges)."""

    __tablename__ = "bh_datasets"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    source_filename: Mapped[str] = mapped_column(
        Text, nullable=False, default=""
    )
    engagement_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("engagements.id", ondelete="SET NULL"), nullable=True
    )
    bh_schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=5
    )
    nodes_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    edges_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    uploaded_by: Mapped[str | None] = mapped_column(
        Text, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_bh_datasets_engagement", "engagement_id"),
        Index("ix_bh_datasets_uploaded_at", "uploaded_at"),
    )


class BHNode(Base):
    """Un objet AD (User/Computer/Group/Domain/OU/GPO) du graphe."""

    __tablename__ = "bh_nodes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dataset_id: Mapped[str] = mapped_column(
        Text, ForeignKey("bh_datasets.id", ondelete="CASCADE"), nullable=False
    )
    sid: Mapped[str] = mapped_column(Text, nullable=False)
    object_type: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    domain: Mapped[str] = mapped_column(Text, nullable=False, default="")
    high_value: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    props: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        UniqueConstraint(
            "dataset_id", "sid", name="uq_bh_nodes_dataset_sid"
        ),
        Index("ix_bh_nodes_dataset_type", "dataset_id", "object_type"),
        Index("ix_bh_nodes_dataset_name", "dataset_id", "name"),
        Index("ix_bh_nodes_high_value", "dataset_id", "high_value"),
    )


class BHEdge(Base):
    """Une relation orientee entre deux noeuds (MemberOf, AdminTo, ACL...)."""

    __tablename__ = "bh_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dataset_id: Mapped[str] = mapped_column(
        Text, ForeignKey("bh_datasets.id", ondelete="CASCADE"), nullable=False
    )
    source_sid: Mapped[str] = mapped_column(Text, nullable=False)
    target_sid: Mapped[str] = mapped_column(Text, nullable=False)
    edge_type: Mapped[str] = mapped_column(Text, nullable=False)
    props: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_bh_edges_source", "dataset_id", "source_sid"),
        Index("ix_bh_edges_target", "dataset_id", "target_sid"),
        Index("ix_bh_edges_type", "dataset_id", "edge_type"),
    )
