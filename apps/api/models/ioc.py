"""Modeles SQLAlchemy pour la gestion des IOC, feeds TAXII et graphe de relations."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.db.base import Base


class IOC(Base):
    """Indicator of Compromise — entite centrale de la gestion TI."""

    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[str] = mapped_column(String(32), index=True)  # ip, domain, url, hash_md5, ...
    value: Mapped[str] = mapped_column(Text, index=True)
    state: Mapped[str] = mapped_column(
        String(20), default="active", index=True
    )  # active, expired, revoked, false_positive
    confidence: Mapped[int] = mapped_column(Integer, default=50)  # 0-100
    tlp: Mapped[str] = mapped_column(
        String(20), default="AMBER"
    )  # WHITE, GREEN, AMBER, AMBER+STRICT, RED
    source: Mapped[str] = mapped_column(String(255), default="manual")
    tags_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    mitre_techniques_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array
    kill_chain_phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON dict
    stix_id: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    sightings: Mapped[list[IOCSighting]] = relationship(
        back_populates="ioc", cascade="all, delete-orphan"
    )


class IOCRelationship(Base):
    """Relation entre deux IOC (graphe)."""

    __tablename__ = "ioc_relationships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_ioc_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("iocs.id", ondelete="CASCADE"), index=True
    )
    target_ioc_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("iocs.id", ondelete="CASCADE"), index=True
    )
    relationship_type: Mapped[str] = mapped_column(
        String(64)
    )  # related-to, derived-from, uses, etc.
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    stix_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class IOCSighting(Base):
    """Observation d'un IOC dans un evenement."""

    __tablename__ = "ioc_sightings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("iocs.id", ondelete="CASCADE"), index=True
    )
    event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    source: Mapped[str] = mapped_column(String(255), default="internal")
    count: Mapped[int] = mapped_column(Integer, default=1)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    ioc: Mapped[IOC] = relationship(back_populates="sightings")


class ThreatFeed(Base):
    """Source de flux de menaces configuree."""

    __tablename__ = "threat_feeds"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    url: Mapped[str] = mapped_column(Text)
    feed_type: Mapped[str] = mapped_column(String(32))  # taxii, stix_url, csv_url, misp, plaintext
    interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    auth_type: Mapped[str | None] = mapped_column(
        String(32), nullable=True
    )  # basic, api_key, cert, none
    auth_config_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    default_tlp: Mapped[str] = mapped_column(String(20), default="AMBER")
    default_confidence: Mapped[int] = mapped_column(Integer, default=50)
    config_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON extra config
    last_poll: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_success: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    ioc_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class STIXCollection(Base):
    """Collection TAXII 2.1 servie par notre serveur."""

    __tablename__ = "stix_collections"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    collection_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    can_read: Mapped[bool] = mapped_column(Boolean, default=True)
    can_write: Mapped[bool] = mapped_column(Boolean, default=False)
    media_types_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class STIXObject(Base):
    """Objet STIX stocke dans une collection TAXII."""

    __tablename__ = "stix_objects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    collection_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("stix_collections.collection_id", ondelete="CASCADE"), index=True
    )
    stix_id: Mapped[str] = mapped_column(String(128), index=True)
    stix_type: Mapped[str] = mapped_column(String(64), index=True)
    spec_version: Mapped[str] = mapped_column(String(8), default="2.1")
    stix_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    object_json: Mapped[str] = mapped_column(Text)  # full STIX JSON
    added: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
