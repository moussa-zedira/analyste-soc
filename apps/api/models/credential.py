"""Coffre-fort des credentials red team (V4.7 Lot A).

Persiste les secrets extraits durant un engagement : hashes NTLM/Kerberos,
cookies navigateur, tokens OAuth, cles SSH, etc. Toutes les entrees sont
rattachees a un engagement pour tracabilite + kill-switch propagation.

Deux tables :
- harvested_credentials : 1 row = 1 secret extrait (dedup par fingerprint)
- exfil_transfers       : journal des exfiltrations cloud (S3/GDrive/etc.)
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class HarvestedCredential(Base):
    """Un secret extrait pendant un engagement (hash/cookie/token/key)."""

    __tablename__ = "harvested_credentials"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    engagement_id: Mapped[str | None] = mapped_column(
        Text,
        ForeignKey("engagements.id", ondelete="SET NULL"),
        nullable=True,
    )
    source: Mapped[str] = mapped_column(Text, nullable=False)
    # secretsdump | browser_chromium | browser_firefox | oauth_token | ssh_key | other
    cred_type: Mapped[str] = mapped_column(Text, nullable=False)
    # ntlm | kerberos_tgs | kerberos_asrep | dcc2 | cleartext | cookie | token | key
    target: Mapped[str] = mapped_column(Text, nullable=False, default="")
    identifier: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # username / email / domain\\user / cookie host
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    # sha256(source|cred_type|identifier|secret-head) pour dedup idempotent
    data: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # contenu structure (hash, cookie value, etc.) — peut etre redige en sortie
    mitre_technique: Mapped[str] = mapped_column(Text, nullable=False, default="")
    harvested_by: Mapped[str | None] = mapped_column(
        Text, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    harvested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    __table_args__ = (
        UniqueConstraint("engagement_id", "fingerprint", name="uq_cred_engagement_fp"),
        Index("ix_credential_engagement", "engagement_id"),
        Index("ix_credential_type", "cred_type"),
        Index("ix_credential_harvested_at", "harvested_at"),
    )


class ExfilTransfer(Base):
    """Journal d'un transfert d'exfiltration cloud (T1537)."""

    __tablename__ = "exfil_transfers"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    engagement_id: Mapped[str | None] = mapped_column(
        Text,
        ForeignKey("engagements.id", ondelete="SET NULL"),
        nullable=True,
    )
    channel: Mapped[str] = mapped_column(Text, nullable=False)
    # s3 | gcs | azure_blob | gdrive | onedrive | dropbox | webhook
    destination: Mapped[str] = mapped_column(Text, nullable=False)
    # bucket/folder ou URL de destination
    object_key: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # clef (chemin) de l'objet transfere
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    content_type: Mapped[str] = mapped_column(Text, nullable=False, default="")
    sha256: Mapped[str] = mapped_column(Text, nullable=False, default="")
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    # pending | uploading | ok | error | aborted
    error: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mitre_technique: Mapped[str] = mapped_column(Text, nullable=False, default="T1537")
    initiated_by: Mapped[str | None] = mapped_column(
        Text, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    response_meta: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    __table_args__ = (
        Index("ix_exfil_engagement", "engagement_id"),
        Index("ix_exfil_status", "status"),
        Index("ix_exfil_channel", "channel"),
        Index("ix_exfil_started_at", "started_at"),
    )
