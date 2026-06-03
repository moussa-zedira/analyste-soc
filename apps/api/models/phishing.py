"""Modeles GoPhish workflow enrichi (V4.6).

Persiste les campagnes de phishing lancees via GoPhish (outil tiers public),
ainsi que leurs cibles et le journal d'evenements (envoi, ouverture, clic,
soumission). Permet de :
- relier une campagne a un Engagement (V4.3b)
- generer des analytics (funnel, top clickers, taux par etape)
- auditer en MITRE T1566.001 (Spearphishing Attachment)

Trois tables :
- phishing_campaigns : metadata + counts agreges
- phishing_targets   : 1 entree par destinataire d'une campagne
- phishing_results   : event log brut (idempotent par dedup ts+target+type)
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from apps.api.db.base import Base


class PhishingCampaign(Base):
    """Une campagne GoPhish persistee localement (1 row = 1 send)."""

    __tablename__ = "phishing_campaigns"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    engagement_id: Mapped[str | None] = mapped_column(
        Text, ForeignKey("engagements.id", ondelete="SET NULL"), nullable=True
    )
    gophish_campaign_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="draft"
    )  # draft | sending | in-progress | completed | stopped | failed
    template_name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    landing_url: Mapped[str] = mapped_column(Text, nullable=False, default="")
    sent_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    opened_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    clicked_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    submitted_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    email_failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    launched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(
        Text, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    mitre_technique: Mapped[str] = mapped_column(Text, nullable=False, default="T1566.001")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    targets: Mapped[list[PhishingTarget]] = relationship(
        "PhishingTarget",
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    results: Mapped[list[PhishingResult]] = relationship(
        "PhishingResult",
        back_populates="campaign",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_phishing_campaigns_engagement", "engagement_id"),
        Index("ix_phishing_campaigns_status", "status"),
        Index("ix_phishing_campaigns_created_at", "created_at"),
    )


class PhishingTarget(Base):
    """Un destinataire d'une campagne (un email)."""

    __tablename__ = "phishing_targets"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    campaign_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey("phishing_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    email: Mapped[str] = mapped_column(Text, nullable=False)
    first_name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    position: Mapped[str] = mapped_column(Text, nullable=False, default="")
    group_name: Mapped[str] = mapped_column(Text, nullable=False, default="")
    last_status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    clicked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    campaign: Mapped[PhishingCampaign] = relationship("PhishingCampaign", back_populates="targets")

    __table_args__ = (
        Index("ix_phishing_targets_campaign_email", "campaign_id", "email"),
        Index("ix_phishing_targets_last_status", "campaign_id", "last_status"),
    )


class PhishingResult(Base):
    """Event log brut (Email Sent / Opened / Clicked Link / Submitted Data / Failed)."""

    __tablename__ = "phishing_results"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    campaign_id: Mapped[str] = mapped_column(
        Text,
        ForeignKey("phishing_campaigns.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_id: Mapped[str | None] = mapped_column(
        Text,
        ForeignKey("phishing_targets.id", ondelete="SET NULL"),
        nullable=True,
    )
    event_type: Mapped[str] = mapped_column(
        Text, nullable=False
    )  # email_sent | email_opened | clicked_link | submitted_data | email_failed
    ip_address: Mapped[str] = mapped_column(Text, nullable=False, default="")
    user_agent: Mapped[str] = mapped_column(Text, nullable=False, default="")
    payload: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    campaign: Mapped[PhishingCampaign] = relationship("PhishingCampaign", back_populates="results")

    __table_args__ = (
        Index("ix_phishing_results_campaign_ts", "campaign_id", "ts"),
        Index(
            "ix_phishing_results_campaign_event",
            "campaign_id",
            "event_type",
        ),
    )
