"""Modele Finding — resultats unifies de tous les modules pentest."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    func,
)

from apps.api.db.base import Base


class Finding(Base):
    """Finding unifie issu de n'importe quel module pentest."""

    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    session_id = Column(String, index=True)
    module = Column(String, index=True)
    finding_type = Column(String, index=True)
    severity = Column(String)
    title = Column(String)
    description = Column(Text)
    target = Column(String)
    evidence = Column(Text)
    exploitable = Column(Boolean, default=False)
    exploited = Column(Boolean, default=False)
    cvss_score = Column(Float, nullable=True)
    cwe_id = Column(String, nullable=True)
    mitre_technique = Column(String, nullable=True)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
