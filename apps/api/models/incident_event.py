"""Table d'association reliant incidents et événements (many-to-many)."""

from __future__ import annotations

from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class IncidentEvent(Base):
    """Liaison many-to-many entre incidents et événements."""

    __tablename__ = "incident_events"

    incident_id: Mapped[str] = mapped_column(Text, ForeignKey("incidents.id"), primary_key=True)
    event_id: Mapped[str] = mapped_column(Text, ForeignKey("events.id"), primary_key=True)
