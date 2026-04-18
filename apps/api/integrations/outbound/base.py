"""Base abstract OutboundConnector for ticketing integrations."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

HTTP_TIMEOUT_SECONDS = 15.0


class OutboundConnector(ABC):
    """Abstract base for outbound ticketing connectors."""

    name: str = "base"

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config or {}

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if mandatory config fields are present and well-formed."""

    @abstractmethod
    async def create_ticket(self, incident: dict[str, Any]) -> dict[str, Any]:
        """Create a ticket from an incident dict.

        Returns dict with keys: external_id (str), url (str), status (str).
        Raises on failure.
        """

    @abstractmethod
    async def sync_status(self, ticket: dict[str, Any]) -> str:
        """Fetch current status from external system. Returns the status string."""

    def _safe_str(self, value: Any, fallback: str = "") -> str:
        if value is None:
            return fallback
        return str(value)
