"""Interface de base pour les providers de Threat Intelligence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class TIResult:
    """Resultat d'un lookup Threat Intelligence."""

    indicator: str
    source: str
    risk_score: int = 0  # 0-100
    is_malicious: bool = False
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    total_reports: int = 0
    raw: dict | None = None


class TIProvider(Protocol):
    """Interface pour les providers TI."""

    name: str

    async def check_ip(self, ip: str) -> TIResult | None:
        """Verifie une adresse IP. Retourne None si erreur ou rate-limited."""
        ...
