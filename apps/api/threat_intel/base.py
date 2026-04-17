"""Interface de base pour les providers de Threat Intelligence."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Protocol, TypeVar

import httpx

from apps.api.threat_intel.observability import (
    CircuitBreaker,
    CircuitOpenError,
    get_circuit_breaker,
    record_result,
    ti_provider_latency_seconds,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


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


class BaseTIProvider:
    """Mixin reutilisable pour les providers TI.

    Fournit :
    - ``self._cb`` : circuit breaker dedie au provider.
    - ``self._call(operation, callable, *args, **kwargs)`` : helper qui
      mesure la latence, met a jour les compteurs Prometheus, route les
      erreurs httpx vers le circuit breaker.

    Les providers existants peuvent l'utiliser de maniere optionnelle :
    ils continuent de fonctionner s'ils n'en heritent pas (le decorateur
    ``@instrument`` couvre deja l'essentiel).
    """

    name: str = "unknown"

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # Le circuit breaker est resolu paresseusement pour respecter
        # l'ordre d'initialisation des sous-classes.
        self._cb: CircuitBreaker = get_circuit_breaker(self.name)

    async def _call(
        self,
        operation: str,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Execute ``func`` au travers du circuit breaker + metriques.

        Wrapper "tout-en-un" pour les appels httpx :
            resp = await self._call("ip_lookup", self._client.get, url)
        """
        import time
        start = time.perf_counter()
        result_label = "error"
        try:
            value = await self._cb.call(func, *args, **kwargs)
            result_label = "success"
            return value
        except CircuitOpenError:
            result_label = "circuit_open"
            raise
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                result_label = "rate_limited"
            else:
                result_label = "error"
            raise
        except (httpx.HTTPError, OSError):
            result_label = "error"
            raise
        finally:
            elapsed = time.perf_counter() - start
            try:
                ti_provider_latency_seconds.labels(
                    provider=self.name, operation=operation,
                ).observe(elapsed)
                record_result(self.name, result_label)
            except Exception:
                pass
