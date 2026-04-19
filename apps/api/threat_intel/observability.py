"""Observabilite Prometheus + Circuit Breaker pour les providers Threat Intel.

Expose:
- Metriques Prometheus (compteurs, histogrammes, gauges) pour suivre chaque
  provider externe (latence, succes/erreur, etat du circuit, rate-limit).
- Decorateur ``@instrument(provider, operation)`` pour wrapper les methodes
  publiques async des providers.
- Classe ``CircuitBreaker`` (implementation maison, sans dependance externe)
  avec etats CLOSED -> OPEN -> HALF_OPEN -> CLOSED.

Conventions de labels :
- ``provider`` : nom court du provider (otx, virustotal, abuseipdb, ...).
- ``operation`` : action logique (check_ip, check_domain, search_hosts, ...).
- ``result`` : ``success`` | ``error`` | ``cache_hit`` | ``rate_limited``
  | ``circuit_open``.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import time
from enum import IntEnum
from typing import Any, Awaitable, Callable, TypeVar

import httpx
from prometheus_client import Counter, Gauge, Histogram

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ─────────────────────────────────────────────────────────────────────
# Metriques Prometheus (registry par defaut, expose via /metrics)
# ─────────────────────────────────────────────────────────────────────

ti_provider_requests_total = Counter(
    "ti_provider_requests_total",
    "Nombre total d'appels aux providers Threat Intel par resultat.",
    labelnames=("provider", "result"),
)

ti_provider_latency_seconds = Histogram(
    "ti_provider_latency_seconds",
    "Latence des appels aux providers Threat Intel (seconds).",
    labelnames=("provider", "operation"),
    buckets=(0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60),
)

ti_provider_rate_limit_remaining = Gauge(
    "ti_provider_rate_limit_remaining",
    "Quota restant rapporte par le provider (si disponible).",
    labelnames=("provider",),
)

ti_provider_circuit_state = Gauge(
    "ti_provider_circuit_state",
    "Etat du circuit breaker du provider : 0=closed, 1=open, 2=half-open.",
    labelnames=("provider",),
)


def record_result(provider: str, result: str) -> None:
    """Increment le compteur de resultat pour un provider."""
    ti_provider_requests_total.labels(provider=provider, result=result).inc()


def set_rate_limit_remaining(provider: str, remaining: float) -> None:
    """Met a jour la jauge de quota restant pour un provider."""
    try:
        ti_provider_rate_limit_remaining.labels(provider=provider).set(float(remaining))
    except Exception as exc:
        logger.debug("Failed to set rate_limit_remaining metric for %s: %s", provider, exc)


# ─────────────────────────────────────────────────────────────────────
# Circuit Breaker maison
# ─────────────────────────────────────────────────────────────────────


class CircuitState(IntEnum):
    CLOSED = 0
    OPEN = 1
    HALF_OPEN = 2


class CircuitOpenError(Exception):
    """Levee quand un appel est rejete car le circuit est OPEN."""


class CircuitBreaker:
    """Circuit breaker simple, asynchrone, par provider.

    Etats :
    - CLOSED   : tous les appels passent. Apres ``failure_threshold`` echecs
                 consecutifs, on bascule en OPEN.
    - OPEN     : tous les appels sont rejetes immediatement avec
                 CircuitOpenError, jusqu'a ce que ``recovery_timeout``
                 secondes soient ecoulees -> HALF_OPEN.
    - HALF_OPEN: on autorise jusqu'a ``half_open_max_calls`` appels d'essai.
                 Un succes -> CLOSED. Un echec -> OPEN.
    """

    def __init__(
        self,
        provider: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 2,
    ) -> None:
        self.provider = provider
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        self._state: CircuitState = CircuitState.CLOSED
        self._failure_count: int = 0
        self._opened_at: float = 0.0
        self._half_open_calls: int = 0
        self._lock = asyncio.Lock()

        # Initialise la jauge a CLOSED (0).
        self._publish_state()

    # ── Etat / metriques ───────────────────────────────────────────

    def _publish_state(self) -> None:
        try:
            ti_provider_circuit_state.labels(provider=self.provider).set(int(self._state))
        except Exception as exc:
            logger.debug("Failed to publish circuit state metric for %s: %s", self.provider, exc)

    @property
    def state(self) -> CircuitState:
        return self._state

    # ── Transitions ────────────────────────────────────────────────

    def _trip_open(self) -> None:
        if self._state != CircuitState.OPEN:
            logger.warning(
                "Circuit breaker OPEN for %s (failures=%d)",
                self.provider, self._failure_count,
            )
        self._state = CircuitState.OPEN
        self._opened_at = time.monotonic()
        self._half_open_calls = 0
        self._publish_state()

    def _close(self) -> None:
        if self._state != CircuitState.CLOSED:
            logger.info("Circuit breaker CLOSED for %s", self.provider)
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._half_open_calls = 0
        self._publish_state()

    def _half_open(self) -> None:
        logger.info("Circuit breaker HALF_OPEN for %s", self.provider)
        self._state = CircuitState.HALF_OPEN
        self._half_open_calls = 0
        self._publish_state()

    # ── API publique ───────────────────────────────────────────────

    async def _before_call(self) -> None:
        """Verifie l'etat avant un appel ; leve CircuitOpenError si rejete."""
        async with self._lock:
            if self._state == CircuitState.OPEN:
                if time.monotonic() - self._opened_at >= self.recovery_timeout:
                    self._half_open()
                else:
                    record_result(self.provider, "circuit_open")
                    raise CircuitOpenError(
                        f"Circuit breaker OPEN for provider '{self.provider}'"
                    )
            if self._state == CircuitState.HALF_OPEN:
                if self._half_open_calls >= self.half_open_max_calls:
                    record_result(self.provider, "circuit_open")
                    raise CircuitOpenError(
                        f"Circuit breaker HALF_OPEN limit reached for '{self.provider}'"
                    )
                self._half_open_calls += 1

    async def record_success(self) -> None:
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._close()
            else:
                # En CLOSED, on remet le compteur d'echecs a zero.
                self._failure_count = 0

    async def record_failure(self) -> None:
        async with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._trip_open()
                return
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._trip_open()

    async def call(
        self,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Execute ``func`` au travers du circuit breaker.

        - Verifie l'etat avant l'appel.
        - Considere comme echec : httpx.HTTPError, asyncio.TimeoutError,
          ainsi que les reponses HTTP 429/5xx (sur ``raise_for_status``).
        - Considere comme succes : tout retour normal.
        """
        await self._before_call()
        try:
            result = await func(*args, **kwargs)
        except CircuitOpenError:
            raise
        except (httpx.HTTPError, asyncio.TimeoutError, OSError) as exc:
            await self.record_failure()
            # Si c'est une reponse HTTP, on regarde le code pour distinguer
            # rate-limit (429) vs erreur reseau.
            if isinstance(exc, httpx.HTTPStatusError):
                code = exc.response.status_code
                if code == 429:
                    record_result(self.provider, "rate_limited")
                else:
                    record_result(self.provider, "error")
            else:
                record_result(self.provider, "error")
            raise
        except Exception:
            await self.record_failure()
            record_result(self.provider, "error")
            raise

        # Si c'est une httpx.Response, on verifie le code de retour pour
        # alimenter le compteur d'echecs sans masquer la reponse.
        if isinstance(result, httpx.Response):
            code = result.status_code
            if code == 429:
                await self.record_failure()
                record_result(self.provider, "rate_limited")
            elif 500 <= code < 600:
                await self.record_failure()
                record_result(self.provider, "error")
            else:
                await self.record_success()
        else:
            await self.record_success()
        return result


# ─────────────────────────────────────────────────────────────────────
# Registry global de circuit breakers (un par provider)
# ─────────────────────────────────────────────────────────────────────

_CIRCUIT_BREAKERS: dict[str, CircuitBreaker] = {}


def get_circuit_breaker(
    provider: str,
    failure_threshold: int = 5,
    recovery_timeout: float = 60.0,
    half_open_max_calls: int = 2,
) -> CircuitBreaker:
    """Retourne (et cree au besoin) le CircuitBreaker singleton du provider."""
    cb = _CIRCUIT_BREAKERS.get(provider)
    if cb is None:
        cb = CircuitBreaker(
            provider=provider,
            failure_threshold=failure_threshold,
            recovery_timeout=recovery_timeout,
            half_open_max_calls=half_open_max_calls,
        )
        _CIRCUIT_BREAKERS[provider] = cb
    return cb


def reset_circuit_breakers() -> None:
    """Utilitaire pour les tests : remet a zero tous les CB."""
    _CIRCUIT_BREAKERS.clear()


# ─────────────────────────────────────────────────────────────────────
# Decorateur d'instrumentation
# ─────────────────────────────────────────────────────────────────────


def instrument(
    provider: str,
    operation: str,
) -> Callable[[Callable[..., Awaitable[T]]], Callable[..., Awaitable[T]]]:
    """Decorateur pour mesurer la latence + result d'une methode async.

    Usage :
        @instrument("otx", "check_ip")
        async def check_ip(self, ip): ...

    Le decorateur :
    - Mesure la latence dans ``ti_provider_latency_seconds``.
    - Incremente ``ti_provider_requests_total`` avec ``result`` =
      ``success`` (retour non-None) | ``cache_hit`` (retour avec attribut
      ``cached``) | ``circuit_open`` (CircuitOpenError) | ``error`` (toute
      autre exception ou retour None).
    """

    def decorator(func: Callable[..., Awaitable[T]]) -> Callable[..., Awaitable[T]]:
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> T:
            start = time.perf_counter()
            result_label = "error"
            try:
                value = await func(*args, **kwargs)
                if value is None:
                    result_label = "error"
                else:
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
            except (httpx.HTTPError, asyncio.TimeoutError, OSError):
                result_label = "error"
                raise
            except Exception:
                result_label = "error"
                raise
            finally:
                elapsed = time.perf_counter() - start
                try:
                    ti_provider_latency_seconds.labels(
                        provider=provider, operation=operation,
                    ).observe(elapsed)
                    record_result(provider, result_label)
                except Exception as exc:
                    logger.debug("Failed to record instrument metrics for %s/%s: %s", provider, operation, exc)

        return wrapper

    return decorator


__all__ = [
    "CircuitBreaker",
    "CircuitOpenError",
    "CircuitState",
    "get_circuit_breaker",
    "reset_circuit_breakers",
    "instrument",
    "record_result",
    "set_rate_limit_remaining",
    "ti_provider_requests_total",
    "ti_provider_latency_seconds",
    "ti_provider_rate_limit_remaining",
    "ti_provider_circuit_state",
]
