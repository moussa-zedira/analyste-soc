"""OpenTelemetry tracing (env-gated).

Activation : exporter OTLP renseigne dans ``OTEL_EXPORTER_OTLP_ENDPOINT``.
Sans endpoint, ``setup_tracing`` est un no-op (pas d'overhead, pas de span).

L'instrumentation FastAPI/SQLAlchemy/Celery/Redis/HTTPX se branche
automatiquement et propage le ``traceparent`` W3C entre services.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)

_INITIALISED = False


def setup_tracing(app: FastAPI) -> bool:
    """Initialise OTel si un endpoint OTLP est configure. Retourne True si actif.

    Idempotent : appels multiples sans effet.
    """
    global _INITIALISED
    if _INITIALISED:
        return True

    from apps.api.config import get_settings

    settings = get_settings()
    endpoint = settings.OTEL_EXPORTER_OTLP_ENDPOINT.strip()
    if not endpoint:
        logger.info("otel_disabled_no_endpoint")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.redis import RedisInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased
    except ImportError as exc:
        logger.warning("otel_import_failed", extra={"error": str(exc)})
        return False

    resource = Resource.create({
        "service.name": settings.OTEL_SERVICE_NAME,
        "service.version": "1.0.0",
        "deployment.environment": settings.ENV,
    })
    sampler = TraceIdRatioBased(max(0.0, min(1.0, settings.OTEL_TRACES_SAMPLER_RATIO)))
    provider = TracerProvider(resource=resource, sampler=sampler)
    exporter = OTLPSpanExporter(
        endpoint=endpoint,
        insecure=settings.OTEL_EXPORTER_OTLP_INSECURE,
    )
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    # /metrics et /healthz: pas de span (bruit pur).
    FastAPIInstrumentor.instrument_app(
        app, excluded_urls="/metrics,/health,/livez,/readyz"
    )

    # SQLAlchemy : instrumentation au niveau du moteur applicatif.
    try:
        from apps.api.db.session import engine

        SQLAlchemyInstrumentor().instrument(engine=engine)
    except Exception as exc:  # noqa: BLE001
        logger.warning("otel_sqlalchemy_instrument_failed", extra={"error": str(exc)})

    RedisInstrumentor().instrument()
    HTTPXClientInstrumentor().instrument()

    # Celery est instrumente cote worker (cf celery_app.py).
    _INITIALISED = True
    logger.info(
        "otel_enabled",
        extra={
            "endpoint": endpoint,
            "service": settings.OTEL_SERVICE_NAME,
            "sampler_ratio": settings.OTEL_TRACES_SAMPLER_RATIO,
        },
    )
    return True


def get_tracer(name: str = "cyberdef"):
    """Retourne un tracer OTel. No-op si OTel desactive."""
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        return _NoopTracer()


class _NoopSpan:
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def set_attribute(self, *args, **kwargs): pass
    def set_status(self, *args, **kwargs): pass
    def record_exception(self, *args, **kwargs): pass
    def add_event(self, *args, **kwargs): pass


class _NoopTracer:
    def start_as_current_span(self, *args, **kwargs):
        return _NoopSpan()


def traced(name: str | None = None, *, attributes: dict | None = None):
    """Decorateur span pour fonctions sync ou async.

    Capture exceptions et marque le span en erreur. Le name par defaut
    est `module.qualname` de la fonction.
    """
    import functools
    import inspect

    def decorator(fn):
        span_name = name or f"{fn.__module__}.{fn.__qualname__}"
        is_async = inspect.iscoroutinefunction(fn)

        if is_async:
            @functools.wraps(fn)
            async def awrap(*args, **kwargs):
                tracer = get_tracer()
                with tracer.start_as_current_span(span_name) as span:
                    if attributes:
                        for k, v in attributes.items():
                            span.set_attribute(k, v)
                    try:
                        return await fn(*args, **kwargs)
                    except Exception as exc:
                        try:
                            span.record_exception(exc)
                            from opentelemetry.trace import Status, StatusCode
                            span.set_status(Status(StatusCode.ERROR, str(exc)))
                        except Exception:
                            logger.debug("tracing: ignored exception", exc_info=True)
                        raise
            return awrap

        @functools.wraps(fn)
        def swrap(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(span_name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, v)
                try:
                    return fn(*args, **kwargs)
                except Exception as exc:
                    try:
                        span.record_exception(exc)
                        from opentelemetry.trace import Status, StatusCode
                        span.set_status(Status(StatusCode.ERROR, str(exc)))
                    except Exception:
                        logger.debug("tracing: ignored exception", exc_info=True)
                    raise
        return swrap

    return decorator


def setup_celery_tracing() -> bool:
    """Variante worker : pas de FastAPI, juste Celery + SQLAlchemy + Redis."""
    global _INITIALISED
    if _INITIALISED:
        return True

    from apps.api.config import get_settings

    settings = get_settings()
    endpoint = settings.OTEL_EXPORTER_OTLP_ENDPOINT.strip()
    if not endpoint:
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.celery import CeleryInstrumentor
        from opentelemetry.instrumentation.redis import RedisInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return False

    resource = Resource.create({
        "service.name": f"{settings.OTEL_SERVICE_NAME}-worker",
        "deployment.environment": settings.ENV,
    })
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(
        OTLPSpanExporter(endpoint=endpoint, insecure=settings.OTEL_EXPORTER_OTLP_INSECURE)
    ))
    trace.set_tracer_provider(provider)

    CeleryInstrumentor().instrument()
    try:
        from apps.api.db.session import engine
        SQLAlchemyInstrumentor().instrument(engine=engine)
    except Exception:  # noqa: BLE001
        pass
    RedisInstrumentor().instrument()
    _INITIALISED = True
    return True
