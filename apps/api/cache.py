"""Redis cache helper with graceful fallback."""

from __future__ import annotations

import json
import logging
from typing import Any

import redis

from apps.api.config import get_settings

logger = logging.getLogger(__name__)

_client: redis.Redis | None = None


def _get_redis() -> redis.Redis | None:
    """Return a Redis client, or None if unavailable."""
    global _client
    if _client is not None:
        return _client
    try:
        settings = get_settings()
        _client = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
            socket_connect_timeout=2,
        )
        _client.ping()
        return _client
    except Exception:
        logger.warning("Redis unavailable — cache disabled")
        _client = None
        return None


def get_cache(key: str) -> Any | None:
    """Get a cached value. Returns None on miss or if Redis is down."""
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(f"siem:{key}")
        if raw is None:
            return None
        return json.loads(raw)
    except Exception:
        return None


def set_cache(key: str, value: Any, ttl: int = 30) -> None:
    """Set a cached value with TTL in seconds."""
    r = _get_redis()
    if r is None:
        return
    try:
        r.setex(f"siem:{key}", ttl, json.dumps(value, default=str))
    except Exception:
        logger.debug("Failed to set cache for %s", key)


def invalidate(pattern: str) -> None:
    """Delete cache keys matching a pattern."""
    r = _get_redis()
    if r is None:
        return
    try:
        keys = r.keys(f"siem:{pattern}")
        if keys:
            r.delete(*keys)
    except Exception:
        logger.debug("Failed to invalidate cache pattern %s", pattern)


def get_redis_client() -> redis.Redis | None:
    """Expose the Redis client for health checks and pub/sub."""
    return _get_redis()
