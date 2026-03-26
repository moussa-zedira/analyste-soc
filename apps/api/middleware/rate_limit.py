"""Rate limiting middleware using slowapi."""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["60/minute"],
    storage_uri=None,  # Set to Redis URL in setup_rate_limiter()
)


def setup_rate_limiter(redis_url: str | None = None) -> None:
    """Reconfigure limiter to use Redis storage if available."""
    if redis_url:
        limiter._storage_uri = redis_url
