"""Rate limiting middleware using slowapi."""

from __future__ import annotations

from apps.api.config import get_settings

from slowapi import Limiter
from slowapi.util import get_remote_address

_settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["60/minute"],
    storage_uri=_settings.REDIS_URL,
)
