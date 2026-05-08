"""Middleware de limitation de débit utilisant slowapi."""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from apps.api.config import get_settings

_settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["60/minute"],
    storage_uri=_settings.REDIS_URL,
)
