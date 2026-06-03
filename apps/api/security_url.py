"""Validation d'URL pour bloquer les SSRF (webhooks, fetchers, callbacks).

Resout le hostname et rejette toute IP privee, loopback, link-local,
multicast, broadcast, ou metadata-cloud (169.254.169.254, etc).
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from urllib.parse import urlparse

from apps.api.config import get_settings

# IPs explicitement bloquees (instance metadata, link-local, etc.)
_BLOCKED_HOSTS: frozenset[str] = frozenset(
    {
        "169.254.169.254",  # AWS / GCP / Azure metadata
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "localhost",
        "0.0.0.0",
        "::1",
    }
)

# Schemes autorises (jamais file://, gopher://, ftp://, etc.)
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


class UnsafeURLError(ValueError):
    """Raised when a URL targets a forbidden internal/cloud-metadata destination."""


def _resolve_addresses(hostname: str) -> Iterable[ipaddress._BaseAddress]:
    """Resolve hostname to all IPs (v4 and v6)."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"Cannot resolve hostname '{hostname}': {exc}") from exc

    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        if addr in seen:
            continue
        seen.add(addr)
        try:
            yield ipaddress.ip_address(addr)
        except ValueError:
            continue


def validate_outbound_url(url: str, *, require_https: bool | None = None) -> str:
    """Valide une URL sortante. Retourne l'URL nettoyee ou leve UnsafeURLError.

    - Refuse les schemes non-HTTP(S)
    - Refuse les IPs privees, loopback, link-local, multicast, reserved
    - Refuse les hostnames blocklistes (metadata cloud, localhost...)
    - En production (ENV != dev), exige HTTPS sauf override explicite
    """
    if not url or not isinstance(url, str):
        raise UnsafeURLError("URL is empty")

    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(f"Scheme '{parsed.scheme}' not allowed (use http or https)")

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        raise UnsafeURLError("URL has no hostname")

    if hostname in _BLOCKED_HOSTS:
        raise UnsafeURLError(f"Host '{hostname}' is blocked")

    settings = get_settings()
    if require_https is None:
        require_https = settings.ENV != "dev"
    if require_https and parsed.scheme.lower() != "https":
        raise UnsafeURLError("HTTPS required in production")

    for ip in _resolve_addresses(hostname):
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise UnsafeURLError(f"URL '{url}' resolves to forbidden address {ip}")

    return url
