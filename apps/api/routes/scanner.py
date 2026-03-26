"""Analyse de domaines/URLs — endpoint de scan de sécurité complet."""

from __future__ import annotations

import re
import socket
import ssl
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

_CHECK_TIMEOUT = 5


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ScannerRequest(BaseModel):
    """Requête d'analyse d'un domaine ou d'une URL."""

    target: str


class ScannerResult(BaseModel):
    """Résultat complet de l'analyse d'un domaine."""

    target: str
    resolved_ip: str | None = None
    geo: dict | None = None
    dns: dict | None = None
    ssl_cert: dict | None = None
    http_headers: dict | None = None
    security_headers: dict | None = None
    whois_info: dict | None = None
    security_score: int = 0
    score_details: list[dict] = []
    scan_duration_ms: int = 0
    errors: list[str] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_domain(raw: str) -> str:
    """Nettoie l'entrée pour extraire un nom de domaine propre."""
    domain = raw.strip()
    for prefix in ("https://", "http://"):
        if domain.lower().startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    domain = domain.split("#")[0]
    domain = domain.rstrip(".")
    return domain.lower()


def _resolve_ip(domain: str) -> str | None:
    """Résout l'adresse IP principale du domaine."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass
    return None


def _get_dns_records(domain: str) -> tuple[dict, list[str]]:
    """Récupère les enregistrements DNS du domaine."""
    records: dict = {}
    errors: list[str] = []

    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.lifetime = _CHECK_TIMEOUT

        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            try:
                answers = resolver.resolve(domain, rtype)
                if rtype == "MX":
                    records[rtype] = [
                        {"priority": r.preference, "exchange": str(r.exchange).rstrip(".")}
                        for r in answers
                    ]
                else:
                    records[rtype] = [str(r).strip('"') for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                records[rtype] = []
            except Exception as exc:
                records[rtype] = []
                errors.append(f"DNS {rtype}: {exc}")
    except ImportError:
        # Repli sur socket pour l'enregistrement A uniquement
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            records["A"] = list({info[4][0] for info in infos})
        except socket.gaierror as exc:
            errors.append(f"DNS A (socket fallback): {exc}")
        try:
            infos6 = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
            records["AAAA"] = list({info[4][0] for info in infos6})
        except socket.gaierror:
            records["AAAA"] = []
        errors.append("dnspython non disponible — résolution DNS limitée à A/AAAA via socket")

    return records, errors


def _get_ssl_cert(domain: str) -> tuple[dict | None, list[str]]:
    """Récupère les informations du certificat SSL du domaine."""
    errors: list[str] = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=_CHECK_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if not cert:
                    return None, ["SSL: certificat vide"]

                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))

                not_before = cert.get("notBefore", "")
                not_after = cert.get("notAfter", "")

                # Parse dates — format: 'Mon DD HH:MM:SS YYYY GMT'
                valid_from = None
                valid_to = None
                days_remaining = None
                try:
                    valid_from_dt = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                    valid_to_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    valid_from = valid_from_dt.isoformat()
                    valid_to = valid_to_dt.isoformat()
                    days_remaining = (valid_to_dt - datetime.now(tz=None)).days
                except ValueError:
                    valid_from = not_before
                    valid_to = not_after

                serial = cert.get("serialNumber", "")

                return {
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "days_remaining": days_remaining,
                    "serial": serial,
                }, errors
    except Exception as exc:
        errors.append(f"SSL: {exc}")
        return None, errors


def _get_http_headers(domain: str) -> tuple[dict | None, dict | None, list[str]]:
    """Effectue une requête HTTP et analyse les en-têtes de sécurité."""
    errors: list[str] = []
    url = f"https://{domain}"
    security_header_names = [
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-XSS-Protection",
    ]

    try:
        with httpx.Client(
            timeout=_CHECK_TIMEOUT,
            follow_redirects=True,
            verify=False,
        ) as client:
            resp = client.get(url)

            headers_info = {
                "status_code": resp.status_code,
                "server": resp.headers.get("server"),
                "content_type": resp.headers.get("content-type"),
            }

            sec_headers: dict = {}
            for name in security_header_names:
                value = resp.headers.get(name)
                sec_headers[name] = value if value else None

            return headers_info, sec_headers, errors
    except Exception as exc:
        errors.append(f"HTTP: {exc}")
        return None, None, errors


def _get_whois_info(domain: str) -> tuple[dict | None, list[str]]:
    """Récupère les informations WHOIS du domaine."""
    errors: list[str] = []
    try:
        import whois  # type: ignore[import-untyped]

        w = whois.whois(domain)
        if w is None or w.get("domain_name") is None:
            return None, ["WHOIS: aucune donnée disponible"]

        def _fmt_date(d):
            if isinstance(d, list):
                d = d[0] if d else None
            if isinstance(d, datetime):
                return d.isoformat()
            return str(d) if d else None

        name_servers = w.get("name_servers")
        if isinstance(name_servers, list):
            name_servers = [ns.lower() for ns in name_servers if ns]
        elif name_servers:
            name_servers = [str(name_servers).lower()]
        else:
            name_servers = []

        return {
            "registrar": w.get("registrar"),
            "creation_date": _fmt_date(w.get("creation_date")),
            "expiration_date": _fmt_date(w.get("expiration_date")),
            "name_servers": name_servers,
        }, errors
    except ImportError:
        errors.append("WHOIS: bibliothèque python-whois non disponible")
        return None, errors
    except Exception as exc:
        errors.append(f"WHOIS: {exc}")
        return None, errors


def _calculate_score(
    ssl_cert: dict | None,
    security_headers: dict | None,
    http_headers: dict | None,
) -> tuple[int, list[dict]]:
    """Calcule un score de sécurité de 0 à 100."""
    score = 0
    details: list[dict] = []

    # SSL valide (+25)
    if ssl_cert and ssl_cert.get("days_remaining") is not None and ssl_cert["days_remaining"] > 0:
        score += 25
        details.append({"check": "SSL valide", "points": 25, "passed": True})
    else:
        details.append({"check": "SSL valide", "points": 0, "passed": False, "max": 25})

    if security_headers:
        # HSTS (+15)
        if security_headers.get("Strict-Transport-Security"):
            score += 15
            details.append({"check": "HSTS présent", "points": 15, "passed": True})
        else:
            details.append({"check": "HSTS présent", "points": 0, "passed": False, "max": 15})

        # X-Frame-Options (+10)
        if security_headers.get("X-Frame-Options"):
            score += 10
            details.append({"check": "X-Frame-Options", "points": 10, "passed": True})
        else:
            details.append({"check": "X-Frame-Options", "points": 0, "passed": False, "max": 10})

        # CSP (+15)
        if security_headers.get("Content-Security-Policy"):
            score += 15
            details.append({"check": "Content-Security-Policy", "points": 15, "passed": True})
        else:
            details.append({"check": "Content-Security-Policy", "points": 0, "passed": False, "max": 15})

        # X-Content-Type-Options (+10)
        if security_headers.get("X-Content-Type-Options"):
            score += 10
            details.append({"check": "X-Content-Type-Options", "points": 10, "passed": True})
        else:
            details.append({"check": "X-Content-Type-Options", "points": 0, "passed": False, "max": 10})

        # X-XSS-Protection (not scored, but tracked)
    else:
        for name, pts in [
            ("HSTS présent", 15),
            ("X-Frame-Options", 10),
            ("Content-Security-Policy", 15),
            ("X-Content-Type-Options", 10),
        ]:
            details.append({"check": name, "points": 0, "passed": False, "max": pts})

    # HTTPS redirect (+10) — implied if HTTP headers were retrieved via HTTPS
    if http_headers and http_headers.get("status_code") and http_headers["status_code"] < 400:
        score += 10
        details.append({"check": "HTTPS accessible", "points": 10, "passed": True})
    else:
        details.append({"check": "HTTPS accessible", "points": 0, "passed": False, "max": 10})

    # Certificate days > 30 (+15)
    if ssl_cert and ssl_cert.get("days_remaining") is not None and ssl_cert["days_remaining"] > 30:
        score += 15
        details.append({"check": "Certificat > 30 jours", "points": 15, "passed": True})
    else:
        details.append({"check": "Certificat > 30 jours", "points": 0, "passed": False, "max": 15})

    return score, details


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post("/analyze", response_model=ScannerResult)
def analyze_target(payload: ScannerRequest) -> ScannerResult:
    """Analyse complète d'un domaine : DNS, SSL, en-têtes HTTP, WHOIS, GeoIP et score de sécurité."""
    start = time.monotonic()
    errors: list[str] = []

    domain = _clean_domain(payload.target)
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Nom de domaine invalide : {domain}",
        )

    result = ScannerResult(target=domain)

    # 1. Résolution IP
    result.resolved_ip = _resolve_ip(domain)

    # 2. GeoIP
    if result.resolved_ip:
        try:
            from apps.api.geoip import lookup_ip

            result.geo = lookup_ip(result.resolved_ip)
        except Exception as exc:
            errors.append(f"GeoIP: {exc}")

    # 3. DNS
    dns_records, dns_errors = _get_dns_records(domain)
    result.dns = dns_records
    errors.extend(dns_errors)

    # 4. SSL
    ssl_cert, ssl_errors = _get_ssl_cert(domain)
    result.ssl_cert = ssl_cert
    errors.extend(ssl_errors)

    # 5. HTTP headers
    http_headers, security_headers, http_errors = _get_http_headers(domain)
    result.http_headers = http_headers
    result.security_headers = security_headers
    errors.extend(http_errors)

    # 6. WHOIS
    whois_info, whois_errors = _get_whois_info(domain)
    result.whois_info = whois_info
    errors.extend(whois_errors)

    # 7. Score de sécurité
    score, score_details = _calculate_score(ssl_cert, security_headers, http_headers)
    result.security_score = score
    result.score_details = score_details

    result.errors = errors
    result.scan_duration_ms = int((time.monotonic() - start) * 1000)

    return result
