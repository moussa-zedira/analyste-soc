"""Analyse de domaines/IPs — scanner réseau complet avec scan de ports, CVE et réputation."""

from __future__ import annotations

import json
import re
import socket
import ssl
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.scan_history import ScanHistory
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])

_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)

_IP_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)

_CHECK_TIMEOUT = 5

# Ports courants à scanner avec leur service associé
COMMON_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ScannerRequest(BaseModel):
    """Requête d'analyse d'un domaine ou d'une IP."""

    target: str


class PortResult(BaseModel):
    """Résultat du scan d'un port individuel."""

    port: int
    service: str
    state: str  # "open", "closed", "filtered"
    banner: str | None = None


class CveResult(BaseModel):
    """Vulnérabilité CVE trouvée pour un service."""

    id: str
    severity: str
    score: float | None = None
    description: str
    service: str


class ReputationResult(BaseModel):
    """Résultat de vérification de réputation d'une IP."""

    abuse_score: int = 0
    is_tor: bool = False
    is_proxy: bool = False
    is_vpn: bool = False
    is_bot: bool = False
    total_reports: int = 0
    last_reported: str | None = None
    source: str = ""


class ScanHistoryOut(BaseModel):
    """Entrée d'historique de scan pour l'API."""

    id: str
    target: str
    target_type: str
    resolved_ip: str | None
    security_score: int
    open_ports_count: int
    scan_duration_ms: int
    created_at: str


class ScannerResult(BaseModel):
    """Résultat complet de l'analyse réseau."""

    id: str | None = None
    target: str
    target_type: str = "domain"
    resolved_ip: str | None = None
    geo: dict | None = None
    dns: dict | None = None
    ssl_cert: dict | None = None
    http_headers: dict | None = None
    security_headers: dict | None = None
    whois_info: dict | None = None
    open_ports: list[PortResult] = []
    ports_scanned: int = 0
    cves: list[CveResult] = []
    reputation: ReputationResult | None = None
    security_score: int = 0
    score_details: list[dict] = []
    scan_duration_ms: int = 0
    errors: list[str] = []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_target(raw: str) -> tuple[str, str]:
    """Nettoie l'entrée et détermine le type (domain ou ip). Retourne (target, type)."""
    target = raw.strip()
    for prefix in ("https://", "http://"):
        if target.lower().startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0]
    target = target.split("?")[0]
    target = target.split("#")[0]
    target = target.split(":")[0]  # Retirer le port éventuel
    target = target.rstrip(".")
    target = target.lower()

    if _IP_RE.match(target):
        return target, "ip"
    return target, "domain"


def _resolve_ip(domain: str) -> str | None:
    """Résout l'adresse IP principale du domaine."""
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
    except socket.gaierror:
        pass
    return None


def _reverse_dns(ip: str) -> str | None:
    """Résolution DNS inverse d'une IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def _scan_single_port(ip: str, port: int, timeout: float = 1.5) -> PortResult:
    """Scanne un port unique et retourne le résultat."""
    service = COMMON_PORTS.get(port, "unknown")
    banner = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        if result == 0:
            # Tenter de récupérer la bannière
            try:
                sock.settimeout(1.0)
                sock.sendall(b"\r\n")
                banner_bytes = sock.recv(256)
                if banner_bytes:
                    banner = banner_bytes.decode("utf-8", errors="replace").strip()[:200]
            except Exception:
                pass
            sock.close()
            return PortResult(port=port, service=service, state="open", banner=banner)
        else:
            sock.close()
            return PortResult(port=port, service=service, state="closed")
    except socket.timeout:
        return PortResult(port=port, service=service, state="filtered")
    except Exception:
        return PortResult(port=port, service=service, state="closed")


def _scan_ports(ip: str) -> list[PortResult]:
    """Scanne tous les ports courants en parallèle."""
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=25) as executor:
        futures = {
            executor.submit(_scan_single_port, ip, port): port
            for port in COMMON_PORTS
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                port = futures[future]
                results.append(PortResult(
                    port=port,
                    service=COMMON_PORTS.get(port, "unknown"),
                    state="closed",
                ))
    results.sort(key=lambda r: r.port)
    return results


def _get_geo_full(ip: str) -> tuple[dict | None, list[str]]:
    """Géolocalisation enrichie via ip-api.com (ISP, ASN, org)."""
    errors: list[str] = []

    # D'abord essayer le module geoip interne
    try:
        from apps.api.geoip import lookup_ip
        basic_geo = lookup_ip(ip)
        if basic_geo:
            # Enrichir avec ip-api.com pour ISP/ASN
            try:
                resp = httpx.get(
                    f"http://ip-api.com/json/{ip}",
                    params={"fields": "status,isp,org,as,asname,reverse,mobile,proxy,hosting"},
                    timeout=5.0,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        basic_geo["isp"] = data.get("isp", "N/A")
                        basic_geo["org"] = data.get("org", "N/A")
                        basic_geo["as"] = data.get("as", "N/A")
                        basic_geo["asname"] = data.get("asname", "N/A")
                        basic_geo["reverse"] = data.get("reverse", "N/A")
                        basic_geo["proxy"] = data.get("proxy", False)
                        basic_geo["hosting"] = data.get("hosting", False)
            except Exception as exc:
                errors.append(f"GeoIP enrichment: {exc}")
            return basic_geo, errors
    except Exception:
        pass

    # Repli complet sur ip-api.com
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,regionName,city,lat,lon,isp,org,as,asname,reverse,mobile,proxy,hosting,timezone,zip"},
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                    "timezone": data.get("timezone", "N/A"),
                    "zip": data.get("zip", "N/A"),
                    "isp": data.get("isp", "N/A"),
                    "org": data.get("org", "N/A"),
                    "as": data.get("as", "N/A"),
                    "asname": data.get("asname", "N/A"),
                    "reverse": data.get("reverse", "N/A"),
                    "proxy": data.get("proxy", False),
                    "hosting": data.get("hosting", False),
                }, errors
    except Exception as exc:
        errors.append(f"GeoIP: {exc}")

    return None, errors


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


def _lookup_cves(open_ports: list[PortResult]) -> tuple[list[CveResult], list[str]]:
    """Recherche des CVE connues pour les services détectés via cve.circl.lu."""
    cves: list[CveResult] = []
    errors: list[str] = []

    # Mapping service -> mots-clés de recherche CPE
    service_keywords: dict[str, str] = {
        "SSH": "openssh",
        "HTTP": "apache OR nginx",
        "HTTPS": "apache OR nginx",
        "FTP": "vsftpd OR proftpd",
        "SMTP": "postfix OR exim",
        "MySQL": "mysql",
        "PostgreSQL": "postgresql",
        "Redis": "redis",
        "MongoDB": "mongodb",
        "SMB": "samba",
        "RDP": "remote desktop",
    }

    seen_services: set[str] = set()
    for port in open_ports:
        if port.state != "open":
            continue
        service = port.service
        if service in seen_services or service not in service_keywords:
            continue
        seen_services.add(service)

        # Utiliser la bannière si disponible, sinon le mot-clé par défaut
        search_term = service_keywords[service]
        if port.banner:
            # Extraire le nom de logiciel de la bannière
            banner_clean = port.banner.split("\n")[0][:50]
            search_term = banner_clean

        try:
            resp = httpx.get(
                f"https://cve.circl.lu/api/search/{search_term}",
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                # Prendre les 3 CVE les plus récentes/critiques
                items = data if isinstance(data, list) else data.get("results", [])
                for item in items[:3]:
                    cvss = item.get("cvss") or item.get("cvss3", {})
                    score_val = None
                    severity = "unknown"
                    if isinstance(cvss, (int, float)):
                        score_val = float(cvss)
                    elif isinstance(cvss, dict):
                        score_val = cvss.get("score")

                    if score_val is not None:
                        if score_val >= 9.0:
                            severity = "critical"
                        elif score_val >= 7.0:
                            severity = "high"
                        elif score_val >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"

                    cves.append(CveResult(
                        id=item.get("id", item.get("cve", "CVE-UNKNOWN")),
                        severity=severity,
                        score=score_val,
                        description=(item.get("summary") or item.get("description", ""))[:200],
                        service=service,
                    ))
        except Exception as exc:
            errors.append(f"CVE lookup ({service}): {exc}")

    return cves, errors


def _check_ip_reputation(ip: str) -> tuple[ReputationResult | None, list[str]]:
    """Vérifie la réputation d'une IP via des APIs publiques."""
    errors: list[str] = []

    try:
        # Utiliser ip-api.com pour les flags proxy/hosting (déjà gratuit)
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,proxy,hosting,mobile,query"},
            timeout=5.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = ReputationResult(
                    is_proxy=data.get("proxy", False),
                    source="ip-api.com",
                )

                # Enrichir avec ipapi.is (gratuit, pas de clé)
                try:
                    resp2 = httpx.get(
                        f"https://api.ipapi.is/?q={ip}",
                        timeout=5.0,
                    )
                    if resp2.status_code == 200:
                        data2 = resp2.json()
                        rir = data2.get("rir", {})
                        company = data2.get("company", {})
                        is_abuser = data2.get("is_abuser", False)
                        is_tor_node = data2.get("is_tor", False)
                        is_proxy_2 = data2.get("is_proxy", False)
                        is_vpn = data2.get("is_vpn", False)
                        is_datacenter = data2.get("is_datacenter", False)
                        is_bot = data2.get("is_bot", False)

                        abuse_score = 0
                        if is_abuser:
                            abuse_score += 40
                        if is_tor_node:
                            abuse_score += 20
                        if is_proxy_2:
                            abuse_score += 15
                        if is_vpn:
                            abuse_score += 10
                        if is_bot:
                            abuse_score += 25

                        result.abuse_score = min(100, abuse_score)
                        result.is_tor = is_tor_node
                        result.is_proxy = is_proxy_2 or data.get("proxy", False)
                        result.is_vpn = is_vpn
                        result.is_bot = is_bot
                        result.source = "ipapi.is + ip-api.com"
                except Exception:
                    pass

                return result, errors
    except Exception as exc:
        errors.append(f"Reputation: {exc}")

    return None, errors


def _calculate_score(
    ssl_cert: dict | None,
    security_headers: dict | None,
    http_headers: dict | None,
    open_ports: list[PortResult],
) -> tuple[int, list[dict]]:
    """Calcule un score de sécurité de 0 à 100."""
    score = 0
    details: list[dict] = []

    # SSL valide (+20)
    if ssl_cert and ssl_cert.get("days_remaining") is not None and ssl_cert["days_remaining"] > 0:
        score += 20
        details.append({"check": "SSL valide", "points": 20, "passed": True})
    else:
        details.append({"check": "SSL valide", "points": 0, "passed": False, "max": 20})

    if security_headers:
        # HSTS (+10)
        if security_headers.get("Strict-Transport-Security"):
            score += 10
            details.append({"check": "HSTS présent", "points": 10, "passed": True})
        else:
            details.append({"check": "HSTS présent", "points": 0, "passed": False, "max": 10})

        # X-Frame-Options (+5)
        if security_headers.get("X-Frame-Options"):
            score += 5
            details.append({"check": "X-Frame-Options", "points": 5, "passed": True})
        else:
            details.append({"check": "X-Frame-Options", "points": 0, "passed": False, "max": 5})

        # CSP (+10)
        if security_headers.get("Content-Security-Policy"):
            score += 10
            details.append({"check": "Content-Security-Policy", "points": 10, "passed": True})
        else:
            details.append({"check": "Content-Security-Policy", "points": 0, "passed": False, "max": 10})

        # X-Content-Type-Options (+5)
        if security_headers.get("X-Content-Type-Options"):
            score += 5
            details.append({"check": "X-Content-Type-Options", "points": 5, "passed": True})
        else:
            details.append({"check": "X-Content-Type-Options", "points": 0, "passed": False, "max": 5})
    else:
        for name, pts in [
            ("HSTS présent", 10),
            ("X-Frame-Options", 5),
            ("Content-Security-Policy", 10),
            ("X-Content-Type-Options", 5),
        ]:
            details.append({"check": name, "points": 0, "passed": False, "max": pts})

    # HTTPS accessible (+10)
    if http_headers and http_headers.get("status_code") and http_headers["status_code"] < 400:
        score += 10
        details.append({"check": "HTTPS accessible", "points": 10, "passed": True})
    else:
        details.append({"check": "HTTPS accessible", "points": 0, "passed": False, "max": 10})

    # Certificate > 30 jours (+10)
    if ssl_cert and ssl_cert.get("days_remaining") is not None and ssl_cert["days_remaining"] > 30:
        score += 10
        details.append({"check": "Certificat > 30 jours", "points": 10, "passed": True})
    else:
        details.append({"check": "Certificat > 30 jours", "points": 0, "passed": False, "max": 10})

    # Ports dangereux fermés (+20)
    dangerous_ports = {21, 23, 135, 139, 445, 3389, 5900}
    open_port_numbers = {p.port for p in open_ports if p.state == "open"}
    dangerous_open = open_port_numbers & dangerous_ports
    if not dangerous_open:
        score += 20
        details.append({"check": "Ports dangereux fermés", "points": 20, "passed": True})
    else:
        # Score partiel : -3 par port dangereux ouvert
        penalty = min(20, len(dangerous_open) * 3)
        pts = max(0, 20 - penalty)
        score += pts
        port_list = ", ".join(str(p) for p in sorted(dangerous_open))
        details.append({
            "check": f"Ports dangereux ouverts: {port_list}",
            "points": pts,
            "passed": False,
            "max": 20,
        })

    # Peu de ports ouverts (+10) — moins de 5 ports ouverts = bon
    total_open = len(open_port_numbers)
    if total_open <= 3:
        score += 10
        details.append({"check": f"Surface d'attaque réduite ({total_open} ports)", "points": 10, "passed": True})
    elif total_open <= 6:
        score += 5
        details.append({"check": f"Surface d'attaque modérée ({total_open} ports)", "points": 5, "passed": True})
    else:
        details.append({"check": f"Surface d'attaque large ({total_open} ports)", "points": 0, "passed": False, "max": 10})

    return score, details


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@router.post("/analyze", response_model=ScannerResult)
def analyze_target(
    payload: ScannerRequest,
    db: Session = Depends(get_db),
) -> ScannerResult:
    """Analyse complète d'une cible : ports, DNS, SSL, en-têtes HTTP, WHOIS, GeoIP, CVE, réputation."""
    start = time.monotonic()
    errors: list[str] = []

    target, target_type = _clean_target(payload.target)

    if target_type == "domain":
        if not _DOMAIN_RE.match(target):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Cible invalide : {target}",
            )
    elif target_type == "ip":
        if not _IP_RE.match(target):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Adresse IP invalide : {target}",
            )

    scan_id = str(uuid.uuid4())
    result = ScannerResult(id=scan_id, target=target, target_type=target_type)

    # 1. Résolution IP (si domaine) ou DNS inverse (si IP)
    if target_type == "domain":
        result.resolved_ip = _resolve_ip(target)
    else:
        result.resolved_ip = target
        reverse = _reverse_dns(target)
        if reverse:
            result.dns = {"reverse": reverse}

    # 2. Scan de ports
    scan_ip = result.resolved_ip
    if scan_ip:
        port_results = _scan_ports(scan_ip)
        result.open_ports = [p for p in port_results if p.state == "open"]
        result.ports_scanned = len(COMMON_PORTS)

    # 3. GeoIP enrichie
    if result.resolved_ip:
        geo, geo_errors = _get_geo_full(result.resolved_ip)
        result.geo = geo
        errors.extend(geo_errors)

    # 4. DNS (si domaine)
    if target_type == "domain":
        dns_records, dns_errors = _get_dns_records(target)
        result.dns = dns_records
        errors.extend(dns_errors)

    # 5. SSL
    ssl_domain = target if target_type == "domain" else result.resolved_ip
    if ssl_domain:
        ssl_cert, ssl_errors = _get_ssl_cert(ssl_domain)
        result.ssl_cert = ssl_cert
        errors.extend(ssl_errors)

    # 6. HTTP headers
    http_target = target if target_type == "domain" else result.resolved_ip
    if http_target:
        http_headers, security_headers, http_errors = _get_http_headers(http_target)
        result.http_headers = http_headers
        result.security_headers = security_headers
        errors.extend(http_errors)

    # 7. WHOIS (domaines uniquement)
    if target_type == "domain":
        whois_info, whois_errors = _get_whois_info(target)
        result.whois_info = whois_info
        errors.extend(whois_errors)

    # 8. Recherche CVE sur les services détectés
    if result.open_ports:
        cves, cve_errors = _lookup_cves(result.open_ports)
        result.cves = cves
        errors.extend(cve_errors)

    # 9. Réputation IP
    if result.resolved_ip:
        reputation, rep_errors = _check_ip_reputation(result.resolved_ip)
        result.reputation = reputation
        errors.extend(rep_errors)

    # 10. Score de sécurité
    score, score_details = _calculate_score(
        result.ssl_cert, result.security_headers, result.http_headers, result.open_ports,
    )
    result.security_score = score
    result.score_details = score_details

    result.errors = errors
    result.scan_duration_ms = int((time.monotonic() - start) * 1000)

    # 11. Sauvegarder dans l'historique
    try:
        history_entry = ScanHistory(
            id=scan_id,
            target=target,
            target_type=target_type,
            resolved_ip=result.resolved_ip,
            result_json=result.model_dump_json(),
            security_score=result.security_score,
            open_ports_count=len(result.open_ports),
            scan_duration_ms=result.scan_duration_ms,
            created_at=datetime.now(timezone.utc),
        )
        db.add(history_entry)
        db.commit()
    except Exception:
        db.rollback()

    return result


# ---------------------------------------------------------------------------
# Endpoints — Historique des scans
# ---------------------------------------------------------------------------


@router.get("/history", response_model=list[ScanHistoryOut])
def list_scan_history(
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    target: str | None = None,
) -> list[ScanHistoryOut]:
    """Retourne l'historique des scans, triés par date décroissante."""
    query = db.query(ScanHistory).order_by(ScanHistory.created_at.desc())
    if target:
        query = query.filter(ScanHistory.target.ilike(f"%{target}%"))
    scans = query.offset(offset).limit(limit).all()
    return [
        ScanHistoryOut(
            id=s.id,
            target=s.target,
            target_type=s.target_type,
            resolved_ip=s.resolved_ip,
            security_score=s.security_score,
            open_ports_count=s.open_ports_count,
            scan_duration_ms=s.scan_duration_ms,
            created_at=s.created_at.isoformat() if s.created_at else "",
        )
        for s in scans
    ]


@router.get("/history/{scan_id}", response_model=ScannerResult)
def get_scan_detail(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScannerResult:
    """Retourne le détail complet d'un scan passé."""
    scan = db.get(ScanHistory, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan non trouvé")
    return ScannerResult(**json.loads(scan.result_json))
