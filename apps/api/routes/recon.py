"""OSINT Recon — Outil de reconnaissance offensive pour collecter un maximum
d'informations sur une cible (IP ou domaine)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import ssl
import time
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])
logger = logging.getLogger(__name__)

_HTTP = httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False)


# ---------------------------------------------------------------------------
# Response schema
# ---------------------------------------------------------------------------

class ReconResponse(BaseModel):
    target: str
    target_type: str
    resolved_ip: str | None = None
    whois: dict | None = None
    dns_records: dict[str, list[str]] | None = None
    subdomains: list[dict] | None = None
    reverse_ip: list[str] | None = None
    geo: dict | None = None
    tech_stack: dict | None = None
    ssl_cert: dict | None = None
    headers: dict | None = None
    wayback: dict | None = None
    google_dorks: list[dict] = []
    robots_sitemap: dict | None = None
    open_ports: list[dict] = []
    emails_found: list[str] = []
    errors: list[str] = []
    scan_duration_ms: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_ip(t: str) -> bool:
    try:
        ipaddress.ip_address(t)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Module 1 — WHOIS (via RDAP)
# ---------------------------------------------------------------------------

async def _get_whois(domain: str) -> dict | None:
    try:
        r = await _HTTP.get(f"https://rdap.org/domain/{domain}", timeout=15.0)
        if r.status_code != 200:
            return None
        d = r.json()
        info: dict = {"name": d.get("ldhName"), "status": d.get("status", [])}
        for ev in d.get("events", []):
            act = ev.get("eventAction", "")
            date = ev.get("eventDate", "")
            if act == "registration":
                info["created"] = date
            elif act == "expiration":
                info["expires"] = date
            elif act == "last changed":
                info["updated"] = date
        for ent in d.get("entities", []):
            roles = ent.get("roles", [])
            vcard = ent.get("vcardArray", [None, []])[1] if ent.get("vcardArray") else []
            name = ""
            for item in vcard:
                if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                    name = item[3]
                    break
            if "registrar" in roles:
                info["registrar"] = name or ent.get("handle")
            if "registrant" in roles:
                info["registrant"] = name or ent.get("handle")
        ns = [n.get("ldhName", "") for n in d.get("nameservers", [])]
        if ns:
            info["nameservers"] = ns
        return info
    except Exception as e:
        logger.debug("WHOIS failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# Module 2 — DNS Records
# ---------------------------------------------------------------------------

async def _get_dns(domain: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {}
    rtypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "CAA"]

    async def q(rt: str) -> tuple[str, list[str]]:
        try:
            r = await _HTTP.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": rt},
                headers={"Accept": "application/dns-json"},
            )
            if r.status_code == 200:
                answers = r.json().get("Answer", [])
                return rt, [a.get("data", "").strip('"') for a in answers]
        except Exception:
            logger.debug("recon: ignored exception", exc_info=True)
        return rt, []

    results = await asyncio.gather(*[q(rt) for rt in rtypes])
    for rt, vals in results:
        if vals:
            records[rt] = vals
    return records


# ---------------------------------------------------------------------------
# Module 3 — Subdomains (Certificate Transparency)
# ---------------------------------------------------------------------------

async def _get_subdomains(domain: str) -> list[dict]:
    subs: set[str] = set()
    try:
        r = await _HTTP.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=20.0,
        )
        if r.status_code == 200:
            for entry in r.json():
                for line in entry.get("name_value", "").split("\n"):
                    line = line.strip().lower()
                    if line.endswith(domain) and "*" not in line:
                        subs.add(line)
    except Exception as e:
        logger.debug("crt.sh failed: %s", e)

    result = []
    for sub in sorted(subs):
        ip = None
        try:
            ip = socket.gethostbyname(sub)
        except Exception:
            logger.debug("recon: ignored exception", exc_info=True)
        result.append({"subdomain": sub, "ip": ip})
    return result


# ---------------------------------------------------------------------------
# Module 4 — Reverse IP
# ---------------------------------------------------------------------------

async def _get_reverse_ip(ip: str) -> list[str]:
    try:
        r = await _HTTP.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=10.0,
        )
        if r.status_code == 200 and "error" not in r.text.lower():
            domains = [d.strip() for d in r.text.strip().split("\n") if d.strip()]
            return domains[:50]
    except Exception as e:
        logger.debug("Reverse IP failed: %s", e)
    return []


# ---------------------------------------------------------------------------
# Module 5 — GeoIP
# ---------------------------------------------------------------------------

async def _get_geo(ip: str) -> dict | None:
    try:
        r = await _HTTP.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"},
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return d
    except Exception as e:
        logger.debug("GeoIP failed: %s", e)
    return None


# ---------------------------------------------------------------------------
# Module 6 — Tech Fingerprint
# ---------------------------------------------------------------------------

async def _get_tech(target: str) -> dict | None:
    fp: dict = {"server": None, "powered_by": None, "framework": None,
                "cms": None, "cdn": None, "language": None, "cookies": [], "detected": []}
    detected: list[str] = []
    try:
        r = await _HTTP.get(f"https://{target}", timeout=12.0)
        h = dict(r.headers)
        body = r.text[:8000].lower()

        fp["server"] = h.get("server")
        fp["powered_by"] = h.get("x-powered-by")

        # Server detection
        srv = (fp["server"] or "").lower()
        for name in ["nginx", "apache", "iis", "litespeed", "caddy"]:
            if name in srv:
                detected.append(name.title())

        # CDN detection
        cdn_map = {"cf-cache-status": "Cloudflare", "x-amz-cf-id": "CloudFront",
                    "x-vercel-id": "Vercel", "x-netlify": "Netlify", "fly-request-id": "Fly.io"}
        for hdr, cdn in cdn_map.items():
            if hdr in h:
                fp["cdn"] = cdn
                detected.append(cdn)
                break

        # Language / framework from headers
        pb = (fp["powered_by"] or "").lower()
        lang_map = {"php": "PHP", "asp.net": "ASP.NET", "express": "Express.js", "next.js": "Next.js"}
        for key, name in lang_map.items():
            if key in pb:
                fp["language"] = name
                detected.append(name)

        # CMS from body
        cms_map = {"wp-content": "WordPress", "drupal": "Drupal", "joomla": "Joomla",
                    "shopify": "Shopify", "wix.com": "Wix", "squarespace": "Squarespace"}
        for key, name in cms_map.items():
            if key in body:
                fp["cms"] = name
                detected.append(name)
                break

        # Framework from body
        fw_map = {"__next": "Next.js", "react": "React", "__vue": "Vue.js",
                   "angular": "Angular", "laravel": "Laravel", "django": "Django",
                   "ruby on rails": "Ruby on Rails", "flask": "Flask"}
        for key, name in fw_map.items():
            if key in body:
                fp["framework"] = name
                detected.append(name)
                break

        # Generator meta tag
        gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body)
        if gen:
            detected.append(f"Generator: {gen.group(1)}")

        # Cookies
        cookies = []
        for raw in r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else []:
            cookies.append(raw.split("=")[0].strip())
        fp["cookies"] = cookies[:20]

        # Cookie-based detection
        ck = " ".join(cookies).lower()
        if "phpsessid" in ck and "PHP" not in detected:
            detected.append("PHP")
        if "jsessionid" in ck:
            detected.append("Java")

        fp["detected"] = list(dict.fromkeys(detected))
        return fp
    except Exception as e:
        logger.debug("Tech fingerprint failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# Module 7 — SSL Certificate
# ---------------------------------------------------------------------------

async def _get_ssl(hostname: str) -> dict | None:
    def _do() -> dict | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                    cert = ss.getpeercert(binary_form=False)
                    proto = ss.version()
                    ci = ss.cipher()
                    if not cert:
                        return {"protocol": proto}

                    subj = ""
                    for field in cert.get("subject", ()):
                        for k, v in field:
                            if k == "commonName":
                                subj = v
                    issuer_parts = []
                    for field in cert.get("issuer", ()):
                        for k, v in field:
                            if k in ("organizationName", "commonName"):
                                issuer_parts.append(v)
                    san = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]

                    not_after = cert.get("notAfter", "")
                    days = None
                    expired = False
                    if not_after:
                        try:
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
                            days = (exp - datetime.now(UTC)).days
                            expired = days < 0
                        except Exception:
                            logger.debug("recon: ignored exception", exc_info=True)

                    return {
                        "subject": subj, "issuer": " / ".join(issuer_parts),
                        "not_before": cert.get("notBefore"), "not_after": not_after,
                        "days_remaining": days, "serial": cert.get("serialNumber"),
                        "san": san[:50], "protocol": proto,
                        "cipher": ci[0] if ci else None,
                        "key_size": ci[2] if ci and len(ci) > 2 else None,
                        "is_expired": expired,
                    }
        except Exception as e:
            logger.debug("SSL failed: %s", e)
            return None

    return await asyncio.to_thread(_do)


# ---------------------------------------------------------------------------
# Module 8 — HTTP Headers Audit
# ---------------------------------------------------------------------------

async def _get_headers(target: str) -> dict | None:
    try:
        r = await _HTTP.get(f"https://{target}", timeout=12.0)
    except Exception:
        try:
            r = await _HTTP.get(f"http://{target}", timeout=12.0)
        except Exception as e:
            logger.debug("Headers failed: %s", e)
            return None

    raw = dict(r.headers)
    checks = [
        ("Strict-Transport-Security", 15, "Force HTTPS, protege contre les attaques downgrade"),
        ("Content-Security-Policy", 15, "Protege contre XSS et injection"),
        ("X-Content-Type-Options", 10, "Empeche le MIME-sniffing"),
        ("X-Frame-Options", 10, "Protege contre le clickjacking"),
        ("Referrer-Policy", 10, "Controle les fuites de referer"),
        ("Permissions-Policy", 10, "Restreint l'acces aux APIs navigateur"),
        ("X-XSS-Protection", 5, "Protection XSS legacy"),
        ("Cross-Origin-Opener-Policy", 5, "Isole le contexte de navigation"),
        ("Cross-Origin-Resource-Policy", 5, "Controle le partage de ressources"),
        ("Cross-Origin-Embedder-Policy", 5, "Controle les ressources embarquees"),
    ]

    lower = {k.lower(): v for k, v in raw.items()}
    missing = []
    details = []
    earned = 0
    total = 0
    for hdr, pts, desc in checks:
        total += pts
        present = hdr.lower() in lower
        if present:
            earned += pts
        else:
            missing.append(hdr)
        details.append({"header": hdr, "present": present, "points": pts, "description": desc})

    return {
        "raw": raw,
        "security_missing": missing,
        "security_score": earned,
        "max_score": total,
        "details": details,
    }


# ---------------------------------------------------------------------------
# Module 9 — Wayback Machine
# ---------------------------------------------------------------------------

async def _get_wayback(domain: str) -> dict | None:
    try:
        r = await _HTTP.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*", "output": "json", "limit": "50",
                "fl": "timestamp,original,statuscode,mimetype",
                "collapse": "urlkey",
            },
            timeout=15.0,
        )
        if r.status_code != 200:
            return None
        rows = r.json()
        if len(rows) < 2:
            return {"snapshots_count": 0, "first_seen": None, "last_seen": None, "urls": []}

        header = rows[0]
        data = rows[1:]
        urls = []
        for row in data:
            entry = dict(zip(header, row, strict=False))
            urls.append({
                "timestamp": entry.get("timestamp", ""),
                "url": entry.get("original", ""),
                "status": entry.get("statuscode", ""),
                "mimetype": entry.get("mimetype", ""),
            })

        timestamps = [u["timestamp"] for u in urls if u["timestamp"]]
        return {
            "snapshots_count": len(data),
            "first_seen": min(timestamps) if timestamps else None,
            "last_seen": max(timestamps) if timestamps else None,
            "urls": urls,
        }
    except Exception as e:
        logger.debug("Wayback failed: %s", e)
        return None


# ---------------------------------------------------------------------------
# Module 10 — Google Dorks
# ---------------------------------------------------------------------------

def _generate_dorks(domain: str) -> list[dict]:
    return [
        {"label": "Documents sensibles", "query": f'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:xlsx OR filetype:csv', "category": "files"},
        {"label": "Pages de login", "query": f'site:{domain} inurl:login OR inurl:admin OR inurl:dashboard OR inurl:signin', "category": "auth"},
        {"label": "APIs exposees", "query": f'site:{domain} inurl:api OR inurl:swagger OR inurl:graphql OR inurl:v1 OR inurl:v2', "category": "api"},
        {"label": "Fichiers de config/backup", "query": f'site:{domain} ext:sql OR ext:bak OR ext:log OR ext:env OR ext:cfg OR ext:conf', "category": "config"},
        {"label": "Listing de repertoires", "query": f'site:{domain} intitle:"index of" "parent directory"', "category": "dirs"},
        {"label": "Messages d'erreur", "query": f'site:{domain} intext:"error" OR intext:"exception" OR intext:"stack trace" OR intext:"syntax error"', "category": "errors"},
        {"label": "Fichiers de donnees", "query": f'site:{domain} ext:xml OR ext:json OR ext:yaml OR ext:yml', "category": "data"},
        {"label": "WordPress", "query": f'site:{domain} inurl:wp-content OR inurl:wp-admin OR inurl:wp-includes', "category": "cms"},
        {"label": "Credentials leakes", "query": f'"{domain}" password OR credentials OR secret OR api_key OR token', "category": "leak"},
        {"label": "Sous-domaines indexes", "query": f'site:*.{domain} -www', "category": "recon"},
        {"label": "Fichiers exposes", "query": f'site:{domain} ext:php intitle:phpinfo OR inurl:info.php', "category": "info"},
        {"label": "Cameras / IoT", "query": f'site:{domain} inurl:"/view/view.shtml" OR inurl:"/cgi-bin" OR intitle:"webcam"', "category": "iot"},
    ]


# ---------------------------------------------------------------------------
# Module 11 — Robots.txt & Sitemap
# ---------------------------------------------------------------------------

async def _get_robots_sitemap(target: str) -> dict | None:
    result: dict = {"robots_txt": None, "disallowed": [], "sitemaps": []}
    try:
        r = await _HTTP.get(f"https://{target}/robots.txt", timeout=8.0)
        if r.status_code == 200 and "user-agent" in r.text.lower():
            result["robots_txt"] = r.text[:3000]
            for line in r.text.split("\n"):
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["disallowed"].append(path)
                elif line.lower().startswith("sitemap:"):
                    url = line.split(":", 1)[1].strip()
                    if url:
                        result["sitemaps"].append(url)
    except Exception:
        try:
            r = await _HTTP.get(f"http://{target}/robots.txt", timeout=8.0)
            if r.status_code == 200 and "user-agent" in r.text.lower():
                result["robots_txt"] = r.text[:3000]
                for line in r.text.split("\n"):
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            result["disallowed"].append(path)
                    elif line.lower().startswith("sitemap:"):
                        url = line.split(":", 1)[1].strip()
                        if url:
                            result["sitemaps"].append(url)
        except Exception:
            logger.debug("recon: ignored exception", exc_info=True)
    return result if result["robots_txt"] or result["disallowed"] or result["sitemaps"] else None


# ---------------------------------------------------------------------------
# Module 12 — Port Scan (top 25)
# ---------------------------------------------------------------------------

async def _scan_ports(host: str) -> list[dict]:
    ports = [
        (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
        (53, "DNS"), (80, "HTTP"), (110, "POP3"), (135, "MSRPC"),
        (139, "NetBIOS"), (143, "IMAP"), (443, "HTTPS"), (445, "SMB"),
        (993, "IMAPS"), (995, "POP3S"), (1433, "MSSQL"), (1521, "Oracle"),
        (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"),
        (5900, "VNC"), (6379, "Redis"), (8080, "HTTP-Alt"),
        (8443, "HTTPS-Alt"), (27017, "MongoDB"), (9200, "Elasticsearch"),
    ]

    async def probe(port: int, svc: str) -> dict | None:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=2.0)
            w.close()
            await w.wait_closed()
            return {"port": port, "service": svc, "state": "open"}
        except Exception:
            return None

    results = await asyncio.gather(*[probe(p, s) for p, s in ports])
    return [r for r in results if r]


# ---------------------------------------------------------------------------
# Module 13 — Email Harvesting
# ---------------------------------------------------------------------------

async def _harvest_emails(target: str) -> list[str]:
    emails: set[str] = set()
    email_re = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    pages = [f"https://{target}", f"https://{target}/contact",
             f"https://{target}/about", f"https://{target}/impressum"]

    async def fetch(url: str) -> None:
        try:
            r = await _HTTP.get(url, timeout=8.0)
            if r.status_code == 200:
                found = email_re.findall(r.text)
                for e in found:
                    if not e.endswith((".png", ".jpg", ".gif", ".css", ".js")):
                        emails.add(e.lower())
        except Exception:
            logger.debug("recon: ignored exception", exc_info=True)

    await asyncio.gather(*[fetch(u) for u in pages])
    return sorted(emails)[:30]


# ---------------------------------------------------------------------------
# Main endpoint — Tout en parallele
# ---------------------------------------------------------------------------

@router.get("/{target:path}", response_model=ReconResponse)
async def recon_target(target: str, request: Request) -> dict:
    """Reconnaissance OSINT complete d'une cible."""
    start = time.time()
    target = target.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    if not target:
        raise HTTPException(400, "Target required")

    is_ip = _is_ip(target)
    resolved_ip = target if is_ip else None
    errors: list[str] = []

    if not is_ip:
        try:
            resolved_ip = await asyncio.to_thread(socket.gethostbyname, target)
        except Exception:
            errors.append(f"Impossible de resoudre {target}")

    # --- Lancer tous les modules en parallele ---
    tasks: dict[str, asyncio.Task] = {}

    if not is_ip:
        tasks["whois"] = asyncio.create_task(_get_whois(target))
        tasks["dns_records"] = asyncio.create_task(_get_dns(target))
        tasks["subdomains"] = asyncio.create_task(_get_subdomains(target))
        tasks["wayback"] = asyncio.create_task(_get_wayback(target))
        tasks["google_dorks"] = asyncio.create_task(asyncio.to_thread(_generate_dorks, target))
        tasks["robots_sitemap"] = asyncio.create_task(_get_robots_sitemap(target))

    if resolved_ip:
        tasks["reverse_ip"] = asyncio.create_task(_get_reverse_ip(resolved_ip))
        tasks["geo"] = asyncio.create_task(_get_geo(resolved_ip))
        tasks["open_ports"] = asyncio.create_task(_scan_ports(resolved_ip))

    tasks["tech_stack"] = asyncio.create_task(_get_tech(target))
    tasks["ssl_cert"] = asyncio.create_task(_get_ssl(target))
    tasks["headers"] = asyncio.create_task(_get_headers(target))
    tasks["emails_found"] = asyncio.create_task(_harvest_emails(target))

    # Attendre tous les resultats
    results: dict = {}
    for key, task in tasks.items():
        try:
            results[key] = await task
        except Exception as e:
            errors.append(f"{key}: {e}")
            results[key] = None

    elapsed = int((time.time() - start) * 1000)

    return {
        "target": target,
        "target_type": "ip" if is_ip else "domain",
        "resolved_ip": resolved_ip,
        "whois": results.get("whois"),
        "dns_records": results.get("dns_records"),
        "subdomains": results.get("subdomains"),
        "reverse_ip": results.get("reverse_ip"),
        "geo": results.get("geo"),
        "tech_stack": results.get("tech_stack"),
        "ssl_cert": results.get("ssl_cert"),
        "headers": results.get("headers"),
        "wayback": results.get("wayback"),
        "google_dorks": results.get("google_dorks", _generate_dorks(target) if not is_ip else []),
        "robots_sitemap": results.get("robots_sitemap"),
        "open_ports": results.get("open_ports", []),
        "emails_found": results.get("emails_found", []),
        "errors": errors,
        "scan_duration_ms": elapsed,
    }
