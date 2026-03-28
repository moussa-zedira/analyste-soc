# Analyste SOC

**Cyber Defense Dashboard -- SIEM & Offensive Security Platform**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat-square&logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-15-000000?style=flat-square&logo=next.js&logoColor=white)
![React](https://img.shields.io/badge/React-19-61DAFB?style=flat-square&logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-Private-red?style=flat-square)

A full-stack Security Information and Event Management (SIEM) platform combined with an integrated offensive security toolkit. The platform provides real-time event monitoring, ML-powered anomaly detection, MITRE ATT&CK mapping, and 30+ penetration testing modules -- all behind a unified dashboard.

> **Disclaimer:** The offensive security tools included in this project are intended strictly for authorized penetration testing, security assessments, and educational purposes. Unauthorized use of these tools against systems you do not own or have explicit written permission to test is illegal and unethical. The authors assume no liability for misuse.

---

## Table of Contents

- [Architecture](#architecture)
- [SIEM & Defense Features](#siem--defense-features)
- [Offensive Security Features](#offensive-security-features)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Database Migrations](#database-migrations)
- [Tech Stack](#tech-stack)

---

## Architecture

```
apps/
├── api/            FastAPI backend (REST + WebSocket) — 200+ endpoints
├── web/            Next.js 15 frontend (App Router, React 19) — 30+ pages
├── agent/          Event simulator for development
└── collectors/     (planned) Syslog, WinLog, File watcher collectors
```

**Infrastructure** -- 7 Docker Compose services:

| Service    | Role                                  |
|------------|---------------------------------------|
| `api`      | FastAPI application server            |
| `web`      | Next.js frontend                      |
| `postgres` | PostgreSQL 16 database                |
| `redis`    | Redis 7 (caching, pub/sub, rate limiting) |
| `worker`   | Celery task worker                    |
| `beat`     | Celery periodic task scheduler        |
| `syslog`   | Syslog ingestion endpoint             |

---

## SIEM & Defense Features

### Core Engine

- **Real-time event stream** -- WebSocket push via Redis pub/sub with live journal and map updates
- **Detection engine** -- Rule-based detection (brute force, impossible travel, statistical anomaly) combined with ML models (Isolation Forest, TF-IDF severity classifier)
- **Anomaly detection** -- ML-powered behavioral analysis using Isolation Forest
- **SIGMA rules engine** -- Import and manage SIGMA detection rules for standardized threat detection

### Incident Response

- **Incident management** -- Auto-created incidents with deduplication, severity scoring, and AI-assisted triage via Ollama
- **Threat scores** -- Composite scoring incorporating threat intelligence factors
- **Webhook notifications** -- Discord-compatible incident alerts with retry and backoff

### Threat Intelligence

- **AbuseIPDB integration** -- IP reputation lookups with 2-level cache
- **AlienVault OTX integration** -- Pulse and indicator enrichment with 2-level cache
- **NVD/CVE lookup** -- Search CVEs by keyword or CPE identifier

### Visualization & Analytics

- **MITRE ATT&CK mapping** -- Technique coverage heatmap with incident drill-down
- **Relationship graph** -- Interactive IP/user/incident force-directed graph (D3)
- **GeoIP map** -- Real-time threat map with Leaflet (MaxMind GeoLite2)
- **Log sources monitoring** -- Source health status and availability tracking

### Platform

- **Authentication** -- Dual JWT + API key auth with role-based access control (RBAC)
- **Rate limiting** -- Redis-backed per-IP rate limiter
- **Export** -- CSV and JSON export of events and incidents
- **Admin panel** -- User management and system configuration

---

## Offensive Security Features

> 30 modules organized across the penetration testing kill chain.

### Reconnaissance & Scanning

| Module                | Description                                              |
|-----------------------|----------------------------------------------------------|
| **Recon**             | Subdomain enumeration, port scanning, technology detection |
| **Deep Scan**         | Comprehensive vulnerability scanning                     |
| **Subdomain Discovery** | Multi-technique subdomain finder                      |
| **NVD/CVE Lookup**    | CVE search by keyword or CPE                             |

### Web Application Attacks

| Module              | Description                                                                                  |
|---------------------|----------------------------------------------------------------------------------------------|
| **SQLi Engine**     | Auto-detect DBMS, 5 injection techniques (UNION/error/boolean/time/stacked), schema enumeration, file read, OS command exec, 10 tamper functions |
| **XSS Engine**      | 6 context detectors, cookie stealer (5 methods), session hijack, keylogger, phishing overlay, BeEF-style hook, WAF bypass |
| **LFI to RCE**      | 15+ traversal techniques, log poisoning (Apache/Nginx/SSH/Mail/FTP), PHP wrappers, /proc exploitation, auto-chain orchestrator |
| **SSRF Advanced**   | Cloud metadata extraction, internal port scanning, protocol smuggling                        |
| **Blind Extraction**| Blind SQL/XXE/SSRF data extraction                                                           |
| **WAF Bypass**      | Encoding, chunking, and case-manipulation evasion techniques                                 |

### Network & Protocol Exploitation

| Module               | Description                                                                                  |
|----------------------|----------------------------------------------------------------------------------------------|
| **Protocol Exploiter** | 7 protocols (SMB/LDAP/RDP/FTP/SNMP/DNS/SMTP), 38 attacks, EternalBlue/SMBGhost/BlueKeep checks, Kerberoasting |
| **Network Evasion**   | Fragmentation, tunneling, protocol abuse                                                   |

### Post-Exploitation

| Module                  | Description                                                                              |
|-------------------------|------------------------------------------------------------------------------------------|
| **Shell Handler**       | TCP reverse shell listener, 18 payload templates (bash/python/php/perl/ruby/powershell/netcat/socat and more), WebSocket live interaction, PTY upgrade |
| **Privilege Escalation**| 55 GTFOBins, 21 kernel CVEs (DirtyCOW/DirtyPipe/PwnKit), 40+ Linux checks, 30+ Windows checks, Potato attacks |
| **Credential Harvester**| 50+ credential sources (config files, SSH keys, cloud, browser, registry, SAM), auto-parsers, hash identification, credential reuse validator |
| **Lateral Movement**    | Pass-the-Hash, Pass-the-Ticket, PSExec, WMI, WinRM, SSH pivoting, chisel tunnels, credential spray, pivot planner, MITRE ATT&CK mapped |

### Persistence & Evasion

| Module            | Description                                                  |
|-------------------|--------------------------------------------------------------|
| **Persistence**   | Backdoor deployment, registry/cron/service persistence       |
| **Anti-Forensics**| Log cleaning, timestamp manipulation, artifact removal       |
| **Exfiltration**  | DNS/HTTP/ICMP exfil, steganography, encrypted channels       |
| **Stealth**       | Traffic obfuscation, timing evasion                          |

### Orchestration & Reporting

| Module                  | Description                                                                              |
|-------------------------|------------------------------------------------------------------------------------------|
| **Attack Chain Engine** | Persistent state machine, 37 auto-action rules, 3 modes (manual/semi-auto/auto), kill chain phase tracking, findings/credentials/sessions sharing |
| **Kill Chain Planner**  | Full MITRE kill chain workflow                                                           |
| **Session Manager**     | Shared HTTP session state, cookie jar, CSRF auto-extraction, auto re-auth               |
| **Pentest Pipeline**    | Automated scan workflows                                                                 |
| **Pentest Report**      | Professional report generation                                                           |
| **Hash Cracker**        | Dictionary, brute force, and rule-based cracking                                         |
| **Wordlist Generator**  | Custom wordlist creation                                                                 |
| **OOB Callback Server** | Out-of-band interaction server for blind vulnerability confirmation                      |
| **Scan History**        | Historical scan tracking and comparison                                                  |
| **Templates**           | Reusable pentest templates                                                               |

---

## Quick Start

### Docker (recommended)

```bash
docker compose up --build
```

| Service   | URL                          |
|-----------|------------------------------|
| Dashboard | http://localhost:3000         |
| API       | http://localhost:8000         |
| API Docs  | http://localhost:8000/docs    |

**Default credentials:** `admin` / `admin`

### Local Development

**Backend:**

```bash
pip install -r requirements.txt
cd apps/api
uvicorn apps.api.main:app --reload
```

**Frontend:**

```bash
cd apps/web
npm install
npm run dev
```

**Workers:**

```bash
celery -A apps.api.celery_app worker --loglevel=info
celery -A apps.api.celery_app beat --loglevel=info
```

---

## Environment Variables

| Variable             | Default                        | Description                          |
|----------------------|--------------------------------|--------------------------------------|
| `DATABASE_URL`       | --                             | PostgreSQL connection string          |
| `REDIS_URL`          | --                             | Redis connection string               |
| `API_KEY`            | --                             | API key for authentication            |
| `JWT_SECRET_KEY`     | --                             | Secret for JWT token signing          |
| `GEOIP_DB_PATH`     | `/app/data/GeoLite2-City.mmdb` | MaxMind GeoLite2 database path       |
| `OLLAMA_BASE_URL`    | `http://localhost:11434`       | Ollama server for AI triage           |
| `WEBHOOK_ENABLED`    | `false`                        | Enable Discord webhook alerts         |
| `WEBHOOK_URL`        | --                             | Discord webhook endpoint              |
| `ABUSEIPDB_API_KEY`  | --                             | AbuseIPDB threat intel API key        |
| `OTX_API_KEY`        | --                             | AlienVault OTX API key                |

---

## Database Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Create a new migration from model changes
alembic revision --autogenerate -m "description"
```

---

## Tech Stack

| Layer      | Technologies                                                              |
|------------|---------------------------------------------------------------------------|
| **Backend**  | Python 3.11+, FastAPI, SQLAlchemy, Celery, scikit-learn, structlog      |
| **Frontend** | Next.js 15, React 19, TypeScript, Tailwind CSS, D3, Leaflet, Framer Motion |
| **Infra**    | Docker Compose, PostgreSQL 16, Redis 7, Alembic                         |
| **Security** | JWT + API key auth, RBAC, rate limiting, CORS                           |
