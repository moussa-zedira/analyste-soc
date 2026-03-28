# Cyber Defense Dashboard API

FastAPI backend for the Cyber Defense Dashboard (SIEM). Provides 200+ endpoints covering event ingestion, detection engine, incident management, AI-powered triage, threat intelligence, and a full penetration testing toolkit.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Authentication](#authentication)
4. [Endpoint Reference](#endpoint-reference)
5. [Configuration](#configuration)
6. [Database](#database)
7. [Monitoring](#monitoring)
8. [Troubleshooting](#troubleshooting)

---

## Overview

- **Framework**: FastAPI 1.0.0
- **Database**: PostgreSQL (SQLAlchemy ORM + Alembic migrations, falls back to `create_all` if Alembic is unavailable)
- **Cache**: Redis
- **Task queue**: Celery with Redis broker
- **Rate limiting**: slowapi with Redis backend
- **Logging**: structlog (JSON output in production)
- **Metrics**: Prometheus via `prometheus-fastapi-instrumentator`
- **Real-time**: WebSocket endpoints for event streaming and shell sessions
- **AI/ML**: Ollama integration for chat/triage, anomaly detection models

---

## Quick Start

### Install

From the **project root** (so Python resolves `apps.api`):

```bash
cd apps/api
python -m venv .venv

# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
# Edit .env with your database URL, API key, Redis URL, etc.
```

### Run

```bash
uvicorn apps.api.main:app --reload --host 0.0.0.0 --port 8000
```

### Explore

- **OpenAPI / Swagger UI**: `http://localhost:8000/docs` (disabled in production)
- **ReDoc**: `http://localhost:8000/redoc` (disabled in production)
- **Health check**: `http://localhost:8000/health`

---

## Authentication

### API Key (`X-API-Key`)

All endpoints except `/health` require the `X-API-Key` header.

```bash
# Public (no key required)
curl http://localhost:8000/health

# Protected
curl http://localhost:8000/events -H "X-API-Key: ${API_KEY}"
```

In dev mode (`ENV=dev`), if `API_KEY` is empty, the server falls back to `dev-insecure-key`. This fallback is disabled in production.

### JWT Authentication

The `/auth` endpoints provide JWT-based authentication:

1. `POST /auth/login` with username/password to obtain an access token.
2. Use the token in the `Authorization: Bearer <token>` header.
3. `POST /auth/refresh` to renew an expiring token.

A default admin account (`admin` / `admin`) is seeded at startup if no users exist.

---

## Endpoint Reference

### Core SIEM

| Prefix | Module | Description | Key Endpoints |
|---|---|---|---|
| `/auth` | auth | Authentication and user sessions | `POST /login`, `POST /register`, `GET /me`, `POST /refresh` |
| `/events` | events | Security event ingestion and query | `GET /`, `POST /`, `POST /batch`, `GET /search` |
| `/rules` | rules | Detection rules management | `GET /`, `POST /`, `POST /run` (execute detection engine) |
| `/incidents` | incidents | Incident lifecycle management | `GET /`, `POST /`, `GET /{id}`, `PATCH /{id}`, triage and status updates |
| `/stats` | stats | Dashboard KPIs and analytics | Dashboard summary, time-series data, severity breakdowns |
| `/alerts` | alerts | Alert management | CRUD operations on alerts |
| `/anomaly` | anomaly | ML-based anomaly detection | Run anomaly detection on events |
| _(none)_ | ml | ML model management | Model training, evaluation, lifecycle |
| `/chat` | chat | AI chat and triage assistant | Chat with Ollama-backed AI for event/incident analysis |
| `/threat-scores` | threat_scores | Composite threat scoring | Compute and query threat scores |
| `/triage` | triage | AI-powered incident triage | Automated incident prioritization and classification |
| `/threat-intel` | threat_intel | Threat intelligence | TI lookups, stats, bulk IoC checks |
| `/sigma` | sigma | SIGMA rule management | Import, manage, and apply SIGMA detection rules |

### Investigation and Reconnaissance

| Prefix | Module | Description | Key Endpoints |
|---|---|---|---|
| `/investigate` | investigate | Investigation tools | IP/domain/hash investigation workflows |
| `/recon` | recon | Reconnaissance tools | OSINT and target reconnaissance |
| `/scanner` | scanner | Vulnerability scanning | Launch and manage vulnerability scans |
| `/scans` | scan_history | Scan history tracking | Query past scan results and history |
| `/log-sources` | log_sources | Log source health monitoring | Monitor status and health of configured log sources |

### Administration and Export

| Prefix | Module | Description | Key Endpoints |
|---|---|---|---|
| `/admin` | admin | Administration | User management, system configuration |
| `/export` | export | Data export | Export events/incidents as CSV or JSON |
| `/wordlists` | wordlists | Wordlist management | Upload, list, and manage wordlists |

### WebSocket

| Prefix | Module | Description |
|---|---|---|
| `/ws` | ws | Real-time event streaming via WebSocket |

### Pentest Core

| Prefix | Module | Description | Key Endpoints |
|---|---|---|---|
| `/pentest` | pentest | Core penetration testing module (10k+ lines) | Scan orchestration, vulnerability assessment, reporting |
| `/pentest/nvd` | pentest_nvd | NVD / CVE lookup | Search CVEs, fetch vulnerability details from NVD |
| `/pentest/shell` | pentest_shell | Reverse shell handler (REST + WebSocket) | Create, manage, and interact with reverse shells |
| `/pentest/chain` | pentest_chain | Attack chain engine | Define and execute multi-step attack chains |
| `/pentest/sqli` | pentest_sqli | SQL injection exploitation engine | Automated SQLi detection and exploitation |
| `/pentest/sessions-mgr` | pentest_sessmgr | Pentest session manager | Track and manage pentest sessions |
| `/pentest/privesc` | pentest_privesc | Privilege escalation | Enumerate and exploit privilege escalation vectors |
| `/pentest/creds` | pentest_creds | Credential harvester | Credential extraction and auditing |
| `/pentest/lateral` | pentest_lateral | Lateral movement | Network lateral movement techniques |
| `/pentest/xss-engine` | pentest_xss_engine | XSS engine | Automated XSS detection and exploitation |
| `/pentest/lfi-rce` | pentest_lfi_rce | LFI to RCE | Local file inclusion to remote code execution |
| `/pentest/protocols` | pentest_protocols | Protocol exploiter | Multi-protocol exploitation (SSH, FTP, SMB, etc.) |

### Pentest Standalone Modules

These routers carry their own prefixes defined internally:

| Module | Tag | Description |
|---|---|---|
| pentest_stream | Pentest Stream | Real-time pentest output streaming |
| pentest_pipeline | Pentest Pipeline | Multi-stage scan pipeline orchestration |
| pentest_sessions | Pentest Sessions | Session persistence and replay |
| pentest_stealth | Pentest Stealth | Stealth and evasion techniques |
| pentest_templates | Pentest Templates | Reusable pentest templates |
| pentest_network_evasion | Network Evasion | Network-level evasion (fragmentation, tunneling) |
| pentest_hash_cracker | Hash Cracker | Hash identification and cracking |
| pentest_report | Pentest Report | Report generation (PDF, HTML, JSON) |
| pentest_wordgen | Wordlist Generator | Custom wordlist generation |
| pentest_deep_scan | Deep Scan | Deep vulnerability scanning |
| pentest_blind | Blind Extraction | Blind injection data extraction |
| pentest_oob | OOB Callback | Out-of-band callback server and receiver |
| pentest_ssrf | SSRF Advanced | Advanced SSRF detection and exploitation |
| pentest_subdomain | Subdomain Discovery | Subdomain enumeration and discovery |
| pentest_waf_bypass | WAF Bypass | WAF detection and bypass techniques |
| pentest_exfil | Exfiltration | Data exfiltration channels (DNS, HTTP, ICMP) |
| pentest_persist | Persistence | Persistence mechanism deployment |
| pentest_antiforensics | Anti-Forensics | Anti-forensics and log tampering |
| pentest_killchain | Kill Chain | Kill chain planning and execution |

---

## Configuration

Create `apps/api/.env` (or set environment variables):

| Variable | Default | Description |
|---|---|---|
| `ENV` | `dev` | `dev` or `prod`. Production disables Swagger/ReDoc docs. |
| `DATABASE_URL` | `sqlite:///./app.db` | Database connection string. Use PostgreSQL in production. |
| `API_KEY` | _(empty; falls back to `dev-insecure-key` in dev)_ | Value expected in the `X-API-Key` header. |
| `API_KEY_HEADER` | `X-API-Key` | Header name for API key authentication. |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string for cache, rate limiting, and Celery broker. |
| `CELERY_BROKER_URL` | _(uses REDIS_URL)_ | Celery broker URL. |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server URL for AI chat/triage. |
| `SECRET_KEY` | _(auto-generated)_ | Secret key for JWT token signing. |

---

## Database

- **Engine**: PostgreSQL recommended for production; SQLite supported for development.
- **ORM**: SQLAlchemy 2.x
- **Migrations**: Alembic. On startup the app runs `alembic upgrade head`. If Alembic is not configured, it falls back to `Base.metadata.create_all()`.
- **Connection**: configured via `DATABASE_URL` environment variable.

### Key Tables

| Table | Purpose |
|---|---|
| `users` | User accounts and roles |
| `events` | Normalized security events |
| `incidents` | Aggregated security incidents |
| `incident_events` | Many-to-many link between incidents and events |
| `rules` | Detection rules |
| `rule_checkpoints` | Last-processed timestamp per detection rule |
| `alerts` | Alert records |
| `scans` | Scan results and history |
| `threat_intel_iocs` | Threat intelligence indicators of compromise |

### Default Admin Account

On first startup (or if the `admin` user exists), the API seeds/resets the default admin:

- **Username**: `admin`
- **Password**: `admin`
- **Role**: `admin`

Change these credentials immediately in any non-development environment.

---

## Monitoring

### Health Check

```
GET /health
```

No authentication required. Returns component-level status:

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime_seconds": 123.4,
  "components": {
    "database": "ok",
    "redis": "ok"
  }
}
```

Status is `"degraded"` if any component fails its check.

### Protected Check

```
GET /protected-check
```

Requires `X-API-Key`. Returns `{"status": "ok"}` to verify authentication is working.

### Prometheus Metrics

```
GET /metrics
```

Exposes Prometheus-compatible metrics (request counts, latencies, status codes). The `/health` and `/metrics` endpoints are excluded from instrumentation.

### Request Tracing

Every response includes an `X-Request-ID` header for correlation in structured logs.

---

## Troubleshooting

- **401 errors**: confirm `API_KEY` in `.env` matches your `X-API-Key` header.
- **CORS errors**: the API allows origins `http://localhost:3000`, `http://127.0.0.1:3000`, and `http://web:3000`.
- **DB not created**: ensure the database URL is correct and the database server is running.
- **Port in use**: stop the conflicting process or change the port.
- **Rate limited (429)**: slowapi rate limits are enforced; wait and retry or adjust limits.
- **Redis unavailable**: the API degrades gracefully but cache and rate limiting will not function.
