# Analyste SOC — Cyber Defense Dashboard (SIEM)

A full-stack Security Information and Event Management (SIEM) platform with real-time event monitoring, ML-powered anomaly detection, and a MITRE ATT&CK mapping interface.

## Architecture

```
apps/
├── api/          FastAPI backend (REST + WebSocket)
├── web/          Next.js 15 frontend (App Router, React 19)
└── agent/        Event simulator for development
```

**Infrastructure**: PostgreSQL 16, Redis 7, Celery (worker + beat scheduler)

## Features

- **Real-time event stream** — WebSocket push via Redis pub/sub, live event journal and map updates
- **Detection engine** — Rule-based (brute force, impossible travel, statistical anomaly) + ML (Isolation Forest, TF-IDF severity classifier)
- **Incident management** — Auto-created incidents with deduplication, severity scoring, and AI triage (Ollama)
- **MITRE ATT&CK mapping** — Technique coverage heatmap with incident drill-down
- **Relationship graph** — Interactive IP/user/incident force-directed graph (D3)
- **GeoIP map** — Real-time threat map with Leaflet (MaxMind GeoLite2 or ip-api.com fallback)
- **Webhook notifications** — Discord-compatible incident alerts with retry/backoff
- **Auth** — Dual API key + JWT authentication, role-based access control
- **Rate limiting** — Redis-backed per-IP rate limiter

## Quick Start

### Docker (recommended)

```bash
docker compose up --build
```

| Service   | URL                    |
|-----------|------------------------|
| Dashboard | http://localhost:3000   |
| API       | http://localhost:8000   |
| API Docs  | http://localhost:8000/docs |

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

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | — | Redis connection string |
| `API_KEY` | — | API key for authentication |
| `JWT_SECRET_KEY` | — | Secret for JWT token signing |
| `GEOIP_DB_PATH` | `/app/data/GeoLite2-City.mmdb` | MaxMind database path |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Ollama server for AI triage |
| `WEBHOOK_ENABLED` | `false` | Enable Discord webhook alerts |
| `WEBHOOK_URL` | — | Discord webhook endpoint |

## Database Migrations

```bash
alembic upgrade head      # apply migrations
alembic revision --autogenerate -m "description"  # create new migration
```

## Tech Stack

- **Backend**: Python 3.11+, FastAPI, SQLAlchemy, Celery, scikit-learn
- **Frontend**: Next.js 15, React 19, TypeScript, Tailwind CSS, D3, Leaflet
- **Infra**: Docker Compose, PostgreSQL, Redis, Alembic
