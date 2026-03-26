# apps/api — FastAPI Backend

FastAPI API for ingesting events, running detection rules, and reading incidents.

Stack: FastAPI + SQLAlchemy + SQLite.

---

## Install & run

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

Create env:

```bash
cp .env.example .env
```

Run (from **project root**):

```bash
uvicorn apps.api.main:app --reload --host 0.0.0.0 --port 8000
```

OpenAPI docs: `http://localhost:8000/docs`

---

## Environment variables

Create `apps/api/.env`:

| Variable | Default | Description |
|---|---|---|
| `ENV` | `dev` | `dev` or `prod` (prod disables docs) |
| `DATABASE_URL` | `sqlite:///./app.db` | SQLite connection string |
| `API_KEY` | _(empty; falls back to `dev-insecure-key` in dev)_ | Value expected in `X-API-Key` header |
| `API_KEY_HEADER` | `X-API-Key` | Header name for API key |

---

## Security — X-API-Key

All endpoints except `/health` require the header `X-API-Key: <API_KEY>`.

```bash
export API_KEY="change-me"

# Public (no key)
curl -sS http://localhost:8000/health

# Protected
curl -sS http://localhost:8000/events -H "X-API-Key: ${API_KEY}"
```

In dev mode (`ENV=dev`), if `API_KEY` is empty the server uses the fallback key `dev-insecure-key`. This fallback is disabled when `ENV=prod`.

---

## Database

- **Engine**: SQLite (file-based, single-user)
- **Location**: controlled by `DATABASE_URL` (default `sqlite:///./app.db`)
- **Schema management**: tables are created at startup via `Base.metadata.create_all()` (no Alembic migrations)
- **Reset**: stop the API, delete the `.db` file, restart

### Tables

| Table | Purpose |
|---|---|
| `events` | Normalised security events |
| `incidents` | Aggregated security incidents |
| `incident_events` | Many-to-many link between incidents and events |
| `rule_checkpoints` | Last-processed timestamp per detection rule |

---

## Endpoints

### `POST /events` — ingest an event

```bash
curl -sS -X POST http://localhost:8000/events \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -d '{"source":"sshd","event_type":"auth.fail","severity":"medium","src_ip":"10.0.0.1","username":"admin","message":"Failed password"}'
```

### `GET /events` — list events (with optional filters)

Query params: `limit`, `offset`, `severity`, `event_type`, `src_ip`

```bash
curl -sS "http://localhost:8000/events?severity=high&event_type=auth.fail" \
  -H "X-API-Key: ${API_KEY}"
```

### `GET /incidents` — list incidents (with optional filters)

Query params: `limit`, `offset`, `severity`, `status_filter`, `rule_id`

```bash
curl -sS "http://localhost:8000/incidents?status_filter=open" \
  -H "X-API-Key: ${API_KEY}"
```

### `GET /incidents/{id}` — incident detail with linked events

```bash
curl -sS http://localhost:8000/incidents/<ID> -H "X-API-Key: ${API_KEY}"
```

### `POST /rules/run` — run detection engine

```bash
curl -sS -X POST http://localhost:8000/rules/run -H "X-API-Key: ${API_KEY}"
# Returns: {"rules_evaluated": 1, "incidents_created": 0}
```

---

## Detection engine

The engine loads declarative rules from `apps/api/detection/rules.py`, evaluates them against recent events (last 1 hour), and creates deduplicated incidents.

### Brute-force rule (`bruteforce.v1`)

- Triggers on: `event_type == "auth.fail"` with non-null `src_ip`
- Threshold: >= 10 events from the same IP within 2 minutes
- Severity: HIGH
- Dedup: SHA-256 hash of `(rule_id, entity_key, minute_bucket)` prevents duplicate incidents

### Reproduce a HIGH incident

```bash
export API_KEY="change-me"

for i in $(seq 1 12); do
  curl -sS -X POST http://localhost:8000/events \
    -H "Content-Type: application/json" \
    -H "X-API-Key: ${API_KEY}" \
    -d '{"source":"sshd","event_type":"auth.fail","severity":"medium","src_ip":"10.0.0.99","username":"admin","message":"Failed password"}' > /dev/null
done

curl -sS -X POST http://localhost:8000/rules/run -H "X-API-Key: ${API_KEY}"
curl -sS http://localhost:8000/incidents -H "X-API-Key: ${API_KEY}"
```

---

## Troubleshooting

- **401 auth errors**: confirm `API_KEY` in `.env` matches your request header
- **CORS errors**: API allows `http://localhost:3000` and `http://127.0.0.1:3000` by default
- **DB not created**: ensure working directory is writable
- **Port in use**: stop the other process or change the port
