# apps/agent — Event Simulator (Optional)

A lightweight simulator that generates events and sends them to the API via `POST /events`.
Useful for demos, testing filters, and triggering detection rules.

Modes:

- `normal` — mixed benign events with occasional failures
- `bruteforce` — repeated auth failures from the same IP (triggers HIGH incident after rules run)
- `continuous` — runs indefinitely at a configured interval

---

## Install & run

From `apps/agent`:

```bash
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env
python -m agent
```

---

## Environment variables

Create `apps/agent/.env`:

| Variable | Default | Description |
|---|---|---|
| `API_BASE_URL` | `http://localhost:8000` | Backend API base URL |
| `API_KEY` | _(required)_ | Sent as `X-API-Key` header |
| `AGENT_MODE` | `normal` | `normal` / `bruteforce` / `continuous` |
| `AGENT_INTERVAL_MS` | `1000` | Delay between events in continuous mode |

---

## Usage patterns

### Normal mode

```bash
AGENT_MODE=normal python -m agent
```

### Bruteforce mode (to generate a HIGH incident)

1. Run the agent in bruteforce mode to ingest failures
2. Run detection rules: `POST /rules/run`
3. Verify incidents in UI or via `GET /incidents`

```bash
AGENT_MODE=bruteforce python -m agent
```

Then trigger detection:

```bash
export API_KEY="change-me"
curl -sS -X POST http://localhost:8000/rules/run -H "X-API-Key: ${API_KEY}"
curl -sS http://localhost:8000/incidents -H "X-API-Key: ${API_KEY}"
```

### Continuous mode

```bash
AGENT_MODE=continuous AGENT_INTERVAL_MS=500 python -m agent
```

Stop with Ctrl+C.

---

## Troubleshooting

- **401/403**: agent `API_KEY` must match API's `API_KEY`
- **Connection refused**: API not running or wrong `API_BASE_URL`
