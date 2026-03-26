# apps/web — Next.js Dashboard

Next.js 15 (App Router) dashboard UI for events, incidents, and KPIs.

Stack: Next.js + TypeScript + Tailwind.

---

## Install & run

From `apps/web`:

```bash
npm install
cp .env.local.example .env.local
# Edit .env.local if needed (API URL, API key)
npm run dev
```

Open: `http://localhost:3000`

---

## Environment variables

Create `apps/web/.env.local`:

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_API_BASE_URL` | `http://127.0.0.1:8000` | Backend API base URL |
| `NEXT_PUBLIC_API_KEY` | `change-me` | API key sent via `X-API-Key` header |

The API key must match the backend's `API_KEY` value.

---

## Pages

| Route | Description |
|---|---|
| `/` | Dashboard with KPI cards and "Run Rules" button |
| `/events` | Events list with filtering and pagination |
| `/incidents` | Incidents list with filtering and pagination |
| `/incidents/[id]` | Incident detail with related events |

---

## Filters and pagination

All filters and pagination state are stored in URL query parameters, making URLs shareable and bookmarkable.

- Applying a filter updates the URL
- Reloading the page preserves the current filter state
- Copying the URL into a new tab loads the same filtered view

---

## API communication

- In the browser, requests go through a Next.js rewrite proxy (`/api/proxy/*` -> backend) to avoid CORS issues
- On the server (SSR), requests go directly to `NEXT_PUBLIC_API_BASE_URL`
- Every request includes the `X-API-Key` header

---

## Troubleshooting

- **Empty dashboard**: API not running or wrong `NEXT_PUBLIC_API_BASE_URL`
- **401 in Network tab**: `NEXT_PUBLIC_API_KEY` doesn't match API's `API_KEY`
- **CORS errors**: API includes CORS middleware for `localhost:3000`; also the Next.js proxy should bypass CORS entirely
