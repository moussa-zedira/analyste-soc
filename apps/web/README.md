# Cyber Defense Dashboard — Frontend

Full-featured Next.js 15 (App Router) frontend for a **Cyber Defense Dashboard** combining SIEM capabilities with an integrated Offensive Security / Pentest platform. Built with React 19, TypeScript, and Tailwind CSS. The UI uses a dark cybersecurity theme (gray-900/950 backgrounds, cyan-400 accents).

---

## 1. Overview

This application provides two major functional areas:

- **SIEM / Defense** — Real-time event monitoring, incident management, threat intelligence, anomaly detection, and admin tooling.
- **Pentest / Offensive Security** — 30+ pages covering the full attack lifecycle: reconnaissance, exploitation, privilege escalation, lateral movement, persistence, and reporting.

---

## 2. Quick Start

```bash
# From apps/web
npm install
cp .env.local.example .env.local
# Edit .env.local to set the API URL and API key
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Environment Variables

Create `apps/web/.env.local`:

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_API_BASE_URL` | `http://127.0.0.1:8000` | Backend base URL (exposed to browser) |
| `INTERNAL_API_BASE_URL` | `http://127.0.0.1:8000` | Backend URL used by `/api/proxy` route handler (server-only) |
| `INTERNAL_API_KEY` | _(required)_ | API key injected server-side by the proxy. **Never** exposed to the browser. Must equal the backend's `API_KEY`. |

Browser requests go through `/api/proxy/*` which adds `X-API-Key` server-side.
This is what keeps the secret out of the JavaScript bundle.

---

## 3. Pages Reference

### SIEM / Defense Pages

| Route | Description |
|---|---|
| `/` | Main dashboard with KPI cards, event timeline, and threat map |
| `/events` | Event journal with filtering, search, and pagination |
| `/incidents` | Incident list with status management |
| `/graph` | Interactive relationship graph (D3 force-directed) |
| `/map` | GeoIP threat map (Leaflet) |
| `/anomaly` | ML anomaly detection visualization |
| `/alerts` | Alert management |
| `/admin` | Admin panel (user management, system configuration) |
| `/sources` | Log source health monitoring |
| `/threat-intel` | Threat intelligence lookup and SIGMA rules |

### Pentest / Offensive Pages

| Route | Description |
|---|---|
| `/pentest` | Core pentest dashboard |
| `/pentest/pipeline` | Automated scan workflows |
| `/pentest/sessions` | Pentest session management |
| `/pentest/nvd` | NVD/CVE search |
| `/pentest/templates` | Reusable pentest templates |
| `/pentest/network` | Network evasion tools |
| `/pentest/history` | Scan history |
| `/pentest/hash` | Hash cracker |
| `/pentest/report` | Report generation |
| `/pentest/wordgen` | Wordlist generator |
| `/pentest/deep` | Deep vulnerability scanner |
| `/pentest/blind` | Blind extraction |
| `/pentest/oob` | OOB callback server |
| `/pentest/ssrf` | SSRF advanced |
| `/pentest/subdomain` | Subdomain discovery |
| `/pentest/waf-bypass` | WAF bypass |
| `/pentest/exfil` | Data exfiltration (DNS/HTTP/ICMP) |
| `/pentest/persist` | Persistence mechanisms |
| `/pentest/antiforensics` | Anti-forensics tools |
| `/pentest/killchain` | Kill chain planner |
| `/pentest/shell` | Reverse shell handler (terminal emulator) |
| `/pentest/chain` | Attack chain command center |
| `/pentest/sqli` | SQLi exploitation engine (5 tabs) |
| `/pentest/privesc` | Privilege escalation scanner (6 tabs) |
| `/pentest/creds` | Credential harvester (6 tabs) |
| `/pentest/lateral` | Lateral movement (8 tabs) |
| `/pentest/xss-engine` | XSS engine (6 tabs) |
| `/pentest/lfi-rce` | LFI to RCE (7 tabs) |
| `/pentest/protocols` | Protocol exploiter (8 tabs) |
| `/pentest/sessions-mgr` | Session manager |
| `/pentest/docs` | Pentest documentation |

---

## 4. Project Structure

```
apps/web/
├── app/                    # Next.js App Router pages
│   ├── page.tsx            # Main dashboard (/)
│   ├── events/             # /events
│   ├── incidents/          # /incidents
│   ├── graph/              # /graph
│   ├── map/                # /map
│   ├── anomaly/            # /anomaly
│   ├── alerts/             # /alerts
│   ├── admin/              # /admin
│   ├── sources/            # /sources
│   ├── threat-intel/       # /threat-intel
│   └── pentest/            # /pentest/* (30 sub-pages)
├── components/             # Shared React components
│   ├── Sidebar.tsx         # Main navigation with collapsible sections
│   └── ...
├── lib/                    # Utilities
│   ├── apiClient.ts        # 289 API functions
│   └── types.ts            # 179 TypeScript interfaces
├── public/                 # Static assets
├── .env.local.example      # Environment variable template
├── next.config.js          # Next.js configuration
├── tailwind.config.ts      # Tailwind CSS configuration
└── tsconfig.json           # TypeScript configuration
```

---

## 5. Key Files

| File | Role |
|---|---|
| `components/Sidebar.tsx` | Main navigation sidebar with collapsible SIEM and Pentest sections |
| `lib/apiClient.ts` | Centralized API client with 289 functions covering all backend endpoints |
| `lib/types.ts` | 179 TypeScript interfaces shared across the application |

---

## 6. Tech Stack

| Technology | Purpose |
|---|---|
| **Next.js 15** (App Router) | Framework, routing, SSR |
| **React 19** | UI library |
| **TypeScript** | Type safety |
| **Tailwind CSS** | Utility-first styling |
| **Framer Motion** | Animations and transitions |
| **D3.js** | Force-directed graphs (`/graph`) |
| **Leaflet** | GeoIP threat map (`/map`) |
| **Recharts** | Charts and data visualization |

### Theme

Dark cybersecurity theme: `gray-900`/`gray-950` backgrounds with `cyan-400` accents throughout the interface.

---

## 7. Configuration

### API Communication

- **Browser requests** go through a Next.js rewrite proxy (`/api/proxy/*` to backend) to avoid CORS issues.
- **Server-side (SSR) requests** go directly to `NEXT_PUBLIC_API_BASE_URL`.
- Every request includes the `X-API-Key` header.

### URL State

All filters and pagination state are stored in URL query parameters, making URLs shareable and bookmarkable. Reloading the page preserves the current filter state.

### Troubleshooting

| Problem | Cause |
|---|---|
| Empty dashboard | Backend API not running or wrong `NEXT_PUBLIC_API_BASE_URL` |
| 401 in Network tab | `INTERNAL_API_KEY` does not match the backend `API_KEY` |
| CORS errors | Backend CORS middleware is configured for `localhost:3000`; the Next.js proxy should bypass CORS entirely |
