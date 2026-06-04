# Analyste SOC

**Cyber Defense Platform — SIEM + Red Team + Pentest + AI Assistant**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-15-000000?style=flat-square&logo=next.js&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-Private-red?style=flat-square)

Plateforme unifiée combinant **SIEM défensif**, **opérations Red Team** (Sliver C2, GoPhish, BloodHound), **modules pentest essentiels**, et **assistant IA contextuel** (Claude / GPT / Ollama). Conçue pour un pentester ou analyste SOC qui veut couvrir le cycle complet — détection → recon → exploit → rapport — depuis un seul dashboard, sans empilement d'outils tiers.

> **V5 — Phase de simplification (2026-04-19)**: après 4 vagues d'expansion (V1→V4.9), la plateforme a été recentrée sur les **30 fonctionnalités UI réellement utilisables et stables**. Les 60+ modules expérimentaux ou non finis ont été retirés de la navigation. Le backend reste complet (1000+ endpoints) pour réactivation à la carte.

---

## Stats actuelles

| Métrique | Valeur |
|---|---|
| Pages frontend | **30 routes** (36 fichiers `page.tsx` incluant les sous-routes dynamiques) |
| Endpoints API | **1046 paths / 1139 opérations** REST + WebSocket |
| Routers FastAPI | **135** routers inclus |
| Modules backend pentest | **16** modules (recon, exploitation, c2_sliver, phishing, bloodhound, post_exploit, etc.) |
| Migrations DB | **23** migrations Alembic — tête `022_chat_messages` |
| Tests | **24** fichiers de tests d'intégration |
| Lignes de code | **~180k** Python (backend) + **~34k** TS/TSX (frontend) |
| Services Docker | **7** (api, web, postgres, redis, worker, beat, syslog) |

---

## Sommaire

- [Architecture](#architecture)
- [Pages UI disponibles](#pages-ui-disponibles)
- [Modules backend complémentaires](#modules-backend-complémentaires)
- [Red Team (C2, Phishing, AD)](#red-team-c2-phishing-ad)
- [Assistant IA](#assistant-ia)
- [Quick Start](#quick-start)
- [Variables d'environnement](#variables-denvironnement)
- [Migrations DB](#migrations-db)
- [Tech Stack](#tech-stack)
- [Documentation](#documentation)
- [Historique des vagues](#historique-des-vagues)

---

## Architecture

```
apps/
├── api/            FastAPI backend — 1046 endpoints REST + WebSocket
├── web/            Next.js 15 (App Router) — 30 routes
├── agent/          Event simulator
└── collectors/     Syslog, WinLog, File watcher
```

**7 services Docker Compose :**

| Service    | Rôle                                      |
|------------|-------------------------------------------|
| `api`      | Serveur FastAPI                           |
| `web`      | Frontend Next.js                          |
| `postgres` | PostgreSQL 16                             |
| `redis`    | Cache, pub/sub, rate limit, sessions      |
| `worker`   | Celery (tâches async)                     |
| `beat`     | Celery scheduler                          |
| `syslog`   | Ingestion syslog UDP/TCP                  |

**Services externes** (host) :
- **Ollama** sur `localhost:11434` — IA locale (`qwen2.5-coder:32b`, alléger via `OLLAMA_MODEL`)
- **Sliver C2** sur `localhost:31337` — daemon opérateur
- **GoPhish** sur `localhost:3333` — serveur phishing (lancé en standalone)

---

## Pages UI disponibles

### SIEM Core (9)
| Route | Description |
|---|---|
| `/` | Dashboard temps réel (events, KPIs, GeoIP) |
| `/search` | Recherche CQL multi-critères sur les events |
| `/events` | Stream events avec filtres et live tail |
| `/incidents` | Triage, timeline, scoring, transitions |
| `/sources` | Santé des sources de logs |
| `/hunting` | Threat hunting interactif |
| `/ioc` | IOC Manager (IP/domain/hash/URL, TTL, confidence) |
| `/threat-intel` | AbuseIPDB + AlienVault OTX + cache |
| `/alerts` | Channels notifications (Discord/Slack/Email/Teams) |

### Red Team (4)
| Route | Description |
|---|---|
| `/redteam/console` | Operator Console Sliver (sessions, terminal, beacon graph) |
| `/redteam/phishing` | Campagnes GoPhish (envoi, tracking, scope, kill-switch) |
| `/redteam/bloodhound` | Import dump AD, analyse chemins d'attaque |
| `/pentest/c2` | Configuration C2 Sliver (listeners, implants) |

### OSINT / Reconnaissance (4)
| Route | Description |
|---|---|
| `/recon` | Recon multi-sources (DNS, certs, tech stack, emails) |
| `/pentest/subdomain` | Subdomain enum (DNS, CT logs, wordlists) |
| `/pentest/crawler` | Spider ciblé, formulaires, endpoints cachés |
| `/pentest/netscan` | Scan réseau / fingerprinting services |

### Pentest Web (4)
| Route | Description |
|---|---|
| `/pentest/pipeline` | Chaînage automatique de scans |
| `/pentest/sqli` | SQLi engine (5 techniques, DBMS auto-detect, tamper) |
| `/pentest/xss-engine` | XSS engine (6 contexts, payloads contextuels) |
| `/pentest/brute` | Brute force services (SSH, FTP, HTTP, etc.) |

### IA (3)
| Route | Description |
|---|---|
| `/ai/triage` | Triage assisté IA (events / incidents) |
| `/ai/rag` | Assistant RAG sur 11k docs (MITRE, NVD, Sigma) |
| `/ai/rule-gen` | Génération règles Sigma/correlation par IA |

### SOAR (2)
| Route | Description |
|---|---|
| `/soar/playbooks` | Bibliothèque playbooks automatisés |
| `/soar/executions` | Historique d'exécutions + résultats |

### Documentation & Admin (4)
| Route | Description |
|---|---|
| `/pentest/docs` | Documentation in-app de tous les modules |
| `/assets` | Inventaire assets monitorés |
| `/reports` | Génération rapports (MITRE, CVSS, exec summary) |
| `/admin` | Gestion users, clés API, RBAC |

---

## Modules backend complémentaires

Le backend FastAPI expose **1046 endpoints**. Beaucoup correspondent à des fonctionnalités **accessibles uniquement via API** (UI retirée en V5 par souci de stabilité). Réactivables au cas par cas.

| Catégorie backend | Routes API exemples |
|---|---|
| Adversary emulation | `/api/pentest/adversary/coverage`, `/emulate/{id}/next` |
| Anti-forensics | `/pentest/antiforensics/clean-logs`, `/timestomp`, `/shred` |
| Auto-exploit | `/pentest/auto-exploit/{session_id}/timeline` |
| Auto-chain | `/pentest/autochain/conditions` |
| AD attacks | `/pentest/ad/delegation` |
| Compliance | `/compliance/attestations`, `/compliance/remediations` |
| Correlation | `/correlation/active`, `/rules`, `/state-machines`, `/simulate` |
| Cases | `/cases/{id}/timeline`, `/transition` |
| Detection MITRE | `/detection/mitre/coverage`, `/navigator` |
| Implants | `/implants/c2-profile`, `/c2-protocols` |
| Integrations | `/integrations`, `/sync-all`, `/test` |

→ Voir `/docs` (Swagger) pour la liste exhaustive.

---

## Red Team (C2, Phishing, AD)

### Sliver C2
- **Intégration gRPC** vers Sliver daemon (`:31337`)
- **Operator Console** — terminal live, gestion sessions, beacon graph
- **Implants** — génération par engagement, beacons/sessions
- **Pivot BloodHound** — utilise les dumps AD pour planifier le lateral movement

### Phishing (GoPhish)
- **Campagnes** — création, envoi, tracking (sent/opened/clicked/submitted)
- **Templates email + landing pages**
- **Scope enforcement** — RoE check par domaine email avant envoi
- **Kill-switch** — arrêt d'urgence + audit trail
- **Sync engine** — dedup events + recompte counts + propagation kill-switch

### Engagements
- **Tracking complet** — scope, clients, dates, RoE signée
- **MITRE reporting** — mapping auto TTP → techniques
- **Kill-switch global** — bloque toute action offensive si activé

---

## Assistant IA

**Multi-provider** (priorité configurable) :
- **Anthropic Claude** (primary) — via API key
- **OpenAI** (fallback optionnel)
- **Ollama local** (fallback gratuit, modèle `qwen2.5-coder:7b`, sans clé)

**Contexte injecté automatiquement** :
- Engagement actif (scope, RoE, kill-switch)
- Sessions Sliver compromises
- Credentials extraits (vault Fernet)
- Résultats BloodHound récents
- Historique de la session chat

**RAG intégré** — 11 000+ docs indexés (MITRE, NVD CVE, SigmaHQ rules). Recherche sémantique (`all-MiniLM-L6-v2`, 384 dim), FAISS.

**Persistance** — chaque message sauvegardé (table `chat_messages`), historique par engagement.

---

## Quick Start

### Docker (recommandé)

```bash
docker compose up --build
```

| Service   | URL                        |
|-----------|----------------------------|
| Dashboard | http://localhost:3001      |
| API       | http://localhost:8000      |
| API Docs  | http://localhost:8000/docs |
| GoPhish   | http://localhost:3333      |

**Credentials par défaut :** `admin` / `admin`

### Services externes requis

**Ollama** (host) :
```bash
ollama pull qwen2.5-coder:7b
ollama serve  # écoute sur :11434
```

**Sliver C2** (host) :
```bash
sliver-server daemon  # écoute sur :31337
# Copier operator.cfg dans /data/sliver/configs/
```

**GoPhish** (host, container séparé) :
```bash
docker run -d --name gophish -p 3333:3333 -p 8080:8080 gophish/gophish
```

### Développement local

**Backend :**
```bash
pip install -r requirements.txt
uvicorn apps.api.main:app --reload
```

**Frontend :**
```bash
cd apps/web
npm install
npm run dev  # port 3001
```

**Workers :**
```bash
celery -A apps.api.celery_app worker --loglevel=info
celery -A apps.api.celery_app beat --loglevel=info
```

---

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | — | Redis connection string |
| `API_KEY` | — | Clé API primaire |
| `JWT_SECRET_KEY` | — | Secret JWT (rotate en prod) |
| `ANTHROPIC_API_KEY` | — | Clé Claude (primary LLM) |
| `OPENAI_API_KEY` | — | Clé OpenAI (fallback) |
| `OLLAMA_BASE_URL` | `http://host.docker.internal:11434` | Ollama local |
| `OLLAMA_MODEL` | `qwen2.5-coder:7b` | Modèle Ollama |
| `SLIVER_OPERATOR_CFG` | `/data/sliver/configs/operator.cfg` | Config opérateur Sliver |
| `SLIVER_DEFAULT_C2_URL` | `https://host.docker.internal:8443` | Listener HTTPS C2 |
| `GOPHISH_API_URL` | `https://host.docker.internal:3333` | API GoPhish |
| `GOPHISH_API_KEY` | — | Clé API GoPhish |
| `GEOIP_DB_PATH` | `/app/data/GeoLite2-City.mmdb` | MaxMind DB |
| `ABUSEIPDB_API_KEY` | — | Threat intel AbuseIPDB |
| `OTX_API_KEY` | — | AlienVault OTX |
| `WEBHOOK_URL` | — | Webhook notifications |

---

## Migrations DB

```bash
alembic upgrade head                             # appliquer toutes les migrations
alembic revision --autogenerate -m "description" # nouvelle migration
```

**Tête actuelle :** `022_chat_messages` (23 migrations)

**Actions post-install** (1x) :
- `POST /ai/rag/rebuild` — index RAG (MITRE + NVD + Sigma → ~11k docs)
- `POST /sigma/sync` — import rules depuis SigmaHQ

---

## Tech Stack

| Layer | Technologies |
|-------|--------------|
| **Backend** | Python 3.11, FastAPI, SQLAlchemy, Celery, scikit-learn, structlog, OpenTelemetry |
| **Frontend** | Next.js 15, React 18, TypeScript, Tailwind CSS, D3, Leaflet, Framer Motion, TanStack Query |
| **IA / RAG** | Anthropic, OpenAI, Ollama, sentence-transformers, FAISS |
| **Infra** | Docker Compose, PostgreSQL 16, Redis 7, Alembic |
| **Sécurité** | JWT + API key, SSO (SAML/OIDC), RBAC, rate limiting, CORS, kill-switch |
| **Offensif** | Sliver C2, GoPhish, BloodHound, custom engines (SQLi/XSS/Brute) |

---

## Documentation

La documentation complète vit dans [`docs/`](./docs/) :

| Fichier | Contenu |
|---------|---------|
| [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) | Vision globale, diagrammes Mermaid, flux données, sécurité |
| [`docs/ONBOARDING.md`](./docs/ONBOARDING.md) | Setup d'un nouveau dev (0 → productif) |
| [`docs/api-reference.md`](./docs/api-reference.md) | Lien Swagger + exemples curl par domaine |
| [`docs/adr/`](./docs/adr/) | Architecture Decision Records (5 ADRs) |
| [`docs/runbooks/`](./docs/runbooks/) | Runbooks opérationnels |

**ADRs disponibles :**
- [ADR-0001 — Stack FastAPI + Next.js + PostgreSQL](./docs/adr/0001-stack-choice.md)
- [ADR-0002 — Auth duale JWT + API key](./docs/adr/0002-auth-dual-jwt-apikey.md)
- [ADR-0003 — LLM multi-provider](./docs/adr/0003-llm-multi-provider.md)
- [ADR-0004 — Sliver C2](./docs/adr/0004-sliver-c2-integration.md)
- [ADR-0005 — Split pentest.py](./docs/adr/0005-split-pentest-routes.md)

**Runbooks disponibles :**
- [DR — Disaster Recovery](./docs/runbooks/DR.md)
- [Déploiement en production](./docs/runbooks/deploy.md)
- [Incident : API down](./docs/runbooks/incident-api-down.md)
- [Incident : RAG index vide](./docs/runbooks/incident-rag-index-vide.md)
- [Migrations DB (upgrade / rollback)](./docs/runbooks/db-migration.md)

---

## Historique des vagues

- **V1–V3** — SIEM core, DevSecOps, GeoIP, TI, AI triage, SOAR, pentest base, RAG, Sigma, UBA, compliance, OTel, notifications
- **V4.1–V4.5** — Outbound integrations, SSO federation, Sliver C2, engagement tracking, MITRE reporting, Operator Console, BloodHound import
- **V4.6** — Phishing Red Team (GoPhish workflow enrichi + scope/kill-switch)
- **V4.7** — Post-Exploit Credential Vault (browser, cloud, secrets)
- **V4.8** — Assistant pentest multi-provider (Claude/OpenAI/Ollama) avec contexte engagement
- **V4.9** — Hardening 3 tours : 95+ bugs corrigés, validation E2E
- **V5** — **Phase de simplification** : retrait de 88 pages frontend non finies (gardé 30 stables), nettoyage navigation, alignement docs ↔ réalité

---

> **Disclaimer :** Les outils offensifs inclus sont destinés strictement à des audits autorisés, missions de pentest sous contrat, ou contextes éducatifs (CTF, labs). Toute utilisation non autorisée est illégale.
