# Analyste SOC

**Cyber Defense Dashboard — SIEM + Offensive Security + Red Team + AI Assistant**

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-15-000000?style=flat-square&logo=next.js&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=flat-square&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat-square&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-Private-red?style=flat-square)

Plateforme unifiée combinant **SIEM défensif**, **65+ modules offensifs**, **opération Red Team** (Sliver C2, GoPhish, BloodHound), et **assistant IA contextuel** (Claude / GPT / Ollama local). Conçue pour un pentester freelance qui doit couvrir tout le cycle — recon → exploit → post-exploit → rapport — depuis un seul dashboard.

**État actuel (V4.9, 2026-04-19)** : 118 pages frontend, 750+ endpoints backend, 65+ modules. Stack validée end-to-end (3 tours de debug automatisés).

> **Disclaimer :** Les outils offensifs inclus sont destinés strictement à des audits autorisés, missions de pentest sous contrat, ou contextes éducatifs (CTF, labs). Toute utilisation non autorisée est illégale.

---

## Sommaire

- [Architecture](#architecture)
- [Modules SIEM / Défense](#modules-siem--défense)
- [Modules Pentest Offensif](#modules-pentest-offensif)
- [Red Team (C2, Phishing, AD)](#red-team-c2-phishing-ad)
- [Assistant IA](#assistant-ia)
- [Workflows guidés](#workflows-guidés)
- [Quick Start](#quick-start)
- [Variables d'environnement](#variables-denvironnement)
- [Migrations DB](#migrations-db)
- [Tech Stack](#tech-stack)
- [Documentation](#documentation)

---

## Architecture

```
apps/
├── api/            FastAPI backend — 750+ endpoints REST + WebSocket
├── web/            Next.js 15 (App Router) — 118 pages
├── agent/          Event simulator
└── collectors/     Syslog, WinLog, File watcher
```

**8 services Docker Compose :**

| Service    | Rôle                                      |
|------------|-------------------------------------------|
| `api`      | Serveur FastAPI                           |
| `web`      | Frontend Next.js                          |
| `postgres` | PostgreSQL 16                             |
| `redis`    | Cache, pub/sub, rate limit, sessions      |
| `worker`   | Celery (tâches async)                     |
| `beat`     | Celery scheduler (tâches périodiques)     |
| `syslog`   | Ingestion syslog UDP/TCP                  |
| `gophish`  | Serveur phishing (container séparé)       |

**Services externes** (host) :
- **Ollama** sur `localhost:11434` — IA locale (`qwen2.5-coder:7b`)
- **Sliver C2** sur `localhost:31337` — daemon opérateur

---

## Modules SIEM / Défense

### Moteur temps réel
- **Event stream** — WebSocket push via Redis pub/sub, journal + carte GeoIP en live
- **Moteur de détection** — règles (brute-force, impossible travel, anomalies stats) + ML (Isolation Forest, TF-IDF)
- **Moteur SIGMA** — import automatique depuis SigmaHQ, conversion des rules, corrélation
- **UBA** — User Behavior Analytics, profils comportementaux, scoring de dérive

### Réponse à incident
- **Gestion des incidents** — création auto, dedup, severity scoring, triage IA (Ollama)
- **SOAR** — playbooks automatisés, actions remediation, intégration webhooks
- **Threat score** — scoring composite (TI, contexte asset, historique)
- **Notifications** — Discord, Slack, Email, Teams (avec retry + backoff)

### Threat Intelligence
- **AbuseIPDB** + **AlienVault OTX** — enrichissement IP/domain avec cache 2 niveaux
- **NVD / CVE** — recherche par keyword ou CPE
- **IOC Manager** — base IOC centralisée (IP, domaines, hash, URL), TTL, confidence scoring

### Visualisation & Analytics
- **MITRE ATT&CK mapping** — heatmap couverture technique
- **Graph relationnel** — graphe force-dirigé IP/user/incident (D3)
- **GeoIP map** — carte temps réel (MaxMind GeoLite2 + Leaflet)
- **Log sources** — santé et disponibilité par source
- **Compliance** — templates ISO27001, NIST CSF, PCI-DSS

### DevSecOps
- **Pipeline scanner** — SAST (semgrep), SCA (trivy/osv), secrets, IaC (checkov)
- **SBOM** — génération CycloneDX
- **Policy as Code** — rules custom YAML

### Plateforme
- **Auth** — JWT + API key + SSO federation (SAML/OIDC)
- **RBAC** — rôles granulaires, mapping attributs IdP
- **Rate limiting** — per-IP, Redis-backed
- **Export** — CSV, JSON, Excel, PDF
- **OpenTelemetry** — traces distribuées, spans manuels
- **Admin panel** — users, clés API, config

---

## Modules Pentest Offensif

> 65+ modules organisés selon la kill chain MITRE.

### Reconnaissance
| Module | Description |
|--------|-------------|
| **Recon** | Subdomain enum, port scan, tech stack detection, SSL cert, Google dorks, robots/sitemap, emails |
| **Deep Scan** | Crawling récursif, détection de surface complète |
| **Subdomain Discovery** | Multi-techniques (DNS, CT logs, wordlists) |
| **NVD / CVE Lookup** | Recherche CVE par keyword ou CPE |
| **Crawler** | Spider ciblé, formulaires, endpoints cachés |

### Web Application
| Module | Description |
|--------|-------------|
| **SQLi Engine** | 5 techniques (UNION/error/boolean/time/stacked), DBMS auto-detect, schema enum, file read, OS exec, 10 tamper fns |
| **XSS Engine** | 6 context detectors, cookie stealer, session hijack, keylogger, BeEF-style hook, WAF bypass |
| **LFI→RCE** | 15+ traversals, log poisoning, wrappers PHP, `/proc` exploit, auto-chain |
| **SSRF Advanced** | Cloud metadata, internal port scan, protocol smuggling |
| **SSTI** | Template engines (Jinja2, Twig, ERB, FreeMarker) |
| **XXE / Blind extraction** | XXE OOB, blind SQL/SSRF |
| **WAF Bypass** | Encoding, chunking, case manipulation |
| **JWT Attacks** | None algo, key confusion, JWK/JKU injection |
| **Smart Payload** | Payload builder contextuel |
| **Headless** | Chrome automation, DOM XSS dynamique |
| **Interceptor** | Proxy HTTP interactif |
| **AI Vuln** | Détection assistée par IA |

### Réseau & Protocoles
| Module | Description |
|--------|-------------|
| **Protocol Exploiter** | 7 protocoles (SMB/LDAP/RDP/FTP/SNMP/DNS/SMTP), 38 attaques, EternalBlue/SMBGhost/BlueKeep, Kerberoasting |
| **Network Scan** | Scan avancé (nmap-like), service fingerprint |
| **NetMap** | Cartographie réseau visuelle |
| **Network Evasion** | Fragmentation, tunneling, protocol abuse |

### Active Directory & Cloud
| Module | Description |
|--------|-------------|
| **BloodHound** | Import dump, analyse chemins d'attaque, pivot read-only |
| **AD Tools** | Kerberoasting, ASREPRoasting, SID history, trust relationships |
| **Cloud** | AWS (IAM, S3, EC2), Azure, GCP — misconfigurations |
| **K8s RBAC** | Audit RBAC, escalade de privilèges |

### Post-Exploitation
| Module | Description |
|--------|-------------|
| **Shell Handler** | TCP listener, 18 payload templates, WebSocket interactif, upgrade PTY |
| **PrivEsc** | 55 GTFOBins, 21 kernel CVEs (DirtyCOW, DirtyPipe, PwnKit), 40+ checks Linux / 30+ Windows, Potato attacks |
| **Credential Harvester** | 50+ sources (configs, SSH keys, cloud, browsers, registry, SAM), parsers, hash ID |
| **Credential Vault** | Coffre-fort centralisé (Fernet), browser/cloud/secrets modules |
| **Lateral Movement** | PtH, PtT, PSExec, WMI, WinRM, SSH pivot, chisel, spray, planner MITRE |

### Persistence & Évasion
| Module | Description |
|--------|-------------|
| **Persistence** | Backdoors, registry, cron, services |
| **Anti-Forensics** | Log cleaning, timestomp, artifact removal |
| **Exfiltration** | DNS/HTTP/ICMP exfil, steganography, channels chiffrés |
| **Stealth** | Traffic obfuscation, timing evasion |
| **Shellcode** | Generator, encoder, loader |

### Mobile / IoT
| Module | Description |
|--------|-------------|
| **Mobile** | APK/IPA analysis, Frida hooks |
| **IoT** | Firmware analysis, protocole MQTT/CoAP |

### Orchestration & Rapports
| Module | Description |
|--------|-------------|
| **Attack Chain Engine** | State machine persistante, 37 auto-actions, 3 modes (manual/semi/auto), kill-chain tracking |
| **Workflows** | **Templates guidés** étape-par-étape (voir section dédiée) |
| **Campaign / Engagement** | Suivi mission, scope, RoE, kill-switch |
| **Session Manager** | HTTP sessions partagées, cookie jar, CSRF auto, re-auth |
| **Pipeline** | Scans chaînés automatiques |
| **Report** | Rapports professionnels (MITRE, CVSS, preuves, exec summary) |
| **Findings** | Base des découvertes, statut, exploitation |
| **Hash Cracker** | Dictionary, brute, rules |
| **Wordgen** | Wordlist custom générée |
| **Templates** | Templates pentest réutilisables |
| **History** | Historique scans + comparaison |
| **Adversary Emulation** | Rejeu TTPs MITRE |
| **Scanner** | Scan vuln unifié |

---

## Red Team (C2, Phishing, AD)

### Sliver C2
- **Intégration gRPC** vers Sliver daemon local (`31337`)
- **Operator Console** — terminal live, gestion sessions, beacon graph
- **Implants** — génération par engagement, beacons/sessions
- **Pivot BloodHound** — utilise les dumps AD pour planifier le lateral movement

### Phishing (GoPhish)
- **Campagnes** — création, envoi, tracking (sent/opened/clicked/submitted)
- **Templates email** — galerie + éditeur
- **Landing pages** — mock login + capture credentials
- **Scope enforcement** — double-check RoE avant envoi
- **Kill-switch** — arrêt d'urgence de toute campagne

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
- Machines compromises (sessions Sliver)
- Credentials extraits (vault)
- Résultats BloodHound récents
- Historique de la session chat

**RAG intégré** — 11 000+ docs indexés (MITRE, NVD CVE, SigmaHQ rules). Recherche sémantique (`all-MiniLM-L6-v2`, 384 dim), FAISS.

**Persistance** — chaque message sauvegardé (table `chat_messages`), historique par engagement.

---

## Workflows guidés

Plutôt que tout demander à l'assistant, la plateforme fournit des **templates de mission** préconfigurés accessibles depuis `/pentest/workflows`. Chaque template enchaîne les étapes avec paramètres pré-remplis, notes par step, et rapport auto.

Exemples de templates : recon web externe, audit AD interne, test API, revue cloud AWS, campagne phishing. Tu peux suivre le workflow pas-à-pas, skip une étape, ou sortir du rail pour taper directement sur un module.

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
# Copier operator.cfg dans le volume Docker /data/sliver/configs/
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

Tête actuelle : `022_chat_messages`.

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
| **Offensif** | Sliver C2, GoPhish, BloodHound, nmap-like, custom engines |

---

## Documentation

La documentation complète vit dans [`docs/`](./docs/) :

| Fichier | Contenu |
|---------|---------|
| [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) | Vision globale, diagrammes Mermaid, flux données, sécurité |
| [`docs/ONBOARDING.md`](./docs/ONBOARDING.md) | Setup d'un nouveau dev (0 → productif), prérequis, smoke tests |
| [`docs/api-reference.md`](./docs/api-reference.md) | Lien Swagger auto + exemples curl par domaine |
| [`docs/adr/`](./docs/adr/) | Architecture Decision Records (5 ADRs initiaux) |
| [`docs/runbooks/`](./docs/runbooks/) | Runbooks opérationnels (DR, deploy, incidents, migrations) |

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

- **V1–V3** (12 commits) — SIEM core, DevSecOps, GeoIP, TI, AI triage, SOAR, pentest base, RAG, Sigma, UBA, compliance, OTel, notifications
- **V4.1–V4.5** — Outbound integrations, SSO federation, Sliver C2, engagement tracking, MITRE reporting, Operator Console, BloodHound import
- **V4.6** — Phishing Red Team (GoPhish workflow enrichi + scope/kill-switch)
- **V4.7** — Post-Exploit Credential Vault (browser, cloud, secrets)
- **V4.8** — Assistant pentest multi-provider (Claude/OpenAI/Ollama) avec contexte engagement
- **V4.9** — Hardening 3 tours : 95+ bugs corrigés, validation E2E, 0 régression frontend sur 118 pages
