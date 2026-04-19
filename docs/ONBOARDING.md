# Onboarding — nouveau contributeur

Objectif : être productif en moins d'une heure. Ce guide part d'une
machine vierge et te mène jusqu'à un dashboard fonctionnel avec tous
les services connectés.

Si une étape échoue, voir la section [Troubleshooting](#troubleshooting)
en fin de document.

---

## 1. Prérequis

| Outil             | Version minimale | Vérifier avec                 |
|-------------------|------------------|-------------------------------|
| Docker Desktop    | 4.30+            | `docker --version`            |
| Docker Compose    | v2 (intégré)     | `docker compose version`      |
| Python            | 3.11 (recommandé 3.12) | `python --version`      |
| Node.js           | 20 LTS           | `node --version`              |
| npm               | 10+              | `npm --version`               |
| Git               | 2.40+            | `git --version`               |
| Make (optionnel)  | GNU make 4+      | `make --version`              |

**Composants optionnels mais recommandés :**

- **Ollama** (LLM local gratuit) — https://ollama.com
- **Sliver** (C2 Red Team) — https://github.com/BishopFox/sliver

RAM conseillée : 16 Go minimum (8 Go seulement permettent de démarrer la
stack mais le worker Celery sature vite avec les scans).

---

## 2. Clone et configuration

```bash
git clone <url-du-repo> analyste-soc
cd analyste-soc
cp .env.example .env
```

Éditer `.env` et remplir au minimum :

```env
ENV=dev
POSTGRES_USER=cyberdef
POSTGRES_PASSWORD=<mot de passe fort>
POSTGRES_DB=cyberdef
DATABASE_URL=postgresql+psycopg2://cyberdef:<password>@postgres:5432/cyberdef
REDIS_URL=redis://redis:6379/0

# Obligatoire : généré par `make secrets-gen`
API_KEY=<32+ chars>
JWT_SECRET_KEY=<48+ chars>
AUDIT_SIGNING_KEY=<32+ chars>

# IA (optionnel mais recommandé — au moins un des trois)
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# OLLAMA_BASE_URL=http://host.docker.internal:11434
```

Générer des secrets forts d'un coup :

```bash
make secrets-gen
```

---

## 3. Démarrage de la stack

### Option A — tout via Docker (recommandé)

```bash
docker compose up -d --build
docker compose logs -f api     # suivre le boot
```

Au premier démarrage, l'API :

1. Applique les migrations Alembic (22 migrations).
2. Crée un compte `admin` par défaut. Le mot de passe est affiché **une
   seule fois** dans les logs :
   ```bash
   docker compose logs api | grep default_admin_created
   ```
3. Seed les playbooks SOAR et les règles SIGMA built-in.

### Option B — backend local, infra Docker

Utile si tu itères sur du code Python et veux garder Uvicorn en reload.

```bash
docker compose up -d postgres redis
make setup-api
uvicorn apps.api.main:app --reload
```

Dans un autre terminal :

```bash
celery -A apps.api.celery_app worker --loglevel=info
```

### Option C — frontend local, API Docker

```bash
docker compose up -d postgres redis api worker
cd apps/web
npm install
npm run dev    # http://localhost:3001
```

---

## 4. Smoke tests

Vérifier que l'installation fonctionne :

```bash
# 1. Process API vivant
curl http://localhost:8000/livez
# → {"status":"ok"}

# 2. Dépendances (DB + Redis) prêtes
curl http://localhost:8000/readyz
# → {"status":"ready","components":{"database":"ok","redis":"ok"}}

# 3. Auth API key
curl -H "X-API-Key: $API_KEY" http://localhost:8000/protected-check
# → {"status":"ok"}

# 4. Dashboard accessible
curl -I http://localhost:3001
# → HTTP/1.1 200 OK

# 5. Docs Swagger (dev uniquement)
open http://localhost:8000/docs
```

Connexion UI : `http://localhost:3001/login` avec `admin` + mot de passe
lu dans les logs.

---

## 5. Services externes

### Ollama (LLM local)

```bash
ollama serve                  # écoute sur :11434
ollama pull qwen2.5-coder:7b  # ~4 Go
```

Vérifier depuis l'API :

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/ai/status
```

### RAG (recherche sémantique)

À lancer une fois après install :

```bash
curl -X POST -H "X-API-Key: $API_KEY" \
  http://localhost:8000/ai/rag/rebuild
```

L'index FAISS (~11 000 docs MITRE + NVD + Sigma) est construit dans le
volume `rag_data`. Compter ~5 minutes la première fois.

### Sliver C2 (optionnel)

```bash
docker compose --profile redteam up -d sliver
docker compose exec sliver sliver-server operator \
  --name op --lhost 0.0.0.0 --save /data/sliver/configs/operator.cfg
```

Exporter `SLIVER_OPERATOR_CFG=/data/sliver/configs/operator.cfg` dans
`.env` et redémarrer l'API.

### GoPhish (optionnel)

Remplir dans `.env` :

```env
GOPHISH_API_URL=https://host.docker.internal:3333
GOPHISH_API_KEY=<clé admin GoPhish>
```

---

## 6. Structure du repo

```
analyste-soc/
├── apps/
│   ├── api/                    Backend FastAPI
│   │   ├── main.py             Point d'entrée, création FastAPI app
│   │   ├── routes/             Sous-routers HTTP (auth, events, ...)
│   │   ├── pentest/            Modules offensifs (recon, exploit, ...)
│   │   ├── ai/                 LLM client, RAG, triage
│   │   ├── models/             SQLAlchemy models
│   │   ├── detection/          Rules + ML + SIGMA engine
│   │   ├── soar/               Playbooks automation
│   │   ├── tests/              pytest (unit + integration)
│   │   └── Dockerfile
│   ├── web/                    Frontend Next.js 15
│   │   ├── src/app/            App Router (118 pages)
│   │   ├── src/components/     Composants partagés
│   │   ├── src/lib/            SDK API, helpers
│   │   └── Dockerfile
│   ├── agent/                  Simulateur events (dev)
│   └── collectors/             Syslog UDP/TCP collector
├── alembic/
│   └── versions/               22 migrations
├── docs/                       Ce dossier
├── scripts/                    backup.sh, restore.sh, secrets-init.sh, ...
├── monitoring/                 Prometheus + Grafana config
├── docker-compose.yml          Stack de base
├── docker-compose.secrets.yml  Overlay prod (Docker secrets)
├── docker-compose.tls.yml      Overlay nginx + TLS
├── docker-compose.monitoring.yml  Overlay Prom/Grafana
├── Makefile                    Commandes dev
└── pyproject.toml              ruff + mypy + pytest config
```

---

## 7. Conventions de code

### Python (apps/api, alembic)

- **Formatter + lint** : `ruff` (config dans `pyproject.toml`).
  ```bash
  make format-api    # format + autofix
  make lint-api      # check seulement
  ```
- **Type checking** : `mypy` strict pour les modules sécurité
  (`security.py`, `auth.py`, `config.py`). Non strict ailleurs.
  ```bash
  make typecheck
  ```
- **Tests** : pytest, markers `integration` et `slow`.
  ```bash
  make test-api            # unit seulement
  make test-integration    # nécessite Docker
  ```
- **Ligne** : 100 cols (soft limit, pas strict).
- **Docstrings** : français pour la logique métier, anglais pour les
  utilitaires techniques (convention existante, ne pas mélanger dans un
  même module).

### TypeScript (apps/web)

- **ESLint** : `cd apps/web && npm run lint`.
- **Prettier** : `make format-web`.
- **Import** : App Router Next.js 15, server components par défaut,
  `"use client"` explicite pour l'interactif.
- **Port dev** : `3001` (jamais 3000, occupé par un autre projet).

### Commits

- Style inspiré de Conventional Commits sans être strict.
- Format recommandé : `Vx.y <Domaine>: description courte` (cf. git log).
  Exemples :
  - `V4.7 Post-Exploit: Credential Vault + browser/cloud/secrets modules`
  - `V4.6b Phishing: scope/RoE check + kill-switch + stop endpoint`
- Commits fréquents, petits, testables.

### Migrations Alembic

- Toujours `autogenerate` puis relire le diff :
  ```bash
  alembic revision --autogenerate -m "description"
  # OU
  make migrate-create M="description"
  ```
- Nommer `NNN_snake_case.py`, numéroté séquentiellement.
- Prévoir la route `downgrade()` pour les tables critiques.

---

## 8. Workflow typique

1. Créer une branche : `git checkout -b v4.10-<feature>`.
2. Coder, écrire les tests en parallèle.
3. Avant commit : `make format && make lint && make test`.
4. Commit, push.
5. PR vers `main` avec description technique + captures si UI.

---

## 9. Troubleshooting

| Symptôme                              | Cause probable                                   | Action                                           |
|---------------------------------------|--------------------------------------------------|--------------------------------------------------|
| `readyz` renvoie 503 database=error   | Postgres pas prêt ou creds incorrectes           | `docker compose logs postgres`                   |
| `readyz` redis=unavailable            | Redis down ou URL mal formée                     | `docker compose restart redis`                   |
| Port 3001 déjà utilisé                | Autre projet Next.js sur cette machine           | Changer le mapping dans `docker-compose.yml`     |
| `default_admin_created` introuvable   | Un utilisateur existe déjà                       | Demander un reset à un admin existant            |
| LLM renvoie `[LLM-FAILURE]`           | Aucune clé configurée ni Ollama démarré          | Voir [ARCHITECTURE §6](./ARCHITECTURE.md#6-assistant-ia--multi-provider) |
| RAG renvoie 0 résultats               | Index non construit                              | Voir [runbooks/incident-rag-index-vide.md](./runbooks/incident-rag-index-vide.md) |
| Alembic échoue au boot                | Migration cassée ou DB divergente                | Voir [runbooks/db-migration.md](./runbooks/db-migration.md) |

---

## 10. Où poser une question

- **Décision structurante** (stack, archi, refacto) : relire les ADRs
  dans [`adr/`](./adr/) avant de proposer un changement.
- **Bug ou feature** : ouvrir une issue avec label `bug` ou `enhancement`.
- **Sécurité** : canal privé uniquement, ne pas publier en clair.
- **Questions dev quotidiennes** : demander dans le channel équipe.

Bienvenue.
