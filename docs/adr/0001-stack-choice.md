# ADR-0001 : Stack — FastAPI + Next.js 15 + PostgreSQL

## Status
Accepté (V1, confirmé à chaque vague jusqu'à V4.9).

## Contexte

Le projet démarre comme un outil personnel pour un pentester freelance
qui doit ensuite servir en clientèle, donc la stack doit permettre :

- Un cycle d'itération rapide (hot reload, typage, tests unitaires).
- 750+ endpoints REST avec documentation OpenAPI générée automatiquement.
- Flux temps réel (WebSocket) pour l'event stream SIEM et la console Sliver.
- Un frontend moderne, composants interactifs lourds (graphes D3,
  carte Leaflet, tableaux filtrables avec des milliers de lignes).
- Un déploiement simple (Docker Compose on-prem ou VPS, pas de
  Kubernetes obligatoire).
- Une équipe mono-développeur initialement — chaque choix doit être
  maintenable par une seule personne.

Options considérées :

| Backend            | Frontend           | Écarté parce que                                   |
|--------------------|--------------------|----------------------------------------------------|
| Django + DRF       | React SPA          | DRF lourd, pas de typage endpoints, pas natif async |
| Flask              | React SPA          | Trop bas niveau, pas d'OpenAPI intégré, async fragile |
| Go (Gin/Echo)      | Vue/React          | Productivité solo plus faible, pas d'écosystème ML/IA |
| NestJS             | Next.js            | Deux langages TypeScript, mais écosystème IA/ML faible côté Python |
| **FastAPI**        | **Next.js**        | **Retenu** — voir décision                         |

Base de données candidates :

- SQLite : trop limité pour le pub/sub et les index JSONB.
- MongoDB : pas besoin de schema-less, on veut des contraintes strictes.
- PostgreSQL : gagnant — JSONB, full-text search, pg_trgm, vues,
  extensions.

## Décision

**Backend FastAPI (Python 3.11+)** :

- OpenAPI généré automatiquement depuis les annotations Pydantic.
- `async/await` natif pour WebSocket et appels LLM parallèles.
- Écosystème Python (scikit-learn, sentence-transformers, FAISS,
  Anthropic/OpenAI SDK, nmap wrappers) indispensable aux modules IA et
  offensifs.
- Dependency injection simple (`Depends`) pour la sécurité (auth, RBAC).

**Frontend Next.js 15 (App Router, React 18, TypeScript)** :

- Server Components réduisent le JS envoyé au navigateur.
- Route proxy server-side (`/api/proxy/[...path]`) pour injecter la clé
  API sans l'exposer au client.
- Hot reload solide sur 118 pages.
- TanStack Query + Zustand pour le state, pas de Redux.

**Base : PostgreSQL 16** :

- JSONB pour les événements bruts, évite de multiplier les tables à
  chaque nouveau type de source.
- pg_trgm et FTS pour la recherche d'événements.
- Migrations Alembic (intégré SQLAlchemy).
- Un seul binôme (SQLAlchemy ORM + Alembic) couvre 100 % du besoin.

**Cache + pub/sub : Redis 7** :

- Un seul produit couvre cache TI, rate limiting SlowAPI, pub/sub temps
  réel, et JTI de révocation JWT.

## Conséquences

**Positives :**

- Documentation API gratuite et à jour (`/docs` en dev).
- Écosystème Python pour l'IA, la sécurité offensive et le data science
  sans quitter le langage.
- Next.js App Router gère le SSR, ISR et les routes API dans le même
  projet — une seule build frontend.
- PostgreSQL tient des mois sans optimisation fine jusqu'aux millions
  d'événements.

**Négatives / compromis :**

- Deux langages (Python + TypeScript). Partage de types via génération
  OpenAPI → TS (`openapi-typescript`) au lieu de tRPC.
- Async Python reste verbeux comparé à Go ou Node pour de la pure I/O.
- Taille de l'image Docker API ~1.2 Go (deps ML + offensif). Acceptable
  pour le scope.
- PostgreSQL seul → pas de time-series natif. Acceptable pour V4.x ;
  migration vers TimescaleDB envisageable si le volume événements
  dépasse 10M/jour.

**À surveiller :**

- Si les WebSockets dépassent quelques centaines de connexions
  simultanées, envisager un broadcaster dédié (Centrifugo, Mercure).
- Si l'équipe grandit, évaluer une séparation monorepo → polyrepo
  (api / web / shared types).
