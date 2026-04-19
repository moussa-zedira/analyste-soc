# API Reference

L'API est **entièrement documentée par OpenAPI**, généré automatiquement
par FastAPI depuis les annotations Pydantic des endpoints.

## Documentation interactive

| Interface      | URL                                   | Disponibilité               |
|----------------|---------------------------------------|-----------------------------|
| Swagger UI     | `http://localhost:8000/docs`          | Dev et staging uniquement   |
| ReDoc          | `http://localhost:8000/redoc`         | Dev et staging uniquement   |
| OpenAPI JSON   | `http://localhost:8000/openapi.json`  | Dev et staging              |

En production (`ENV=prod`), `/docs` et `/redoc` sont désactivés. Pour
consulter l'OpenAPI, récupérer le JSON depuis un environnement non-prod
et l'ouvrir localement dans Swagger UI.

## Authentification

Tous les endpoints (sauf `/livez`, `/readyz`, `/health`, `/metrics`,
`/auth/login`) exigent une authentification. Deux mécanismes acceptés
au choix (voir [ADR-0002](./adr/0002-auth-dual-jwt-apikey.md)) :

### API key (service-à-service)

```bash
curl -H "X-API-Key: $API_KEY" http://localhost:8000/<path>
```

### JWT Bearer (utilisateur)

```bash
# 1. Login
curl -X POST http://localhost:8000/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "<password>"}'
# → {"access_token": "eyJ...", "refresh_token": "eyJ...", ...}

# 2. Appel authentifié
curl -H "Authorization: Bearer $ACCESS_TOKEN" http://localhost:8000/<path>
```

## Exemples par domaine

### Health

```bash
# Liveness (pas de dépendance)
curl http://localhost:8000/livez
# → {"status":"ok"}

# Readiness (DB + Redis)
curl http://localhost:8000/readyz
# → {"status":"ready","components":{"database":"ok","redis":"ok"}}

# Vue détaillée (rétrocompatible)
curl http://localhost:8000/health
```

### Events

```bash
# Ingérer un événement
curl -X POST http://localhost:8000/events/ \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "source": "syslog",
       "host": "srv-web-01",
       "severity": "high",
       "message": "ssh brute force detected",
       "src_ip": "198.51.100.10"
     }'

# Lister les derniers événements
curl -H "X-API-Key: $API_KEY" \
     "http://localhost:8000/events/?limit=50&severity=high"
```

### Incidents

```bash
# Lister les incidents ouverts
curl -H "X-API-Key: $API_KEY" \
     "http://localhost:8000/incidents/?status=open"

# Détail d'un incident
curl -H "X-API-Key: $API_KEY" \
     http://localhost:8000/incidents/<incident-id>
```

### Pentest — scan recon

```bash
curl -X POST http://localhost:8000/recon/scan \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "example.com",
       "modules": ["subdomain", "port_scan", "tech_stack"]
     }'
```

### Findings

```bash
# Ajouter un finding à un engagement
curl -X POST http://localhost:8000/findings/ \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "engagement_id": "<uuid>",
       "title": "SQLi Union-based on /api/products",
       "severity": "high",
       "mitre_technique": "T1190",
       "evidence": "..."
     }'
```

### Engagements

```bash
# Créer un engagement avec scope
curl -X POST http://localhost:8000/engagements \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Pentest Acme Q2 2026",
       "client": "Acme Corp",
       "scope_cidrs": ["10.0.0.0/8"],
       "scope_domains": ["acme.tld"],
       "roe_signed_at": "2026-04-01T00:00:00Z"
     }'

# Activer le kill-switch d'un engagement
curl -X POST http://localhost:8000/engagements/<id>/kill-switch \
     -H "X-API-Key: $API_KEY"
```

### Chat IA

```bash
curl -X POST http://localhost:8000/chat/messages \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{
       "engagement_id": "<uuid>",
       "message": "Résume les 5 findings les plus critiques"
     }'
```

### RAG

```bash
# Reconstruire l'index (une fois après install, ou rafraîchissement)
curl -X POST http://localhost:8000/ai/rag/rebuild \
     -H "X-API-Key: $API_KEY"

# Recherche sémantique
curl -X POST http://localhost:8000/ai/rag/query \
     -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"query": "kerberoasting detection", "top_k": 5}'
```

### SIGMA

```bash
# Synchroniser les règles depuis SigmaHQ
curl -X POST http://localhost:8000/sigma/sync \
     -H "X-API-Key: $API_KEY"

# Lister les règles actives
curl -H "X-API-Key: $API_KEY" \
     "http://localhost:8000/sigma/rules?enabled=true&limit=20"
```

## WebSockets

| Endpoint                    | Rôle                                     |
|-----------------------------|------------------------------------------|
| `/ws`                       | Broadcast événements + incidents temps réel |
| `/c2/ws/operator`           | Console Sliver — sessions et beacons     |
| `/orchestrator/ws`          | Pentest orchestrator live feed           |
| `/pentest/shell/ws/<id>`    | Shell interactif post-exploit            |
| `/pentest/proxy/ws`         | HTTP interceptor proxy                   |
| `/pentest/interceptor/ws`   | HTTP interceptor fine-grained            |

Auth via paramètre de query `?api_key=...` ou header si supporté par
le client.

## Codes d'erreur

| Code | Sens                                                        |
|------|-------------------------------------------------------------|
| 200  | OK                                                          |
| 201  | Créé                                                        |
| 400  | Validation Pydantic échouée (payload mal formé)             |
| 401  | Auth manquante ou invalide (ni API key, ni JWT)             |
| 403  | Auth valide mais rôle insuffisant                           |
| 404  | Ressource inexistante                                       |
| 409  | Conflit — ex : kill-switch actif, ou duplicate               |
| 422  | Validation sémantique (FastAPI body validation errors)      |
| 429  | Rate limit (SlowAPI, per-IP)                                |
| 503  | `/readyz` uniquement — une dépendance est down              |

## Rate limiting

Rate limit global via [SlowAPI](https://github.com/laurentS/slowapi),
backé par Redis. Limites par défaut :

- `/auth/login` : 5 requêtes / minute / IP.
- Endpoints offensifs (`/pentest/**`) : limites plus strictes selon module.
- Endpoints IA : budget global `AI_DAILY_BUDGET_USD` (cost tracking,
  pas compteur de requêtes).

Passage à 429 → attendre et retry avec backoff exponentiel.

## Pagination

Convention standard sur les endpoints de listing :

```
GET /events/?limit=50&offset=100&sort=-ts
```

Paramètres communs :

- `limit` : défaut 50, max 500.
- `offset` : défaut 0.
- `sort` : champ à trier, préfixer par `-` pour descendant.
- Filtres spécifiques par endpoint (voir `/docs`).

Réponse :

```json
{
  "items": [...],
  "total": 1234,
  "limit": 50,
  "offset": 100
}
```

## Génération de clients

L'OpenAPI JSON permet de générer des clients typés dans n'importe quel
langage :

```bash
# Client TypeScript (exemple)
npx openapi-typescript http://localhost:8000/openapi.json \
    -o apps/web/src/lib/api-types.ts

# Client Python (exemple)
openapi-python-client generate \
    --url http://localhost:8000/openapi.json
```
