# Runbook : API down (incident oncall)

## Symptôme

Un ou plusieurs des signaux suivants :

- Dashboard affiche une bannière "API unreachable" ou renvoie 502/504
  sur les requêtes.
- Alerte Prometheus `up{job="api"} == 0` depuis > 2 min.
- `curl https://<domain>/livez` → timeout, 502, 503.
- Les collectors syslog empilent des erreurs POST dans leurs logs.
- WebSockets `/ws` et `/c2/ws/operator` se déconnectent en boucle.

## Diagnostic

Lancer ces commandes **dans l'ordre**, passer à la résolution dès que
la cause est identifiée.

### 1. Status Docker

```bash
docker compose ps
```

Repérer l'état du service `api` :

| État observé            | Cause probable                                   |
|-------------------------|--------------------------------------------------|
| `Exit 1` / `Exit 137`   | Crash (OOM, exception startup). Voir §2.         |
| `Restarting`            | Crash-loop — healthcheck échoue. Voir §2.        |
| `Up`, healthy           | L'API tourne mais n'est pas joignable depuis l'extérieur. Voir §3. |
| Absent de la liste      | Service stoppé manuellement. Voir §4.            |

### 2. Logs API

```bash
docker compose logs --tail=200 api
```

Chercher dans les dernières lignes :

- `config_invalid_for_prod` → `.env` incomplet ou secret faible. Voir §5.
- `audit_signing_key_missing` (warning, pas bloquant en dev).
- `Traceback` Python → exception startup. Prendre le nom de l'exception.
- `OperationalError: could not connect to server: postgres` → DB down.
  Voir §6.
- `redis.exceptions.ConnectionError` → Redis down. Voir §6.
- `OOM` / `Killed` → mémoire saturée. Voir §7.

### 3. L'API tourne mais n'est pas joignable

Tester depuis l'intérieur du container :

```bash
docker compose exec api curl http://localhost:8000/livez
# → 200 : problème réseau/proxy extérieur
# → erreur : l'API n'écoute pas
```

Si 200 en interne mais KO en externe :

```bash
# Vérifier que nginx / proxy est up
docker compose ps | grep nginx
# Logs nginx
docker compose logs --tail=50 nginx
```

### 4. Service stoppé

```bash
docker compose up -d api
```

Si redémarrage manuel insuffisant, continuer le diag.

### 5. Validation config prod

Le lifespan refuse de démarrer si `ENV=prod` et des secrets sont
faibles (cf. `settings.validate_for_prod`).

```bash
grep -E "^(ENV|API_KEY|JWT_SECRET_KEY|AUDIT_SIGNING_KEY|POSTGRES_PASSWORD)=" .env
```

Chaque secret doit faire au moins 32 caractères (48 pour JWT).
Régénérer si besoin :

```bash
make secrets-gen
# copier les valeurs dans .env
```

### 6. Dépendances DB / Redis

```bash
# Postgres up ?
docker compose exec postgres pg_isready -U ${POSTGRES_USER}
# → accepting connections

# Redis up ?
docker compose exec redis redis-cli ping
# → PONG
```

Si KO : redémarrer le service concerné.

```bash
docker compose restart postgres   # ou redis
# Attendre healthy
docker compose ps
```

### 7. Mémoire saturée

```bash
docker stats --no-stream
```

Si `api` ou `worker` sont à 95+ % de leur limite (`mem_limit: 2g`) :

```bash
# Identifier la cause dans les logs récents
docker compose logs --tail=500 worker | grep -i "scan\|rag\|ml"
```

Causes fréquentes : RAG rebuild en cours, scan pentest massif, ML
training concurrent.

## Résolution

### Cas A — Crash startup (config invalide)

1. Corriger `.env` selon §5.
2. Redémarrer : `docker compose up -d --force-recreate api worker beat`.
3. Revérifier : `curl https://<domain>/readyz`.

### Cas B — DB ou Redis down

1. Redémarrer la dépendance : `docker compose restart postgres` (ou `redis`).
2. Attendre healthy : `docker compose ps`.
3. L'API redevient healthy automatiquement via le healthcheck.
4. Vérifier : `curl https://<domain>/readyz`.

Si Postgres refuse de démarrer :

```bash
docker compose logs --tail=100 postgres
# Chercher : "FATAL", "PANIC", "corrupt"
```

Corruption disque → voir [DR.md §3 Restauration](./DR.md#3-restauration-apres-incident).

### Cas C — Crash-loop (Traceback récurrent)

1. Identifier l'exception dans les logs.
2. Si c'est un bug dans la version fraîchement déployée → rollback :
   voir [deploy.md — Rollback rapide](./deploy.md#rollback-rapide).
3. Si c'est un bug historique, créer une issue et proposer un workaround
   temporaire (ex : désactiver une feature via une env var).

### Cas D — OOM

1. Immediate : `docker compose restart api worker` (vide la mémoire).
2. Si le problème se reproduit :
   - Baisser `--concurrency` du worker Celery dans
     `docker-compose.yml` (défaut 2, mettre 1).
   - Augmenter `mem_limit` sur l'hôte si la RAM disponible le permet.
   - Tuer les scans/operations qui saturent depuis `/admin` ou en DB.
3. Root cause : chercher une régression mémoire (leak dans un scan,
   chargement d'un modèle ML trop gros).

### Cas E — Proxy/TLS KO

1. Redémarrer nginx : `docker compose restart nginx`.
2. Vérifier certificats (pas expirés) : `openssl x509 -in certs/fullchain.pem -noout -dates`.
3. Si certs expirés : renouveler via Let's Encrypt ou
   `make tls-certs` (staging).

## Prévention

- **Alerting Prometheus** configuré :
  - `up{job="api"} == 0 for 2m` → PagerDuty / Discord.
  - `(node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) < 0.1 for 5m` → avertissement.
  - `pg_up == 0` et `redis_up == 0`.
- **Healthchecks Docker** déjà en place : `api`, `postgres`, `redis`,
  `web` ont tous un healthcheck qui permet à `depends_on: condition:
  service_healthy` de fonctionner.
- **Resource limits** (`mem_limit`, `cpus`) déjà définis V4.7 pour
  éviter la cascade OOM — ne pas les retirer.
- **Secrets validés** au boot → pas de démarrage silencieux avec
  une config faible.
- **Post-mortem** systématique après tout incident > 15 min :
  timeline + root cause + action corrective.
