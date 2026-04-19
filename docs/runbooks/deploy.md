# Runbook : déploiement en production

## Symptôme
Pas un incident : guide nominal de mise en production d'une nouvelle
version de la plateforme sur un hôte déjà provisionné.

Prérequis : hôte Linux avec Docker Desktop ou Docker Engine installé,
accès SSH, domaine DNS pointant sur l'hôte, port 443 ouvert.

## Diagnostic — avant déploiement

Valider que l'environnement est prêt :

```bash
# 1. Version Docker Compose v2
docker compose version
# → Docker Compose version v2.29+

# 2. Secrets présents et en mode 600
ls -la secrets/
# → -rw------- … api_key.txt jwt_secret.txt postgres_password.txt audit_signing_key.txt

# 3. Certificats TLS en place
ls -la certs/
# → fullchain.pem, privkey.pem

# 4. .env configuré pour la prod
grep ^ENV= .env
# → ENV=prod

# 5. Backup récent disponible (< 24h)
ls -lh backups/ | tail -3
```

Si un secret manque : `make secrets-init`. Si les certs manquent :
`make tls-certs` (staging uniquement, sinon utiliser Let's Encrypt).

## Résolution — déploiement

### 1. Backup préventif

Avant tout, créer un point de retour :

```bash
make backup
# → ./backups/cyberdef-<host>-<ts>.dump
```

Vérifier que le dump n'est pas vide :

```bash
ls -lh backups/ | tail -1
# doit peser plusieurs Mo minimum
```

### 2. Récupérer la nouvelle version

```bash
cd /opt/analyste-soc
git fetch --tags
git checkout <tag ou commit>
# → ex : git checkout V4.9
```

### 3. Lecture des release notes

Vérifier le CHANGELOG ou le dernier commit :

```bash
git log --oneline -20
```

Attention particulière à :

- Nouvelles variables d'environnement → mettre à jour `.env`.
- Nouvelles migrations Alembic → appliquées automatiquement au boot,
  mais vérifier qu'elles n'exigent pas un downtime.
- Changements d'image base → rebuild obligatoire.

### 4. Build des images

```bash
docker compose -f docker-compose.yml \
               -f docker-compose.secrets.yml \
               -f docker-compose.tls.yml \
               build --pull api web worker beat
```

Le `--pull` récupère les dernières images base (Python, Node, Postgres).

### 5. Application rolling

Redémarrer les services par ordre de dépendance, sans couper les autres :

```bash
# Pas de nouveau schéma à appliquer à la main : l'API le fait au lifespan.
# On redémarre API + workers, la base reste up.

docker compose -f docker-compose.yml \
               -f docker-compose.secrets.yml \
               -f docker-compose.tls.yml \
               up -d --force-recreate api worker beat web
```

### 6. Vérifications post-déploiement

```bash
# Healthchecks
curl -k https://<domain>/livez
# → 200 {"status":"ok"}

curl -k https://<domain>/readyz
# → 200 {"status":"ready","components":{"database":"ok","redis":"ok"}}

# Migrations appliquées à la tête ?
docker compose exec api alembic current
# → doit correspondre au dernier fichier dans alembic/versions/

# Logs API : chercher les erreurs récentes
docker compose logs --since 2m api | grep -i error

# Worker Celery actif
docker compose logs --since 2m worker | tail -20
```

### 7. Smoke test fonctionnel

- Se connecter à l'UI `https://<domain>/login` avec un compte existant.
- Vérifier que le dashboard principal charge (`/`).
- Créer un événement de test via `POST /events` et vérifier qu'il
  apparaît en temps réel sur `/events`.
- Si IA utilisée : tester `/chat` avec un prompt simple.

## Prévention

- **Backups quotidiens automatiques** via cron (voir [DR.md](./DR.md)).
- **Tag git** à chaque version déployée : `git tag -a V4.9 -m "..."`
  avant le déploiement, push les tags.
- **Canary / staging** : déployer d'abord sur un environnement de
  staging (`.env` dédié, domaine séparé) avant la prod.
- **Monitoring** : garder `make monitoring-up` actif en prod, alertes
  Prometheus sur `up{job="api"} == 0` et `pg_up == 0`.
- **Rollback plan** : si le nouveau build casse en post-déploiement,
  `git checkout <tag précédent>` puis reprendre depuis l'étape 4.
  Si la DB a été migrée et qu'il faut vraiment revenir en arrière,
  voir [db-migration.md](./db-migration.md).

## Rollback rapide

```bash
# Revenir au commit précédent
git checkout <tag-précédent>

# Rebuild
docker compose -f docker-compose.yml \
               -f docker-compose.secrets.yml \
               -f docker-compose.tls.yml \
               up -d --force-recreate --build api worker beat web

# Si migration incompatible, restaurer le dump pris en étape 1
make restore F=./backups/cyberdef-<host>-<ts>.dump
docker compose exec api alembic upgrade head
```
