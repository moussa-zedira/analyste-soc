# Runbook — Disaster Recovery & Hardening Prod

Procedure courte pour deployer la stack en mode prod (secrets, TLS, backups) et
restaurer apres incident.

## 1. Premier deploiement (machine vide)

```bash
# 1. Cloner et configurer
git clone <repo> && cd analyste-soc
cp .env.example .env
# Editer .env : ENV=prod, DATABASE_URL avec mot de passe fort, etc.

# 2. Generer les secrets locaux (./secrets/*.txt, mode 600, hors git)
make secrets-init

# 3. Generer les certificats TLS (self-signed pour staging — Let's Encrypt en vrai prod)
make tls-certs

# 4. Lancer la stack durcie : base + secrets overlay + TLS overlay
make prod-up

# 5. Verifier
curl -k https://localhost/livez       # 200 = process up
curl -k https://localhost/readyz      # 200 = DB+Redis OK
docker compose ps                     # tous les services healthy
```

Le bootstrap admin est genere une seule fois dans les logs API au demarrage :
`docker compose logs api | grep default_admin_created` — change le mot de passe immediatement.

## 2. Backup quotidien

Cron suggere (UTC) :

```cron
0 2 * * * cd /opt/analyste-soc && make backup >> /var/log/cyberdef-backup.log 2>&1
```

Manuellement :

```bash
make backup        # ecrit ./backups/cyberdef-<host>-<ts>.dump
make backup-list   # liste ce qui existe
```

Retention par defaut : 14 jours (variable `RETENTION_DAYS`).
**Off-site** : `rclone copy backups/ s3:cyberdef-backups/` ou rsync vers un host distant.

## 3. Restauration apres incident

```bash
# 1. Stopper l'API + worker pour eviter les ecritures concurrentes
docker compose stop api worker beat

# 2. Identifier le dump cible
make backup-list

# 3. Restaurer (drop + recreate du schema public)
make restore F=./backups/cyberdef-node1-20260417T020000Z.dump

# 4. Re-jouer les migrations si besoin (au cas ou le schema a evolue depuis le dump)
docker compose exec api alembic upgrade head

# 5. Repartir
docker compose start api worker beat
curl -k https://localhost/readyz   # doit repondre 200
```

## 4. Rotation secret

JWT_SECRET_KEY ou API_KEY compromis :

```bash
# 1. Re-generer le fichier secret
rm secrets/jwt_secret.txt
make secrets-init   # regenere uniquement les manquants

# 2. Recharger les containers qui en dependent
docker compose -f docker-compose.yml -f docker-compose.secrets.yml \
    up -d --force-recreate api worker beat
```

Effet de bord : tous les JWT existants deviennent invalides (logout force).
Idem si tu rotes API_KEY — recharge aussi `web` et `syslog`.

## 5. Verifications periodiques

| Cadence       | Check                                                                  |
|---------------|------------------------------------------------------------------------|
| Quotidien     | `make backup` reussit (cron) + dump > 0 octets                         |
| Hebdomadaire  | `pg_restore --list <dump>` valide la structure du dernier dump         |
| Mensuel       | **Drill** : restauration sur un environnement vierge, verif `/readyz`  |
| Trimestriel   | Rotation `JWT_SECRET_KEY` + revue des comptes admin (`/admin/users`)   |
| Annuel        | Renouvellement du certificat TLS                                       |

## 6. Limites connues

- Les certs `make tls-certs` sont self-signed : navigateurs afficheront un warning. Pour la prod : Let's Encrypt via certbot ou ta CA interne.
- Les backups sont des dumps logiques (pg_dump -Fc), pas du PITR. RTO ~minutes, RPO = derniere snapshot. Pour du PITR vrai, ajouter `wal-g` ou `pgBackRest`.
- L'overlay TLS suppose nginx co-localise avec api/web. En architecture multi-host, replacer par un LB managed (AWS ALB, GCP HTTPS LB, Cloudflare).
