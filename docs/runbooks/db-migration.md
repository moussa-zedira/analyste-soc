# Runbook : migrations Alembic — exécution, suivi, rollback

## Symptôme

Trois situations distinctes pour ce runbook :

1. **Nominal** : appliquer une nouvelle migration après un `git pull`.
2. **Incident au boot** : l'API refuse de démarrer avec une erreur
   Alembic (log `database_migrated` absent, fallback `create_all` ou
   crash).
3. **Rollback** : une migration récente a corrompu ou rendu illisibles
   des données, il faut revenir à l'état précédent.

## Diagnostic

### 1. État actuel de la base

```bash
docker compose exec api alembic current
# → ex : 022_chat_messages (head)
```

Comparer avec la dernière migration disponible dans le code :

```bash
ls alembic/versions/ | tail -5
# → doit finir par le même identifiant
```

Si le `alembic current` est antérieur au dernier fichier, il faut
appliquer les migrations en attente.

### 2. Historique

```bash
docker compose exec api alembic history --verbose | head -40
```

Permet de voir la chaîne `down_revision → revision` et d'identifier à
quel point revenir en cas de rollback.

### 3. Logs API au démarrage

```bash
docker compose logs api | grep -E "alembic|database_migrated|database_initialised"
```

- `database_migrated method=alembic` : tout est OK, migrations appliquées.
- `database_initialised method=create_all` : **fallback** ! Alembic a
  échoué, `Base.metadata.create_all` a été exécuté. Les tables sont
  créées mais pas les index / triggers spécifiques — à ne JAMAIS laisser
  en prod. Investiguer l'échec Alembic.

## Résolution

### Cas 1 — Appliquer les migrations en attente (nominal)

Les migrations sont appliquées **automatiquement au boot** de l'API.
Un simple redémarrage suffit dans le flow normal :

```bash
docker compose up -d --force-recreate api
```

Pour forcer manuellement (utile en déploiement avec beaucoup de
workers, où on veut migrer avant de rouler le reste) :

```bash
docker compose exec api alembic upgrade head
```

Vérifier :

```bash
docker compose exec api alembic current
```

### Cas 2 — Créer une nouvelle migration

Après modification des modèles SQLAlchemy :

```bash
# Génération autogen
docker compose exec api alembic revision --autogenerate -m "description courte"

# OU en local
make migrate-create M="description courte"
```

**Toujours relire le fichier généré** dans `alembic/versions/` avant
commit. Autogenerate rate fréquemment :

- Les renommages de colonnes (interprétés comme drop + add).
- Les contraintes CHECK complexes.
- Les types custom (JSONB, arrays).
- Les index partiels.

Compléter manuellement ces cas. Tester upgrade **et** downgrade en local :

```bash
alembic upgrade head
alembic downgrade -1
alembic upgrade head
```

### Cas 3 — Boot échoue sur une migration

Lire le traceback dans les logs API :

```bash
docker compose logs --tail=200 api | grep -A 30 "alembic\|Traceback"
```

Causes fréquentes :

| Erreur                                                  | Action                                                       |
|---------------------------------------------------------|--------------------------------------------------------------|
| `DuplicateTable` / `relation already exists`            | Migration déjà appliquée mais non inscrite dans `alembic_version`. Stamp manuel, voir §a. |
| `DependentObjectsStillExist` / `cannot drop`            | Objet dépendant hors schéma (vue, trigger externe). Drop manuel puis upgrade. |
| `UndefinedColumn` dans un `ALTER`                       | Migration prend pour acquise une colonne absente. Corriger le fichier ou stamp vers la bonne revision. |
| `sqlalchemy.exc.OperationalError: connection refused`   | Postgres pas prêt. Laisser le healthcheck faire son job, ou forcer `restart` Postgres. |
| `AlembicMultipleHeads`                                  | Deux branches coexistent. `alembic merge -m "merge" <rev1> <rev2>`. |

#### §a. Stamp manuel (reprise après fix hors bande)

Si la DB est déjà à l'état voulu mais `alembic_version` est désynchro :

```bash
docker compose exec api alembic stamp <revision-cible>
# ex : alembic stamp 022_chat_messages
```

À n'utiliser qu'en connaissance de cause — `stamp` **ne modifie pas**
le schéma, juste le marqueur.

### Cas 4 — Rollback (la nouvelle migration a cassé des données)

⚠ **Rollback = perte potentielle de données** produites depuis
l'application. Toujours faire un backup préalable.

#### Étape 1 : backup immédiat

```bash
make backup
# → ./backups/cyberdef-<host>-<ts>-pre-rollback.dump
```

#### Étape 2 : déterminer la revision cible

```bash
docker compose exec api alembic history | head -10
```

Exemple : si on est à `022_chat_messages` et qu'on veut revenir à
`021_credential_vault` :

```bash
docker compose exec api alembic downgrade 021_credential_vault
```

Ou revenir d'une seule marche :

```bash
docker compose exec api alembic downgrade -1
```

#### Étape 3 : redéployer la version de code cohérente

Le code source contient probablement les modèles SQLAlchemy qui
réclament le schéma `022`. Il faut revenir à un commit antérieur :

```bash
git log --oneline -- alembic/versions/022_chat_messages.py
# identifier le commit qui l'a introduit
git checkout <commit-précédent>

# Rebuild et relance
docker compose up -d --force-recreate --build api worker beat
```

#### Étape 4 : vérifier

```bash
docker compose exec api alembic current
# → doit afficher la revision cible (ex: 021_credential_vault)
curl https://<domain>/readyz
```

#### Rollback impossible (downgrade() non implémenté)

Certaines migrations n'ont pas de `downgrade()` écrit (il est laissé
vide ou `pass`). Dans ce cas :

1. Restaurer depuis le backup (voir [DR.md §3](./DR.md#3-restauration-apres-incident)) :

   ```bash
   docker compose stop api worker beat
   make restore F=./backups/<backup-avant-migration>.dump
   docker compose start api worker beat
   ```

2. Puis revenir à la version de code cohérente comme en étape 3.

## Prévention

- **Toujours écrire `downgrade()`** pour les tables critiques.
  `pass` est acceptable pour les migrations de seed statique (données
  de référence), jamais pour un `create_table` ou `alter`.
- **Tester upgrade + downgrade en local** avant commit :
  ```bash
  alembic upgrade head
  alembic downgrade -1
  alembic upgrade head
  ```
- **Backup avant déploiement** : voir [deploy.md §1](./deploy.md#1-backup-préventif).
  Non négociable si une migration est incluse.
- **Revue des migrations autogen** : c'est souvent incorrect sur les
  cas non triviaux (renommage, types custom, triggers). Relire à
  chaque fois.
- **Migrations non bloquantes** : pour les grosses tables, éviter les
  `ALTER TABLE` qui prennent un lock exclusif long. Préférer les
  `ADD COLUMN ... DEFAULT NULL` + backfill asynchrone + contrainte
  `NOT NULL` dans une migration ultérieure.
- **Branches Alembic** : si deux devs écrivent en parallèle, merge
  avec `alembic merge` dès la review PR — ne pas laisser traîner.
