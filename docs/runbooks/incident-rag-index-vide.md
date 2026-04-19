# Runbook : RAG renvoie 0 résultat / index vide

## Symptôme

Un ou plusieurs des signaux suivants :

- Assistant chat réponde systématiquement "Aucun contexte disponible"
  ou produit des réponses non-étayées.
- Appel `POST /ai/rag/query` renvoie `{"results": []}` même pour des
  requêtes basiques ("MITRE T1003").
- Dashboard `/admin/ai` affiche un compteur de documents indexés à 0
  ou très faible (< 1 000).
- Module triage IA dégrade en stub pour les incidents non-triviaux.

L'index attendu contient **~11 000+ documents** issus de :

- MITRE ATT&CK (techniques, tactiques).
- NVD / CVE (base locale).
- SigmaHQ rules (packs synchronisés via `/sigma/sync`).

## Diagnostic

### 1. Vérifier le statut RAG

```bash
curl -H "X-API-Key: $API_KEY" \
     http://localhost:8000/ai/rag/status
```

Réponse attendue sur un index sain :

```json
{
  "indexed_documents": 11234,
  "index_size_bytes": 47382912,
  "last_build_at": "2026-04-15T03:21:14Z",
  "embedding_model": "sentence-transformers/all-MiniLM-L6-v2"
}
```

Cas anormaux :

| Réponse                        | Cause                                       |
|--------------------------------|---------------------------------------------|
| `indexed_documents: 0`         | Index jamais construit ou réinitialisé.     |
| `indexed_documents < 1000`     | Construction partielle — source manquante.  |
| `last_build_at` très ancien    | Nouvelles sources (CVE récents) absentes.   |
| 404 / 500 sur `/ai/rag/status` | Module IA KO — voir logs.                   |

### 2. Vérifier le volume Docker

L'index FAISS est persisté dans le volume `rag_data` monté sur
`/data/rag` dans les containers `api` et `worker`.

```bash
docker compose exec api ls -lh /data/rag/
```

Fichiers attendus :

- `index.faiss` (plusieurs Mo, binaire)
- `metadata.jsonl` (un JSON par doc)
- `version.txt`

Si le dossier est vide ou partiel → voir §Résolution cas A.

### 3. Vérifier les sources

Les sources doivent être présentes en base avant de lancer un rebuild :

```bash
# CVE
curl -s -H "X-API-Key: $API_KEY" \
     http://localhost:8000/threat-intel/cve/stats
# → doit indiquer des milliers de CVE

# SIGMA rules
curl -s -H "X-API-Key: $API_KEY" \
     http://localhost:8000/sigma/stats
# → doit indiquer les règles importées
```

Si les sources sont vides, rebuild préalablement :

```bash
# Sync SIGMA depuis SigmaHQ
curl -X POST -H "X-API-Key: $API_KEY" \
     http://localhost:8000/sigma/sync
```

## Résolution

### Cas A — Rebuild complet de l'index

```bash
curl -X POST -H "X-API-Key: $API_KEY" \
     http://localhost:8000/ai/rag/rebuild
```

La construction tourne en tâche de fond (Celery). Durée indicative :
**3 à 6 minutes** selon la machine, pour ~11 000 docs.

Suivre l'avancement :

```bash
# Logs worker
docker compose logs -f --tail=50 worker | grep -i rag

# Status API
watch -n 10 'curl -s -H "X-API-Key: $API_KEY" http://localhost:8000/ai/rag/status | jq'
```

Une fois `indexed_documents` stable et > 10 000, tester :

```bash
curl -X POST -H "X-API-Key: $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"query": "credential dumping lsass", "top_k": 5}' \
     http://localhost:8000/ai/rag/query
# → doit retourner 5 docs pertinents (T1003 et familiers)
```

### Cas B — Volume Docker corrompu

Si un rebuild échoue systématiquement (fichiers partiels, I/O errors),
purger le volume :

```bash
# Stopper les consommateurs
docker compose stop api worker

# Vider le volume
docker compose exec -T api sh -c "rm -rf /data/rag/*"
# OU : docker volume rm analyste-soc_rag_data && recréer

# Redémarrer
docker compose up -d api worker

# Relancer le rebuild
curl -X POST -H "X-API-Key: $API_KEY" \
     http://localhost:8000/ai/rag/rebuild
```

### Cas C — Embedding model absent

Le modèle `all-MiniLM-L6-v2` est téléchargé depuis HuggingFace au
premier usage. Sans réseau sortant, la construction échoue.

```bash
docker compose logs worker | grep -i "sentence-transformers\|huggingface"
# Chercher : "HTTPSConnectionPool", "OSError", "404"
```

Solution : exposer un proxy HuggingFace ou pré-télécharger le modèle
et monter le cache.

### Cas D — Sources manquantes

Si `indexed_documents` reste faible après rebuild (ex : 500 docs) :

1. Vérifier que les sources sont peuplées (§Diagnostic 3).
2. Chaque source absente = ~plusieurs milliers de docs manquants.
3. Lancer les imports manquants puis rebuild :

```bash
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/sigma/sync
# Attendre fin
curl -X POST -H "X-API-Key: $API_KEY" http://localhost:8000/ai/rag/rebuild
```

## Prévention

- **Rebuild planifié** : ajouter une tâche Celery Beat hebdomadaire qui
  rafraîchit l'index (ajouts CVE, nouvelles règles SIGMA).
  À configurer dans `apps/api/celery_app.py` si pas déjà présent.
- **Monitoring** : exposer `indexed_documents` en métrique Prometheus,
  alerter si la valeur chute soudainement (ex : < 80 % du max observé).
- **Volume nommé persistant** : `rag_data` est déjà un named volume
  dans `docker-compose.yml`, il survit aux `docker compose down`.
  Ne pas faire `docker compose down -v` en prod — cela supprime tous
  les volumes y compris `rag_data`.
- **Backup du volume** : si la construction prend du temps et que la
  stack tourne sur un environnement contraint (pas de réseau sortant),
  sauvegarder `rag_data` dans les backups :
  ```bash
  docker run --rm -v analyste-soc_rag_data:/data \
             -v $(pwd)/backups:/backup \
             alpine tar czf /backup/rag-$(date +%F).tar.gz -C /data .
  ```
