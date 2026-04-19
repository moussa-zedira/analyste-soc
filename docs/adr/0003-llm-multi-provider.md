# ADR-0003 : LLM multi-provider avec fallback cascade

## Status
Accepté (V4.8, élargi en V4.9).

## Contexte

La plateforme utilise un LLM pour plusieurs usages :

- **Triage d'incidents** (classification severity + verdict).
- **Assistant chat contextuel** pour l'opérateur pentest.
- **Génération de règles SIGMA** à partir de descriptions en langage naturel.
- **RAG** (résumé de la réponse avec contexte MITRE / NVD / Sigma injecté).
- **Analyse de findings** (explication, remédiation, priorisation).

Contraintes qui orientent la décision :

- **Budget imprévisible** : un client peut refuser qu'on envoie ses
  données à Anthropic ou OpenAI. Il faut une option 100 % locale.
- **Disponibilité** : un incident de production d'Anthropic (comme en
  2025) ne doit pas figer l'ensemble de la plateforme.
- **Qualité différenciée** : les tâches de raisonnement complexe
  (génération SIGMA, analyse de chain d'attaque) gagnent à tourner sur
  un modèle frontier ; un résumé de log peut tourner sur un petit
  modèle local.
- **Pas de vendor lock-in** : on doit pouvoir passer de Claude à GPT
  ou à Llama sans réécrire les modules appelants.

Options considérées :

1. **Single-provider (Anthropic seul)** : simple mais fragile.
2. **Router custom par tâche** : trop de code pour le bénéfice initial.
3. **Gateway externe (LiteLLM, OpenRouter)** : dépendance supplémentaire
   à opérer, latence, coût d'abstraction.
4. **Multi-provider intégré avec fallback** : retenu.

## Décision

**Un unique client `apps/api/ai/llm_client.py` expose `await call(prompt, ...)`
et gère la cascade fallback automatiquement.**

### Ordre de priorité par défaut

1. **Anthropic Claude** (`claude-sonnet-4-5` par défaut) si
   `ANTHROPIC_API_KEY` défini. **Primary** pour la qualité.
2. **OpenAI** (`gpt-4o-mini` par défaut) si `OPENAI_API_KEY` défini.
   Fallback qualité comparable.
3. **Ollama local** (`qwen2.5-coder:32b` ou variante configurée) si
   `OLLAMA_ENABLED=true` (défaut). Fallback gratuit et offline.
4. **Stub déterministe** (réponse JSON fixe, ne casse pas l'UI) en
   dernier recours — jamais surprise pour l'opérateur.

Le caller peut forcer un provider via `prefer="anthropic" | "openai" |
"ollama" | "stub"`.

### Retry et fallback

Pour chaque provider tenté :

- **3 tentatives** avec backoff exponentiel (1s, 2s, 4s).
- Respect du header `Retry-After` sur 429.
- Erreurs 429, 5xx, timeout → retry.
- Erreurs 4xx non-429 → échec immédiat, passage au fallback.

Si un provider épuise ses retries, on **passe automatiquement au
suivant** dans la liste, sans remonter l'erreur au caller.

### Cost tracking

Chaque appel insère une ligne dans `ai_cost_log` (migration 010) :
provider, modèle, opération, tokens_in, tokens_out, latency_ms, success.
Un compteur Redis journalier est maintenu pour le dashboard
`/admin/ai-costs`. Tarification stockée en dur dans `MODEL_PRICING`.

### Contexte injecté

L'assistant pentest (`apps/api/pentest/automation/ai_assistant.py`)
enrichit automatiquement le prompt avec :

- Engagement actif (scope, RoE, kill-switch).
- Sessions Sliver ouvertes.
- Credentials vault (noms seuls, jamais les secrets).
- Dernier dump BloodHound.
- Historique de la conversation (table `chat_messages`, migration 022).

## Conséquences

**Positives :**

- Zéro downtime IA si un provider tombe : on dégrade vers le suivant.
- Opérateur peut choisir un mode 100 % local pour les missions
  sensibles (`ANTHROPIC_API_KEY` et `OPENAI_API_KEY` vides → Ollama only).
- Comparaison qualité triviale : changer `prefer` dans un test et
  relancer.
- Coûts traçables par opération et par jour.

**Négatives :**

- Quatre providers à tester quand on modifie le client (bien que le
  code de cascade soit centralisé dans `call`).
- Ollama demande du VRAM/CPU local : sur une petite machine, latence de
  plusieurs secondes par appel. Inadapté pour du batch temps réel.
- Les prompts sont optimisés pour Claude par défaut ; certaines
  structures JSON ne sortent pas aussi proprement sur GPT-4o-mini ou
  un Qwen 7B. Atténué par `parse_json_response` qui tolère des
  variations et par du few-shot.

**À surveiller :**

- Quand un fournisseur sort un nouveau modèle, mettre à jour
  `MODEL_PRICING` sinon le coût est sous-estimé à 0.
- Si le stub est déclenché trop souvent, c'est le signe d'un problème
  config ou réseau. Compteur Redis dédié sur `ai:stub:count` à prévoir.
