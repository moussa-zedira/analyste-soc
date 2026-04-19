# Architecture Decision Records (ADR)

Ce dossier contient les décisions d'architecture structurantes du projet.
Un ADR documente **pourquoi** un choix a été fait, pas **comment** le
code fonctionne (ça, c'est dans [`../ARCHITECTURE.md`](../ARCHITECTURE.md)).

## Pourquoi écrire des ADRs

- Garder la mémoire des compromis faits quand on revisite une décision
  six mois plus tard.
- Éviter de refaire les mêmes débats en boucle.
- Donner aux nouveaux arrivants le contexte nécessaire pour comprendre
  l'état actuel sans interroger dix personnes.
- Distinguer les contraintes réelles (budget, compétences équipe,
  dépendances) des préférences personnelles.

## Quand écrire un ADR

Écrire un ADR quand la décision :

- Engage le projet sur un élément difficilement réversible (choix de
  base de données, framework web, langage principal).
- Touche un contrat d'interface (auth, API publique, format d'événement).
- Introduit une nouvelle dépendance majeure (un outil externe comme
  Sliver, GoPhish, Ollama).
- Crée une règle transverse que plusieurs modules devront respecter.

Ne **pas** écrire d'ADR pour :

- Le nommage d'une variable.
- Le choix d'un algorithme interne à un module.
- Les micro-refactos.

## Format

Chaque ADR utilise ce canevas minimal :

```markdown
# ADR-NNNN : Titre court de la décision

## Status
Proposé | Accepté | Déprécié | Remplacé par ADR-XXXX

## Contexte
Quel problème on résout, quelles contraintes, quelles alternatives
étaient sur la table.

## Décision
Ce qu'on a choisi. Une phrase claire, puis les détails.

## Conséquences
- Positives : ce qu'on gagne.
- Négatives : ce qu'on accepte de payer.
- Effets de bord : ce qu'il faudra surveiller.
```

## Numérotation et nommage

- Quatre chiffres, séquentiel : `0001`, `0002`, …
- Fichier : `NNNN-kebab-case-titre.md`.
- Le numéro n'est jamais réutilisé, même si un ADR est déprécié.

## Cycle de vie

1. **Proposé** : en discussion, pas encore appliqué dans le code.
2. **Accepté** : appliqué, référence active. C'est l'état des ADRs 0001–0005.
3. **Déprécié** : plus valide, mais conservé pour trace. Indiquer
   **par quoi il est remplacé** dans le champ `Status`.
4. **Remplacé par ADR-XXXX** : variante de déprécié quand un nouveau
   ADR prend la relève.

Ne jamais supprimer un ADR historique. On écrase un fichier seulement
pour corriger une typo — la décision, elle, reste.

## Index des ADRs

| Numéro | Titre | Status |
|--------|-------|--------|
| [0001](./0001-stack-choice.md) | Stack : FastAPI + Next.js + PostgreSQL | Accepté |
| [0002](./0002-auth-dual-jwt-apikey.md) | Authentification duale JWT + API key | Accepté |
| [0003](./0003-llm-multi-provider.md) | LLM multi-provider avec fallback cascade | Accepté |
| [0004](./0004-sliver-c2-integration.md) | Sliver C2 comme C2 Red Team | Accepté |
| [0005](./0005-split-pentest-routes.md) | Split du monolithe pentest.py | Accepté |
