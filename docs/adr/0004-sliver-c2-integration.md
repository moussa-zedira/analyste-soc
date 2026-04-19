# ADR-0004 : Intégration Sliver comme C2 Red Team

## Status
Accepté (V4.3, enrichi en V4.4 Operator Console + V4.5 pivot BloodHound).

## Contexte

La plateforme doit couvrir des engagements Red Team complets, ce qui
implique un Command & Control pour gérer les implants sur les postes
compromis. Sans C2 intégré, l'opérateur doit jongler entre la plateforme
(findings, rapports, scope) et un outil externe — mauvaise expérience
et cassure du log d'audit unifié.

Options sérieuses considérées :

| Outil           | Licence           | Raison écartée / retenue                              |
|-----------------|-------------------|-------------------------------------------------------|
| Cobalt Strike   | Commercial $$$$$  | Licence Fortra, ~5 000 USD/an, trop lourd pour un indé. Blocage commercial chez certains clients. |
| Metasploit/Meterpreter | Open source | Signatures AV/EDR trop connues, pas de design moderne beacon-oriented, API pro limitée. |
| Empire / Starkiller | Open source   | Projet abandonné officiellement, forks incertains, Python legacy. |
| Mythic          | Open source (BSD) | Excellent produit, mais architecture Docker lourde (12+ conteneurs), courbe d'apprentissage des Payloads, pas d'API gRPC stable pour un embed tiers. |
| **Sliver**      | Open source (GPLv3) | **Retenu** — voir décision.                          |
| Havoc           | Open source       | Récent, communauté prometteuse mais API Teamserver non stabilisée, moins d'implant templates. |

Contraintes supplémentaires :

- Besoin d'une API programmable pour générer les implants à la volée
  par engagement (pas manuellement comme dans Metasploit).
- Besoin d'un mode beacon discret + mode session interactif.
- Les clients exigent de plus en plus une trace d'audit **signée** de
  chaque commande opérateur.

## Décision

**Sliver est le C2 officiel de la plateforme.**

### Intégration technique

- **Sliver daemon** tourne sur l'hôte ou dans un container Docker avec
  le profil `redteam` (`docker compose --profile redteam up -d sliver`).
- **Client gRPC** officiel (lib Go reportée en Python via un wrapper
  maison dans `apps/api/pentest/c2_sliver/client.py`).
- **Config opérateur** (`operator.cfg`) stockée dans le volume Docker
  `sliver_configs`, référencée par `SLIVER_OPERATOR_CFG`.
- **Port gRPC** : `31337` (par défaut Sliver).

### Poller asynchrone

Au démarrage de l'API (lifespan hook), un task asyncio
(`apps/api/pentest/c2_sliver/poller.py`) interroge Sliver périodiquement :

- Récupère la liste des beacons/sessions actifs.
- Publie les nouveautés dans Redis pub/sub (`redteam:events`).
- Un deuxième task (`notifier.py`) écoute ce canal et broadcast via
  WebSocket `/c2/ws/operator` vers la console frontend.

Ce design permet à plusieurs opérateurs sur le même dashboard de voir
le même état de flotte en temps réel.

### Audit signé

Toute action opérateur (envoi de commande, génération d'implant, tâche
planifiée) produit une entrée `pentest_audit_log` (migration 008) avec
une signature HMAC-SHA256 utilisant `AUDIT_SIGNING_KEY`. Sans cette clé,
l'API démarre quand même mais logue une erreur — les entrées utilisent
une clé fallback déterministe sans valeur cryptographique réelle, et
on refuse ce mode en prod (`settings.validate_for_prod`).

### Pivot BloodHound (V4.5)

Après un dump SharpHound importé, l'opérateur peut demander à l'assistant
IA de suggérer des cibles de pivot sur la base des chemins calculés.
Le lien est unidirectionnel (lecture seule sur le dataset) pour éviter
les allers-retours destructifs.

## Conséquences

**Positives :**

- Sliver a une API gRPC propre conçue pour être embarquée.
- Open source, pas de licence, pas de blocage commercial.
- Implants modernes : AES-GCM, HTTPS/DNS/mTLS, beacon + session, multi-OS.
- Communauté active (BishopFox), releases fréquentes.
- L'intégration se fait via un binaire unique + volume de config —
  déploiement simple.

**Négatives :**

- Sliver est écrit en Go ; on dépend du wrapper Python maison, qui doit
  suivre les changements d'API. Versioning du wrapper à coupler avec
  celui de Sliver (mention dans `requirements.txt`).
- gRPC ajoute une dépendance binaire (protobuf) à l'image API.
- Les implants générés par Sliver sont connus de la plupart des EDR
  modernes sans personnalisation. Les clients exigeant une réelle
  furtivité doivent construire un profile custom — non automatisé
  pour l'instant.
- Signatures AV : à chaque nouvelle vague EDR, refaire le tour des
  obfuscateurs (`apps/api/pentest/evasion/`).

**Ce qu'on pourrait reconsidérer plus tard :**

- Support **multi-C2** (Sliver + Mythic + Havoc en parallèle dans la
  même plateforme) : l'abstraction actuelle `c2_sliver` pourrait devenir
  `c2/<backend>/`. Pas de demande client encore.
- Migration vers un wrapper gRPC auto-généré depuis les .proto Sliver
  si le maintenance du wrapper manuel devient coûteuse.
