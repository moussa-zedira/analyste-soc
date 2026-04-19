# ADR-0002 : Authentification duale JWT + API key

## Status
Accepté (V1, durci en V3 avec révocation Redis).

## Contexte

La plateforme a deux classes de clients radicalement différentes :

1. **Opérateurs humains** qui utilisent le dashboard Next.js : login
   avec username/password, session de plusieurs heures, permissions
   liées à un rôle (analyst, lead, admin), bouton logout, rotation de
   mot de passe.
2. **Services automatisés** : le collector syslog, l'agent simulateur,
   les intégrations sortantes (Jira, Slack, webhooks), les scripts
   CI/CD. Ils font du trafic machine-to-machine 24/7, ne peuvent pas
   gérer un flow OAuth, et doivent survivre à un redéploiement du
   dashboard sans reconnexion.

Un seul mécanisme d'auth ne couvre pas les deux proprement :

- **JWT seul** : les services devraient gérer l'expiration, le refresh,
  stocker un mot de passe de service quelque part. Fragile.
- **API key seule** : pas de notion d'utilisateur, pas de RBAC
  granulaire, pas de logout, pas de révocation côté client.
- **mTLS** : lourd à déployer pour du solo dev, nécessite une PKI.
- **OAuth 2.0 full** : over-engineering pour le scope actuel, et le
  SSO SAML/OIDC est déjà géré en parallèle (V4.2).

## Décision

**Deux mécanismes coexistent, acceptés côté API via la même dépendance
`require_api_key` (`apps/api/security.py`) :**

### 1. JWT Bearer — pour les humains

- Flow : `POST /auth/login` → `{access_token, refresh_token}`.
- Access token court : 15 min par défaut (`JWT_EXPIRE_MINUTES`).
- Refresh token long : 7 jours, rotation à chaque usage.
- Chaque token porte un `jti` (UUID hex).
- **Révocation** : `jti` pushé dans Redis avec TTL aligné sur `exp`.
  Le middleware teste la présence dans la liste de révocation à chaque
  requête. Pas de table SQL dédiée.
- RBAC : le claim `role` est comparé à la hiérarchie
  `analyst < lead < admin` via `require_roles("admin")`.

### 2. X-API-Key — pour les services

- Une clé unique (`API_KEY`) partagée, configurée via env/secret.
- Header `X-API-Key` (renommable via `API_KEY_HEADER`).
- Comparaison **`hmac.compare_digest`** (temps constant, évite les
  attaques de timing).
- Traitée comme **admin** pour simplifier l'automatisation. Un endpoint
  qui veut strictement un utilisateur humain doit utiliser
  `require_roles_strict(..., api_key_allowed=False)`.

### Ordre de résolution dans le middleware

```python
if check_api_key(request):  # accès service-à-service
    return
if extract_jwt_payload(request):  # accès humain
    return
raise HTTPException(401)
```

## Conséquences

**Positives :**

- Les services n'ont pas à gérer de refresh — une clé dans la config,
  et c'est tout.
- Les humains bénéficient d'une session courte avec révocation
  immédiate au logout.
- Séparation claire des surfaces d'attaque : compromission d'un token
  utilisateur = 15 min d'impact, d'une API key = tout.
- La compatibilité avec SSO (SAML/OIDC via `apps/api/sso/`) reste
  possible — le flow SSO émet le JWT final comme le login password.

**Négatives :**

- Deux chemins de code à maintenir et deux surfaces à auditer.
- Une API key unique est un SPOF : rotation = redéploiement de tous les
  services qui l'utilisent. Atténué par `make secrets-init` +
  `docker compose up -d --force-recreate`.
- Pas de scopes par API key (une seule clé = accès total). Si le besoin
  apparaît, migrer vers des API keys par service avec scopes est
  additif, pas destructif.

**Effets de bord à surveiller :**

- La liste de révocation Redis peut grossir — le TTL auto-nettoie,
  mais en cas de clear Redis, tous les JWT redeviennent valides jusqu'à
  leur expiration naturelle. Acceptable pour access token (15 min),
  plus gênant pour refresh token (7j). Monitoring sur la clé
  `auth:revoked:*`.
