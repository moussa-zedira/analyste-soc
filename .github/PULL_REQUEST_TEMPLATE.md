## Resume

<!-- 1-3 lignes : qu'est-ce qui change et pourquoi. -->

## Type de changement

- [ ] Bug fix (changement non-cassant qui corrige un probleme)
- [ ] Nouvelle fonctionnalite (changement non-cassant qui ajoute une feature)
- [ ] Breaking change (modifie le contrat existant)
- [ ] Refactor / nettoyage (pas de changement de comportement)
- [ ] Documentation
- [ ] CI / outillage

## Verifications

- [ ] `make lint` passe localement
- [ ] `make test-api` passe (tests unitaires)
- [ ] Si modif schema DB : migration Alembic creee + testee (`make migrate`)
- [ ] Si modif securite (auth, RBAC, audit) : revue manuelle des chemins de secours
- [ ] `.env.example` mis a jour si nouvelles variables d'environnement
- [ ] Pas de secret en clair dans le diff (TruffleHog devrait bloquer sinon)

## Plan de test

<!-- Comment verifier que ce PR fait bien ce qu'il pretend ? -->
