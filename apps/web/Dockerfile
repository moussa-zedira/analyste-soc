# syntax=docker/dockerfile:1.7
# =====================================================================
# Next.js multi-stage build — hardening non-root
# =====================================================================
FROM node:25-alpine AS builder

WORKDIR /app

COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci

COPY apps/web/ .

# Next.js bakes NEXT_PUBLIC_* at build time. NEVER include API_KEY here.
ARG NEXT_PUBLIC_API_BASE_URL=http://api:8000
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL

RUN npm run build

# ── Production ────────────────────────────────────────────
FROM node:25-alpine AS runtime

# node:20-alpine fournit déjà un utilisateur "node" (UID 1000).
# On l'utilise pour appliquer le principe de moindre privilège.

WORKDIR /app

# Copie avec ownership explicite → éviter les warnings / perm denied.
COPY --from=builder --chown=node:node /app/.next/standalone ./
COPY --from=builder --chown=node:node /app/.next/static ./.next/static
COPY --from=builder --chown=node:node /app/public ./public

# Public base URL is exposed to the browser; safe to bake.
ENV NEXT_PUBLIC_API_BASE_URL=http://api:8000
# INTERNAL_API_KEY must be supplied at runtime via docker-compose .env (server-only).
# It is consumed by the /api/proxy route handler and never sent to the browser.
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
EXPOSE 3000

# Passage non-root.
USER node

# Healthcheck sur la racine Next.js (200 attendu).
HEALTHCHECK --interval=10s --timeout=5s --retries=5 --start-period=15s \
    CMD wget -qO- http://127.0.0.1:3000/ >/dev/null 2>&1 || exit 1

CMD ["node", "server.js"]
