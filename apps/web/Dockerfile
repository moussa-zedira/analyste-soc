FROM node:20-alpine AS builder

WORKDIR /app

COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci

COPY apps/web/ .

# Next.js bakes NEXT_PUBLIC_* at build time. NEVER include API_KEY here.
ARG NEXT_PUBLIC_API_BASE_URL=http://api:8000
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL

RUN npm run build

# ── Production ────────────────────────────────────────────
FROM node:20-alpine

WORKDIR /app

COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

# Public base URL is exposed to the browser; safe to bake.
ENV NEXT_PUBLIC_API_BASE_URL=http://api:8000
# INTERNAL_API_KEY must be supplied at runtime via docker-compose .env (server-only).
# It is consumed by the /api/proxy route handler and never sent to the browser.
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
EXPOSE 3000

CMD ["node", "server.js"]
