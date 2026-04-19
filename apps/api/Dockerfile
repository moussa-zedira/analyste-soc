# syntax=docker/dockerfile:1.7
# =====================================================================
# Multi-stage Dockerfile — hardening CIS Docker Benchmark
# - Stage "builder" : compile Python wheels avec gcc/libpq-dev
# - Stage "runtime" : image finale minimale, user non-root "appuser"
# =====================================================================

# ── Stage 1 : builder (compile wheels only) ─────────────────────────
FROM python:3.13-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

# Build deps (gcc, libpq-dev) — uniquement pour compiler les wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY apps/api/requirements.txt requirements.txt

# Produit des wheels pré-compilées (copiées ensuite dans runtime).
RUN pip wheel --wheel-dir /wheels -r requirements.txt \
    && pip wheel --wheel-dir /wheels \
        "semgrep>=1.50" \
        "bandit[toml]>=1.7" \
        "safety>=3.0" \
        "checkov>=3.2"


# ── Stage 2 : runtime (image finale, non-root) ──────────────────────
FROM python:3.13-slim AS runtime

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/data/playwright

# Runtime deps uniquement : libpq5 (sans -dev), libs Playwright, outils réseau.
# gcc/build-essential/libpq-dev NE sont PAS installés ici → image finale allégée.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
        # Playwright browser deps
        libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
        libcups2 libdrm2 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
        libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
        libcairo2 libasound2 libwayland-client0 \
        # Network tools pour modules pentest
        net-tools iproute2 dnsutils \
        # curl/git/tar pour runtime (git-history scans, scripts)
        curl ca-certificates git tar \
    && rm -rf /var/lib/apt/lists/*

# ── DevSecOps native binaries (conservés en runtime) ────────────────
# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin \
    && trivy --version

# Gitleaks
RUN curl -sSL -o /tmp/gitleaks.tar.gz \
        https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && chmod +x /usr/local/bin/gitleaks \
    && gitleaks version

# Hadolint
RUN curl -sSL -o /usr/local/bin/hadolint \
        https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 \
    && chmod +x /usr/local/bin/hadolint \
    && hadolint --version || true

# ── Install Python deps from pre-built wheels (no gcc needed) ───────
# --find-links=/wheels permet de reutiliser les wheels compiles au stage
# builder (psycopg2, scipy...). PyPI reste actif pour resolver les deps
# transitives manquantes (pip wheel n'inclut pas toutes les variantes).
COPY --from=builder /wheels /wheels
COPY apps/api/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --find-links=/wheels \
        -r /tmp/requirements.txt \
    && pip install --no-cache-dir --find-links=/wheels \
        "semgrep>=1.50" \
        "bandit[toml]>=1.7" \
        "safety>=3.0" \
        "checkov>=3.2" \
    && rm -rf /wheels /tmp/requirements.txt

# ── Non-root user ───────────────────────────────────────────────────
# UID/GID 1000 pour compatibilité bind-mounts dev.
RUN groupadd --system --gid 1000 appuser \
    && useradd  --system --uid 1000 --gid appuser \
        --home-dir /home/appuser --create-home \
        --shell /usr/sbin/nologin appuser

WORKDIR /app

# Playwright doit être installé comme appuser pour que les binaires Chromium
# atterrissent dans /data/playwright (accessible par appuser).
RUN mkdir -p /app /data/geoip /data/models /data/rag \
             /data/sliver/configs /data/sliver/builds \
             /data/playwright /app/data \
    && chown -R appuser:appuser /app /data

# Copie du code applicatif (ownership appuser).
COPY --chown=appuser:appuser apps/ apps/
COPY --chown=appuser:appuser alembic.ini alembic.ini
COPY --chown=appuser:appuser alembic/ alembic/

USER appuser

# Playwright Chromium installé sous appuser (évite les perm denied au runtime).
RUN python -m playwright install chromium

EXPOSE 8000
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
