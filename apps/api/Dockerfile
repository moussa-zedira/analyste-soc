# syntax=docker/dockerfile:1.7
# =====================================================================
# Multi-stage Dockerfile — hardening CIS Docker Benchmark + slim build
# - Stage "builder" : compile Python wheels avec gcc/libpq-dev
# - Stage "runtime" : image finale minimale, user non-root "appuser"
#
# Optim V4.7b (size) :
#   - torch CPU-only (PyTorch wheel index CPU) → -1.5/-2 GB vs CUDA par défaut
#   - pip --no-compile + strip __pycache__ runtime → -150/-300 MB
#   - Playwright: chromium only, pas firefox/webkit (cible déjà par défaut)
#   - Layers "stables" (apt, pip, binaires pentest, playwright) AVANT
#     le COPY apps/ → cache docker beaucoup plus chaud sur rebuild code.
# =====================================================================

# ── Stage 1 : builder (compile wheels only) ─────────────────────────
FROM python:3.14-slim AS builder

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
# torch forcé CPU-only via l'index PyTorch dédié (sinon CUDA ~2 GB).
RUN pip wheel --wheel-dir /wheels \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        -r requirements.txt \
    && pip wheel --wheel-dir /wheels \
        "semgrep>=1.50" \
        "bandit[toml]>=1.7" \
        "safety>=3.0" \
        "checkov>=3.2"


# ── Stage 2 : runtime (image finale, non-root) ──────────────────────
FROM python:3.14-slim AS runtime

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
    && rm -rf /var/lib/apt/lists/* \
    && find /var/log -type f -delete

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
# builder (psycopg2, scipy...). PyPI + index CPU PyTorch restent actifs
# pour resolver les deps transitives manquantes.
# --no-compile : pas de .pyc generes a l'install (recomputes au 1er run, en /tmp).
COPY --from=builder /wheels /wheels
COPY apps/api/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --no-compile --find-links=/wheels \
        --extra-index-url https://download.pytorch.org/whl/cpu \
        -r /tmp/requirements.txt \
    && pip install --no-cache-dir --no-compile --find-links=/wheels \
        "semgrep>=1.50" \
        "bandit[toml]>=1.7" \
        "safety>=3.0" \
        "checkov>=3.2" \
    && rm -rf /wheels /tmp/requirements.txt \
    # Strip __pycache__ eventuels (cas de libs qui compilent a l'install).
    && find /usr/local/lib/python3.13 -type d -name __pycache__ -prune -exec rm -rf {} + \
    && find /usr/local/lib/python3.13 -type f -name "*.pyc" -delete \
    # Strip tests/docs des libs lourdes (torch, scipy, sklearn...) : ~50-100 MB.
    && find /usr/local/lib/python3.13 -type d -name tests -prune -exec rm -rf {} + 2>/dev/null || true \
    && find /usr/local/lib/python3.13 -type d -name test -prune -exec rm -rf {} + 2>/dev/null || true

# ── Non-root user ───────────────────────────────────────────────────
# UID/GID 1000 pour compatibilité bind-mounts dev.
RUN groupadd --system --gid 1000 appuser \
    && useradd  --system --uid 1000 --gid appuser \
        --home-dir /home/appuser --create-home \
        --shell /usr/sbin/nologin appuser

# Playwright doit être installé comme appuser pour que les binaires Chromium
# atterrissent dans /data/playwright (accessible par appuser).
RUN mkdir -p /app /data/geoip /data/models /data/rag \
             /data/sliver/configs /data/sliver/builds \
             /data/playwright /app/data \
    && chown -R appuser:appuser /app /data

WORKDIR /app
USER appuser

# Playwright Chromium installé sous appuser (évite les perm denied au runtime).
# "chromium" uniquement (pas firefox/webkit → -300 MB). On nettoie aussi
# le cache de download (.cache/ms-playwright/.links → kept, tmp → flush).
RUN python -m playwright install chromium \
    && rm -rf /home/appuser/.cache/ms-playwright/.tmp* 2>/dev/null || true

# ── Code applicatif (layer final — change souvent) ──────────────────
# Place en dernier pour que le cache Docker reste chaud sur les layers
# lourds (pip install, playwright, binaires pentest) lors des rebuilds
# quand seul le code Python change.
USER root
COPY --chown=appuser:appuser apps/ apps/
COPY --chown=appuser:appuser alembic.ini alembic.ini
COPY --chown=appuser:appuser alembic/ alembic/
USER appuser

EXPOSE 8000
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-date-header"]
