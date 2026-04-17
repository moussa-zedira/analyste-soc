FROM python:3.13-slim

WORKDIR /app

# System deps for psycopg2, Playwright, network tools, and DevSecOps binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    # Playwright browser deps
    libnss3 libnspr4 libdbus-1-3 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libatspi2.0-0 libxcomposite1 \
    libxdamage1 libxfixes3 libxrandr2 libgbm1 libpango-1.0-0 \
    libcairo2 libasound2 libwayland-client0 \
    # Network tools for pentest modules (arp, nmap-like)
    net-tools iproute2 dnsutils \
    # DevSecOps tooling deps (curl, git for trivy/gitleaks installers and git history scans)
    curl ca-certificates git tar \
    && rm -rf /var/lib/apt/lists/*

# ── DevSecOps native binaries ─────────────────────────────────────────────
# Trivy (filesystem + container image vulnerability scanner)
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin \
    && trivy --version

# Gitleaks (secret detection)
RUN curl -sSL -o /tmp/gitleaks.tar.gz \
        https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks \
    && rm /tmp/gitleaks.tar.gz \
    && chmod +x /usr/local/bin/gitleaks \
    && gitleaks version

# Hadolint (Dockerfile linter — optional)
RUN curl -sSL -o /usr/local/bin/hadolint \
        https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Linux-x86_64 \
    && chmod +x /usr/local/bin/hadolint \
    && hadolint --version || true
# ──────────────────────────────────────────────────────────────────────────

COPY apps/api/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# DevSecOps Python-based scanners (Semgrep, Bandit, Safety, Checkov)
RUN pip install --no-cache-dir \
        "semgrep>=1.50" \
        "bandit[toml]>=1.7" \
        "safety>=3.0" \
        "checkov>=3.2" \
    && semgrep --version \
    && bandit --version \
    && safety --version \
    && checkov --version

# Install Playwright Chromium browser
RUN python -m playwright install chromium

COPY apps/ apps/
COPY alembic.ini alembic.ini
COPY alembic/ alembic/

RUN mkdir -p /app/data /data/geoip /data/models /data/rag

EXPOSE 8000
CMD ["uvicorn", "apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
