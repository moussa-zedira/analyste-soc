# ─────────────────────────────────────────────────────────────
# Cyber Defense / SOC platform — developer commands
# ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
.PHONY: help setup setup-api setup-web dev dev-api dev-web \
        lint lint-api lint-web format format-api format-web \
        typecheck test test-api test-integration docker-up docker-down docker-logs \
        monitoring-up monitoring-down monitoring-logs \
        migrate migrate-create secrets-gen secrets-init tls-certs \
        prod-up prod-down backup backup-list restore clean

PY ?= python
NPM ?= npm

# ── Help ─────────────────────────────────────────────────────
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ── Setup ────────────────────────────────────────────────────
setup: setup-api setup-web  ## Install backend + frontend + pre-commit
	pre-commit install || pip install pre-commit && pre-commit install

setup-api:  ## Install backend Python dependencies (runtime + dev/test)
	$(PY) -m pip install -r apps/api/requirements.txt
	$(PY) -m pip install -r apps/api/requirements-dev.txt

setup-web:  ## Install frontend Node dependencies
	cd apps/web && $(NPM) install

# ── Dev servers ──────────────────────────────────────────────
dev: docker-up  ## Bring up the full Docker stack
	@echo "API: http://localhost:8000  ·  Web: http://localhost:3000"

dev-api:  ## Run API locally with hot reload
	cd apps/api && $(PY) -m uvicorn main:app --reload --port 8000

dev-web:  ## Run frontend dev server
	cd apps/web && $(NPM) run dev

# ── Lint / Format / Types ────────────────────────────────────
lint: lint-api lint-web  ## Lint everything

lint-api:  ## Lint Python (ruff)
	ruff check apps alembic

lint-web:  ## Lint frontend (eslint)
	cd apps/web && $(NPM) run lint

format: format-api format-web  ## Format everything

format-api:  ## Format Python (ruff format)
	ruff format apps alembic
	ruff check --fix apps alembic

format-web:  ## Format frontend (prettier)
	cd apps/web && npx prettier --write 'src/**/*.{ts,tsx,js,jsx,json,css,md}'

typecheck:  ## Run mypy on the API
	mypy apps/api

# ── Tests ────────────────────────────────────────────────────
test: test-api  ## Run all tests

test-api:  ## Run backend unit tests (skip integration)
	cd apps/api && $(PY) -m pytest -v -m "not integration"

test-integration:  ## Run integration tests (Postgres + Redis via testcontainers, requires Docker)
	cd apps/api && $(PY) -m pytest -v -m integration

# ── Docker ───────────────────────────────────────────────────
docker-up:  ## Start the Docker stack (postgres, redis, api, web, ...)
	docker compose up -d --build

docker-down:  ## Stop the Docker stack
	docker compose down

docker-logs:  ## Tail Docker stack logs
	docker compose logs -f --tail=100

# ── Observabilite (Prometheus + Grafana) ─────────────────────
monitoring-up:  ## Start monitoring overlay (Prometheus :9090, Grafana :3002)
	docker compose -f docker-compose.yml -f docker-compose.monitoring.yml up -d prometheus grafana postgres-exporter redis-exporter

monitoring-down:  ## Stop monitoring overlay
	docker compose -f docker-compose.yml -f docker-compose.monitoring.yml stop prometheus grafana postgres-exporter redis-exporter

monitoring-logs:  ## Tail monitoring stack logs
	docker compose -f docker-compose.yml -f docker-compose.monitoring.yml logs -f --tail=100 prometheus grafana

# ── Database migrations ──────────────────────────────────────
migrate:  ## Apply all pending Alembic migrations
	alembic upgrade head

migrate-create:  ## Create a new Alembic migration (use M="message")
	alembic revision --autogenerate -m "$(M)"

# ── Secrets ──────────────────────────────────────────────────
secrets-gen:  ## Generate strong random secrets for .env (prints to stdout)
	@$(PY) -c "import secrets; print('API_KEY=' + secrets.token_urlsafe(32)); print('JWT_SECRET_KEY=' + secrets.token_urlsafe(48)); print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(20))"

secrets-init:  ## Initialize ./secrets/*.txt files for docker-compose secrets overlay
	bash scripts/secrets-init.sh

tls-certs:  ## Generate self-signed TLS certs (./certs/) for the TLS overlay
	bash scripts/tls-certs.sh

# ── Prod-like stack (secrets + TLS overlays) ─────────────────
prod-up:  ## Bring up base + secrets + TLS overlays
	docker compose -f docker-compose.yml -f docker-compose.secrets.yml -f docker-compose.tls.yml up -d --build

prod-down:  ## Stop the prod-like stack
	docker compose -f docker-compose.yml -f docker-compose.secrets.yml -f docker-compose.tls.yml down

# ── Backup / restore Postgres ────────────────────────────────
backup:  ## Dump Postgres into ./backups/cyberdef-*.dump (custom format)
	bash scripts/backup.sh

backup-list:  ## List existing backups
	@ls -lh backups/cyberdef-*.dump 2>/dev/null || echo "no backups yet"

restore:  ## Restore from a dump (use F=path/to/dump)
	bash scripts/restore.sh "$(F)"

# ── Seed (amorçage instance fraîche) ─────────────────────────
seed:  ## Amorce RAG (rebuild index) + SigmaHQ (sync) après le 1er boot
	bash scripts/seed.sh

# ── Cleanup ──────────────────────────────────────────────────
clean:  ## Remove caches and build artifacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
	find . -type d -name .ruff_cache -prune -exec rm -rf {} +
	find . -type d -name .mypy_cache -prune -exec rm -rf {} +
	rm -rf apps/web/.next apps/web/tsconfig.tsbuildinfo
