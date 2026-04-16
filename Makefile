# ─────────────────────────────────────────────────────────────
# Cyber Defense / SOC platform — developer commands
# ─────────────────────────────────────────────────────────────

.DEFAULT_GOAL := help
.PHONY: help setup setup-api setup-web dev dev-api dev-web \
        lint lint-api lint-web format format-api format-web \
        typecheck test test-api docker-up docker-down docker-logs \
        migrate migrate-create secrets-gen clean

PY ?= python
NPM ?= npm

# ── Help ─────────────────────────────────────────────────────
help:  ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ── Setup ────────────────────────────────────────────────────
setup: setup-api setup-web  ## Install backend + frontend + pre-commit
	pre-commit install || pip install pre-commit && pre-commit install

setup-api:  ## Install backend Python dependencies
	$(PY) -m pip install -r apps/api/requirements.txt
	$(PY) -m pip install ruff mypy pre-commit pytest pytest-asyncio detect-secrets

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

test-api:  ## Run backend tests
	cd apps/api && $(PY) -m pytest -v

# ── Docker ───────────────────────────────────────────────────
docker-up:  ## Start the Docker stack (postgres, redis, api, web, ...)
	docker compose up -d --build

docker-down:  ## Stop the Docker stack
	docker compose down

docker-logs:  ## Tail Docker stack logs
	docker compose logs -f --tail=100

# ── Database migrations ──────────────────────────────────────
migrate:  ## Apply all pending Alembic migrations
	alembic upgrade head

migrate-create:  ## Create a new Alembic migration (use M="message")
	alembic revision --autogenerate -m "$(M)"

# ── Secrets ──────────────────────────────────────────────────
secrets-gen:  ## Generate strong random secrets for .env (prints to stdout)
	@$(PY) -c "import secrets; print('API_KEY=' + secrets.token_urlsafe(32)); print('JWT_SECRET_KEY=' + secrets.token_urlsafe(48)); print('POSTGRES_PASSWORD=' + secrets.token_urlsafe(20))"

# ── Cleanup ──────────────────────────────────────────────────
clean:  ## Remove caches and build artifacts
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	find . -type d -name .pytest_cache -prune -exec rm -rf {} +
	find . -type d -name .ruff_cache -prune -exec rm -rf {} +
	find . -type d -name .mypy_cache -prune -exec rm -rf {} +
	rm -rf apps/web/.next apps/web/tsconfig.tsbuildinfo
