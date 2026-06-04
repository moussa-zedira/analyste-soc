"""Fixtures partagees : Postgres + Redis ephemeres via testcontainers.

L'objectif est de tester contre les vrais moteurs (Postgres, Redis) plutot
que contre des mocks ou SQLite, pour ne pas masquer les bugs de migration
ou de comportement specifique. Voir feedback projet : "ne pas mocker la DB".
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Iterator

import pytest


@pytest.fixture(scope="session")
def _postgres_url() -> Iterator[str]:
    """Fournit une URL Postgres pour la session.

    Par defaut, spin un container ephemere via testcontainers.
    Si TEST_DATABASE_URL est defini dans l'env (CI, docker-compose dev),
    on l'utilise directement — evite de lancer Docker-in-Docker.
    """
    override = os.environ.get("TEST_DATABASE_URL")
    if override:
        if override.startswith("postgresql://"):
            override = override.replace("postgresql://", "postgresql+psycopg2://", 1)
        yield override
        return

    try:
        from testcontainers.postgres import PostgresContainer
    except ImportError:
        pytest.skip("testcontainers manquant : pip install -r apps/api/requirements-dev.txt")
    try:
        pg_ctx = PostgresContainer("postgres:16-alpine")
        pg = pg_ctx.start()
    except Exception as exc:  # noqa: BLE001 — Docker absent/injoignable -> skip propre
        pytest.skip(
            f"Docker indisponible pour Postgres ({exc.__class__.__name__}) — tests DB ignores"
        )
    try:
        url = pg.get_connection_url()
        # SQLAlchemy attend ``postgresql+psycopg2://`` — testcontainers donne ``postgresql+psycopg2://``
        # par defaut depuis 4.x mais on sait jamais.
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg2://", 1)
        yield url
    finally:
        pg_ctx.stop()


@pytest.fixture(scope="session")
def _redis_url() -> Iterator[str]:
    """Fournit une URL Redis pour la session.

    TEST_REDIS_URL override le container ephemere pour CI / dev-compose.
    """
    override = os.environ.get("TEST_REDIS_URL")
    if override:
        yield override
        return

    try:
        from testcontainers.redis import RedisContainer
    except ImportError:
        pytest.skip("testcontainers manquant : pip install -r apps/api/requirements-dev.txt")
    try:
        r_ctx = RedisContainer("redis:7-alpine")
        r = r_ctx.start()
    except Exception as exc:  # noqa: BLE001 — Docker absent/injoignable -> skip propre
        pytest.skip(
            f"Docker indisponible pour Redis ({exc.__class__.__name__}) — tests Redis ignores"
        )
    try:
        host = r.get_container_host_ip()
        port = r.get_exposed_port(6379)
        yield f"redis://{host}:{port}/0"
    finally:
        r_ctx.stop()


@pytest.fixture(scope="session", autouse=True)
def _configure_env() -> Iterator[None]:
    """Configure les variables d'environnement avant l'import de l'app.

    NE depend PAS des conteneurs Postgres/Redis : les tests purement unitaires
    (qui ne demandent ni ``db_session`` ni ``redis_client``) tournent ainsi sans
    Docker. Les URLs DB/Redis reelles sont injectees a la demande par les
    fixtures ``_engine`` et ``redis_client``.
    """
    overrides = {
        "ENV": "dev",
        "API_KEY": "test-api-key-" + secrets.token_hex(8),
        "JWT_SECRET_KEY": "test-jwt-" + secrets.token_hex(16),
        "JWT_EXPIRE_MINUTES": "5",
        "JWT_REFRESH_EXPIRE_DAYS": "1",
        "ADMIN_BOOTSTRAP_PASSWORD": "test-admin-pw-" + secrets.token_hex(8),
    }
    saved = {k: os.environ.get(k) for k in overrides}
    os.environ.update(overrides)

    # Invalide le cache settings + recharge le moteur DB.
    from apps.api.config import get_settings

    get_settings.cache_clear()

    yield

    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    get_settings.cache_clear()


@pytest.fixture(scope="session")
def _engine(_configure_env, _postgres_url: str):
    """Recree le moteur SQLAlchemy contre la DB testcontainer + applique le schema."""
    from sqlalchemy import create_engine

    # Injecte l'URL du conteneur (le fixture _postgres_url declenche le spin Docker
    # uniquement quand un test reclame une session DB) puis invalide le cache settings.
    os.environ["DATABASE_URL"] = _postgres_url

    # Import obligatoire pour que tous les models soient enregistres dans Base.metadata
    import apps.api.models  # noqa: F401
    from apps.api.config import get_settings
    from apps.api.db.base import Base

    get_settings.cache_clear()
    settings = get_settings()
    engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
    Base.metadata.create_all(bind=engine)

    # Trigger d'immutabilite sur pentest_audit_logs (cf migration 008).
    from sqlalchemy import text

    with engine.begin() as conn:
        conn.execute(
            text(
                """
            CREATE OR REPLACE FUNCTION pentest_audit_logs_no_modify()
            RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'pentest_audit_logs is append-only';
            END;
            $$ LANGUAGE plpgsql;
            """
            )
        )
        conn.execute(
            text(
                """
            DROP TRIGGER IF EXISTS pentest_audit_logs_block_update ON pentest_audit_logs;
            CREATE TRIGGER pentest_audit_logs_block_update
            BEFORE UPDATE OR DELETE ON pentest_audit_logs
            FOR EACH ROW EXECUTE FUNCTION pentest_audit_logs_no_modify();
            """
            )
        )

    # Repointe la SessionLocal globale du module sur ce moteur.
    from apps.api.db import session as db_session_mod

    db_session_mod.engine = engine
    db_session_mod.SessionLocal.configure(bind=engine)
    return engine


@pytest.fixture()
def db_session(_engine):
    """Session DB isolee par test (rollback complet en sortie)."""
    from sqlalchemy.orm import sessionmaker

    connection = _engine.connect()
    trans = connection.begin()
    Session = sessionmaker(bind=connection, autocommit=False, autoflush=False)
    session = Session()
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


@pytest.fixture()
def redis_client(_configure_env, _redis_url: str):
    """Client Redis branche sur le container, FLUSHDB entre les tests."""
    import redis

    os.environ["REDIS_URL"] = _redis_url
    from apps.api.config import get_settings

    get_settings.cache_clear()
    client = redis.Redis.from_url(_redis_url, decode_responses=True)
    client.flushdb()
    yield client
    client.flushdb()


@pytest.fixture()
def api_client(_engine, db_session, redis_client):
    """TestClient FastAPI partageant la session test (voit les fixtures insérées)."""
    from fastapi.testclient import TestClient

    from apps.api.db.session import get_db
    from apps.api.main import create_app

    app = create_app()

    def _override_get_db():
        # Partage la session du test : fixtures insérées visibles côté serveur,
        # rollback final propre à la sortie du test.
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = _override_get_db

    client = TestClient(app)
    # Inclut automatiquement la cle API requise pour les routes protegees
    # par require_api_key (n'a pas d'effet sur celles qui exigent du JWT).
    client.headers.update({"X-API-Key": os.environ["API_KEY"]})
    yield client


@pytest.fixture()
def auth_headers(api_client) -> dict[str, str]:
    """Cree un user analyst + retourne les headers Authorization Bearer."""
    import uuid

    username = f"alice-{uuid.uuid4().hex[:6]}"
    password = "TestPassw0rd!"
    api_client.post(
        "/auth/register",
        json={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
            "role": "analyst",
        },
    )
    resp = api_client.post("/auth/login", json={"username": username, "password": password})
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
