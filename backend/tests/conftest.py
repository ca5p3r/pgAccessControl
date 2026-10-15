"""Integration tests run against a real PostgreSQL server (never point them at production!).

Configure with TEST_PG_HOST / TEST_PG_PORT / TEST_PG_USER / TEST_PG_PASSWORD (superuser required).
"""

import asyncio
import os
import sys
import tempfile

import psycopg
import pytest
from psycopg import sql

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

PG = {
    "host": os.environ.get("TEST_PG_HOST", "127.0.0.1"),
    "port": int(os.environ.get("TEST_PG_PORT", "55432")),
    "user": os.environ.get("TEST_PG_USER", "postgres"),
    "password": os.environ.get("TEST_PG_PASSWORD", "testpw"),
}
os.environ.update(
    PG_HOST=PG["host"],
    PG_PORT=str(PG["port"]),
    PG_USER=PG["user"],
    PG_PASSWORD=PG["password"],
    AUTH_ENABLED="false",
    LOG_LEVEL="warning",
    AUDIT_DB_PATH=os.path.join(tempfile.mkdtemp(prefix="pgac-audit-"), "audit.db"),
    DATA_DB_PATH=os.path.join(tempfile.mkdtemp(prefix="pgac-data-"), "app.db"),
    ENCRYPTION_KEY="test-encryption-key-0123456789abcdef",
)

from fastapi.testclient import TestClient  # noqa: E402

from app.config import get_settings  # noqa: E402

DB = "pgac_test"

# A second PostgreSQL server, used to prove that servers are isolated from each other.
PG2 = {
    "host": os.environ.get("TEST_PG2_HOST", "127.0.0.1"),
    "port": int(os.environ.get("TEST_PG2_PORT", "55433")),
    "user": os.environ.get("TEST_PG2_USER", "postgres"),
    "password": os.environ.get("TEST_PG2_PASSWORD", "testpw2"),
}


def admin2(dbname="postgres"):
    return psycopg.connect(**PG2, dbname=dbname, autocommit=True, connect_timeout=3)


def pg2_available() -> bool:
    try:
        admin2().close()
        return True
    except psycopg.Error:
        return False


def admin(dbname="postgres"):
    return psycopg.connect(**PG, dbname=dbname, autocommit=True)


@pytest.fixture(scope="session", autouse=True)
def database():
    with admin() as c:
        c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(DB)))
        c.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(DB)))
    with admin(DB) as c:
        c.execute(
            """
            CREATE SCHEMA app;
            CREATE TABLE app.orders (id serial PRIMARY KEY, total numeric);
            CREATE TABLE app.customers (id serial PRIMARY KEY, name text);
            CREATE VIEW app.order_totals AS SELECT sum(total) FROM app.orders;
            CREATE FUNCTION app.double(i int) RETURNS int LANGUAGE sql AS 'SELECT i * 2';
            """
        )
    yield
    with admin() as c:
        c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(DB)))
        for (name,) in c.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 't\\_%'").fetchall():
            c.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


@pytest.fixture(scope="session")
def client(database):
    get_settings.cache_clear()
    from app.main import create_app

    with TestClient(create_app()) as c:
        yield c


@pytest.fixture(autouse=True)
def clean_roles():
    yield
    with admin(DB) as c:
        for (name,) in c.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 't\\_%'").fetchall():
            ident = sql.Identifier(name)
            c.execute(sql.SQL("DROP OWNED BY {}").format(ident))  # no-op for roles owning nothing
        with admin() as g:
            for (name,) in g.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 't\\_%'").fetchall():
                g.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))


@pytest.fixture
def srv2(client):
    """The second PostgreSQL server, registered as a profile through the real API (password included)."""
    if not pg2_available():
        pytest.skip("second test PostgreSQL server (TEST_PG2_*) is not running")
    r = client.post("/api/servers", json={
        "name": "Second server", "environment": "staging", "host": PG2["host"], "port": PG2["port"], "user": PG2["user"],
        "password": PG2["password"], "database": "postgres", "sslmode": "disable",
    })
    assert r.status_code == 201, r.text
    server = r.json()
    with admin2() as c:
        c.execute("CREATE TABLE IF NOT EXISTS public.srv2_t (id int)")
    yield server
    with admin2() as c:
        for (name,) in c.execute("SELECT rolname FROM pg_roles WHERE rolname LIKE 't\\_%'").fetchall():
            c.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
            c.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))
        c.execute("DROP TABLE IF EXISTS public.srv2_t")
    client.delete(f"/api/servers/{server['id']}")
