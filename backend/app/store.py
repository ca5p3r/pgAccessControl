"""App data store (SQLite): accounts, server profiles, temporary-access schedules and permission snapshots.

Kept separate from the audit file so audit history can be retained, exported or disabled on its own.
All access goes through ``run`` which executes a function with a short-lived connection in a worker
thread, so the event loop is never blocked and several workers can share the file (WAL mode).

Schema changes are applied by ``_migrate`` (idempotent, safe on existing databases). Everything that
belongs to one PostgreSQL server carries a ``server_id``; data created before multi-server support is
assigned to the environment-configured server, whose id is ``default``.
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")

DEFAULT_SERVER = "default"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS app_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    created_by    TEXT,
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS servers (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description     TEXT,
    environment     TEXT NOT NULL DEFAULT 'other' CHECK (environment IN ('production', 'staging', 'development', 'other')),
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL,
    username        TEXT NOT NULL,
    password_enc    TEXT,                 -- AES-256-GCM, bound to the server id; NULL = no password
    database        TEXT NOT NULL,        -- maintenance database for cluster-wide queries
    sslmode         TEXT NOT NULL DEFAULT 'verify-full',
    ssl_ca          TEXT,                 -- PEM text of a CA certificate (public)
    connect_timeout INTEGER NOT NULL DEFAULT 5,
    read_only       INTEGER NOT NULL DEFAULT 0,
    min_role        TEXT NOT NULL DEFAULT 'viewer' CHECK (min_role IN ('viewer', 'operator', 'admin')),
    disabled        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL,
    created_by      TEXT,
    updated_at      TEXT NOT NULL,
    updated_by      TEXT
);

CREATE TABLE IF NOT EXISTS expiring_access (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id    TEXT NOT NULL DEFAULT 'default',
    kind         TEXT NOT NULL CHECK (kind IN ('grant', 'membership')),
    grantee      TEXT NOT NULL,           -- the role that holds the access
    database     TEXT,                    -- for grants
    description  TEXT NOT NULL,
    revoke_spec  TEXT NOT NULL,           -- JSON: what to undo when it expires
    created_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'expired', 'cancelled', 'failed')),
    finished_at  TEXT,
    error        TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id  TEXT NOT NULL DEFAULT 'default',
    name       TEXT NOT NULL,
    note       TEXT,
    database   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    baseline   INTEGER NOT NULL DEFAULT 0,
    counts     TEXT NOT NULL,
    data       BLOB NOT NULL,           -- gzip-compressed JSON
    last_check TEXT,                    -- JSON summary of the last scheduled drift check
    UNIQUE (server_id, name, database)
);
"""

_INDEXES = """
CREATE INDEX IF NOT EXISTS ix_expiring_due ON expiring_access (status, expires_at);
CREATE INDEX IF NOT EXISTS ix_expiring_server_grantee ON expiring_access (server_id, grantee, status);
CREATE INDEX IF NOT EXISTS ix_snapshots_server ON snapshots (server_id, database);
"""


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _migrate(conn: sqlite3.Connection) -> None:
    """Bring databases created by earlier versions up to date."""
    if "server_id" not in _columns(conn, "expiring_access"):
        conn.execute("ALTER TABLE expiring_access ADD COLUMN server_id TEXT NOT NULL DEFAULT 'default'")
    if "server_id" not in _columns(conn, "snapshots"):
        # UNIQUE (name, database) became UNIQUE (server_id, name, database): SQLite needs a table rebuild.
        conn.executescript(
            """
            ALTER TABLE snapshots RENAME TO snapshots_old;
            CREATE TABLE snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT, server_id TEXT NOT NULL DEFAULT 'default',
                name TEXT NOT NULL, note TEXT, database TEXT NOT NULL, created_at TEXT NOT NULL, created_by TEXT NOT NULL,
                baseline INTEGER NOT NULL DEFAULT 0, counts TEXT NOT NULL, data BLOB NOT NULL, last_check TEXT,
                UNIQUE (server_id, name, database)
            );
            INSERT INTO snapshots (id, server_id, name, note, database, created_at, created_by, baseline, counts, data, last_check)
                 SELECT id, 'default', name, note, database, created_at, created_by, baseline, counts, data, last_check FROM snapshots_old;
            DROP TABLE snapshots_old;
            """
        )


class AppStore:
    def __init__(self, path: str) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init(self) -> None:
        Path(self.path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            _migrate(conn)
            conn.executescript(_INDEXES)
            conn.commit()
        finally:
            conn.close()

    def _run(self, fn: Callable[..., T], *args: Any) -> T:
        conn = self._connect()
        try:
            result = fn(conn, *args)
            conn.commit()
            return result
        finally:
            conn.close()

    async def run(self, fn: Callable[..., T], *args: Any) -> T:
        return await asyncio.to_thread(self._run, fn, *args)
