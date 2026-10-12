"""App data store (SQLite): accounts, temporary-access schedules and permission snapshots.

Kept separate from the audit file so audit history can be retained, exported or disabled on its own.
All access goes through ``run`` which executes a function with a short-lived connection in a worker
thread, so the event loop is never blocked and several workers can share the file (WAL mode).
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Any, Callable, TypeVar

T = TypeVar("T")

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

CREATE TABLE IF NOT EXISTS expiring_access (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
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
CREATE INDEX IF NOT EXISTS ix_expiring_due ON expiring_access (status, expires_at);
CREATE INDEX IF NOT EXISTS ix_expiring_grantee ON expiring_access (grantee, status);

CREATE TABLE IF NOT EXISTS snapshots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    note       TEXT,
    database   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    baseline   INTEGER NOT NULL DEFAULT 0,
    counts     TEXT NOT NULL,
    data       BLOB NOT NULL,           -- gzip-compressed JSON
    last_check TEXT,                    -- JSON summary of the last scheduled drift check
    UNIQUE (name, database)
);
"""


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
