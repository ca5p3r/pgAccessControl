"""Connection pool management.

PostgreSQL catalogs for tables/schemas/sequences are per-database, so inspecting permissions in
several databases needs a connection to each one. ``PoolManager`` lazily creates one small pool per
database and evicts the least-recently-used idle pools to bound the number of server connections.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .config import Settings
from .errors import NotFound


class _Entry:
    __slots__ = ("pool", "last_used", "in_flight")

    def __init__(self, pool: AsyncConnectionPool) -> None:
        self.pool = pool
        self.last_used = time.monotonic()
        self.in_flight = 0


class PoolManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._entries: dict[str, _Entry] = {}
        self._lock = asyncio.Lock()

    @property
    def default_database(self) -> str:
        return self.settings.pg_database

    def _conninfo(self, dbname: str) -> dict:
        s = self.settings
        return {
            "host": s.pg_host,
            "port": s.pg_port,
            "user": s.pg_user,
            "password": s.pg_password,
            "dbname": dbname,
            "sslmode": s.pg_sslmode,
            "connect_timeout": s.pg_connect_timeout,
            "application_name": s.pg_application_name,
            "row_factory": dict_row,
        }

    def _make_pool(self, dbname: str) -> AsyncConnectionPool:
        s = self.settings
        return AsyncConnectionPool(
            kwargs=self._conninfo(dbname),
            min_size=s.pool_min_size,
            max_size=s.pool_max_size,
            max_idle=s.pool_max_idle_seconds,
            timeout=s.pool_acquire_timeout,
            check=AsyncConnectionPool.check_connection,
            open=False,
        )

    async def _get(self, dbname: str) -> _Entry:
        entry = self._entries.get(dbname)
        if entry is not None:
            return entry
        async with self._lock:
            entry = self._entries.get(dbname)
            if entry is None:
                if dbname != self.default_database:
                    await self._ensure_database_exists(dbname)
                # A pool whose connections fail only reports a generic timeout; a direct probe
                # surfaces the real error (bad password, no CONNECT privilege, ...) immediately.
                probe = await psycopg.AsyncConnection.connect(**self._conninfo(dbname))
                await probe.close()
                await self._evict_locked()
                pool = self._make_pool(dbname)
                await pool.open(wait=False)
                entry = self._entries[dbname] = _Entry(pool)
            return entry

    async def _ensure_database_exists(self, dbname: str) -> None:
        # Only real databases may get a pool; the default pool must already be open (or be opened now).
        default = self._entries.get(self.default_database)
        if default is None:
            probe = await psycopg.AsyncConnection.connect(**self._conninfo(self.default_database))
            conn, owned = probe, True
        else:
            conn, owned = None, False
        try:
            if owned:
                cur = await conn.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
                found = await cur.fetchone()
            else:
                async with default.pool.connection() as c:
                    cur = await c.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,))
                    found = await cur.fetchone()
        finally:
            if owned:
                await conn.close()
        if not found:
            raise NotFound(f'Database "{dbname}" does not exist')

    async def _evict_locked(self) -> None:
        limit = self.settings.pool_max_databases
        while len(self._entries) >= limit:
            idle = [
                (e.last_used, name)
                for name, e in self._entries.items()
                if e.in_flight == 0 and name != self.default_database
            ]
            if not idle:
                return
            _, victim = min(idle)
            entry = self._entries.pop(victim)
            await entry.pool.close()

    @asynccontextmanager
    async def connection(self, dbname: str | None = None) -> AsyncIterator[psycopg.AsyncConnection]:
        """Borrow a connection; commits on success, rolls back on error."""
        entry = await self._get(dbname or self.default_database)
        entry.in_flight += 1
        try:
            async with entry.pool.connection() as conn:
                yield conn
        finally:
            entry.in_flight -= 1
            entry.last_used = time.monotonic()

    async def warm_up(self) -> None:
        await self._get(self.default_database)

    async def ping(self) -> bool:
        try:
            async with self.connection() as conn:
                await conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    async def close(self) -> None:
        async with self._lock:
            entries, self._entries = list(self._entries.values()), {}
        await asyncio.gather(*(e.pool.close() for e in entries), return_exceptions=True)
