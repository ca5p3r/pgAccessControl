"""Persistent audit history.

Every change made through the app (and every sign-in) is stored in a small SQLite file together with
who did it, the SQL that ran (passwords redacted), before/after values and any error. Entries are also
emitted as JSON lines on the ``pgac.audit`` logger so a log collector can pick them up.

Only changes made *through this app* are recorded; direct ``psql`` sessions are not visible here.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import re
import sqlite3
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator

import psycopg
from fastapi import HTTPException, Request
from psycopg import sql

from .config import Settings
from .errors import AppError

log = logging.getLogger("pgac.audit")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    actor       TEXT NOT NULL,
    ip          TEXT,
    action      TEXT NOT NULL,
    target_type TEXT,
    target      TEXT,
    database    TEXT,
    status      TEXT NOT NULL,
    summary     TEXT NOT NULL,
    statements  TEXT,
    details     TEXT,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS ix_audit_ts     ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS ix_audit_target ON audit_log (target, ts DESC);
CREATE INDEX IF NOT EXISTS ix_audit_actor  ON audit_log (actor, ts DESC);
"""

# PASSWORD 'secret'  /  PASSWORD E'it''s'  -> PASSWORD '********'
_PASSWORD_RE = re.compile(r"(PASSWORD\s+)E?'(?:[^']|'')*'", re.IGNORECASE)

EXPORT_LIMIT = 100_000


def redact_sql(text: str) -> str:
    return _PASSWORD_RE.sub(r"\1'********'", text)


# ---------------------------------------------------------------------------
# Statement capture: services call record_statement() for every mutating statement they run, and the
# active audited() block collects them without the service needing to know about auditing.
# ---------------------------------------------------------------------------
_statements: contextvars.ContextVar[list[str] | None] = contextvars.ContextVar("audit_statements", default=None)


def record_statement(stmt: sql.Composable, conn: psycopg.AsyncConnection) -> None:
    bucket = _statements.get()
    if bucket is not None:
        bucket.append(redact_sql(stmt.as_string(conn).strip()) + ";")


def add_statements(statements: list[str]) -> None:
    bucket = _statements.get()
    if bucket is not None:
        bucket.extend(redact_sql(s) for s in statements)


def note(comment: str) -> None:
    bucket = _statements.get()
    if bucket is not None:
        bucket.append(f"-- {comment}")


@dataclass
class AuditEntry:
    summary: str = ""
    database: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    statements: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------
def _escape_like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class AuditStore:
    def __init__(self, settings: Settings) -> None:
        self.enabled = settings.audit_enabled
        self.path = settings.audit_db_path
        self.retention_days = settings.audit_retention_days

    # -- plumbing -------------------------------------------------------
    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def init(self) -> None:
        if not self.enabled:
            return
        Path(self.path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)
            conn.commit()
        finally:
            conn.close()

    # -- writing --------------------------------------------------------
    def _insert(self, e: dict[str, Any]) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """INSERT INTO audit_log (ts, actor, ip, action, target_type, target, database, status,
                                          summary, statements, details, error)
                   VALUES (:ts, :actor, :ip, :action, :target_type, :target, :database, :status,
                           :summary, :statements, :details, :error)""",
                e,
            )
            conn.commit()
        finally:
            conn.close()

    async def record(self, **e: Any) -> None:
        """Persist one entry. Never raises: a failing audit write must not undo a committed change."""
        row = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "actor": e.get("actor") or "unknown",
            "ip": e.get("ip"),
            "action": e["action"],
            "target_type": e.get("target_type"),
            "target": e.get("target"),
            "database": e.get("database"),
            "status": e.get("status", "success"),
            "summary": e.get("summary", ""),
            "statements": json.dumps(e.get("statements") or []),
            "details": json.dumps(e.get("details") or {}, default=str),
            "error": e.get("error"),
        }
        log.info(json.dumps({k: v for k, v in row.items() if k not in ("statements", "details") or v not in ("[]", "{}")}))
        if not self.enabled:
            return
        try:
            await asyncio.to_thread(self._insert, row)
        except Exception:  # noqa: BLE001
            log.exception("Could not write audit entry (action=%s target=%s)", row["action"], row["target"])

    # -- reading --------------------------------------------------------
    @staticmethod
    def _where(f: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        clauses, p = ["1=1"], {}
        for key, column in (("actor", "actor"), ("target", "target"), ("database", "database"), ("status", "status")):
            if f.get(key):
                clauses.append(f"{column} = :{key}")
                p[key] = f[key]
        if f.get("action"):
            clauses.append("action LIKE :action ESCAPE '\\'")
            p["action"] = _escape_like(f["action"])[1:]  # prefix match: "role." matches role.create, ...
        if f.get("q"):
            clauses.append(
                "(actor LIKE :q ESCAPE '\\' OR target LIKE :q ESCAPE '\\' OR summary LIKE :q ESCAPE '\\' "
                "OR statements LIKE :q ESCAPE '\\' OR error LIKE :q ESCAPE '\\')"
            )
            p["q"] = _escape_like(f["q"])
        if f.get("date_from"):
            clauses.append("ts >= :date_from")
            p["date_from"] = f["date_from"]
        if f.get("date_to"):
            # inclusive of the whole end day
            end = datetime.fromisoformat(f["date_to"]) + timedelta(days=1)
            clauses.append("ts < :date_to")
            p["date_to"] = end.strftime("%Y-%m-%d")
        return " AND ".join(clauses), p

    @staticmethod
    def _row(r: sqlite3.Row) -> dict[str, Any]:
        d = dict(r)
        d["statements"] = json.loads(d["statements"] or "[]")
        d["details"] = json.loads(d["details"] or "{}")
        return d

    def _query(self, f: dict[str, Any], limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        where, p = self._where(f)
        conn = self._connect()
        try:
            total = conn.execute(f"SELECT count(*) FROM audit_log WHERE {where}", p).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM audit_log WHERE {where} ORDER BY ts DESC, id DESC LIMIT :limit OFFSET :offset",
                {**p, "limit": limit, "offset": offset},
            ).fetchall()
            return [self._row(r) for r in rows], total
        finally:
            conn.close()

    async def query(self, f: dict[str, Any], limit: int, offset: int) -> tuple[list[dict[str, Any]], int]:
        if not self.enabled:
            return [], 0
        return await asyncio.to_thread(self._query, f, limit, offset)

    def _facets(self) -> dict[str, list[str]]:
        conn = self._connect()
        try:
            return {
                "actors": [r[0] for r in conn.execute("SELECT DISTINCT actor FROM audit_log ORDER BY actor")],
                "databases": [
                    r[0] for r in conn.execute("SELECT DISTINCT database FROM audit_log WHERE database IS NOT NULL ORDER BY 1")
                ],
            }
        finally:
            conn.close()

    async def facets(self) -> dict[str, list[str]]:
        if not self.enabled:
            return {"actors": [], "databases": []}
        return await asyncio.to_thread(self._facets)

    def _purge(self) -> int:
        if self.retention_days <= 0:
            return 0
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.retention_days)).isoformat()
        conn = self._connect()
        try:
            n = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,)).rowcount
            conn.commit()
            return n
        finally:
            conn.close()

    async def purge_loop(self) -> None:
        """Delete entries older than the retention period, once at startup and then daily."""
        while self.enabled and self.retention_days > 0:
            try:
                n = await asyncio.to_thread(self._purge)
                if n:
                    log.info("Audit retention: removed %d entries older than %d days", n, self.retention_days)
            except Exception:  # noqa: BLE001
                log.exception("Audit retention job failed")
            await asyncio.sleep(24 * 3600)


# ---------------------------------------------------------------------------
# Helpers used by routers
# ---------------------------------------------------------------------------
def _client(request: Request) -> str | None:
    return request.client.host if request.client else None


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, psycopg.Error):
        return exc.diag.message_primary or str(exc)
    if isinstance(exc, AppError):
        return exc.message
    if isinstance(exc, HTTPException):
        return str(exc.detail)
    return f"{type(exc).__name__}: {exc}"


@asynccontextmanager
async def audited(
    request: Request,
    actor: str,
    action: str,
    *,
    target: str | None,
    target_type: str = "role",
    database: str | None = None,
) -> AsyncIterator[AuditEntry]:
    """Record the outcome of the wrapped operation. Set ``entry.summary`` / ``entry.details`` inside."""
    store: AuditStore = request.app.state.audit
    entry = AuditEntry(database=database)
    token = _statements.set(entry.statements)
    status, error = "success", None
    try:
        yield entry
    except Exception as exc:
        status, error = "failed", _error_text(exc)
        raise
    finally:
        _statements.reset(token)
        summary = entry.summary or action
        if status == "failed":
            summary = f"Failed: {summary}"
        await store.record(
            actor=actor, ip=_client(request), action=action, target_type=target_type, target=target,
            database=entry.database, status=status, summary=summary, statements=entry.statements,
            details=entry.details, error=error,
        )


async def log_event(request: Request, actor: str, action: str, summary: str, status: str = "success") -> None:
    await request.app.state.audit.record(
        actor=actor, ip=_client(request), action=action, target_type="session", target=actor,
        status=status, summary=summary,
    )
