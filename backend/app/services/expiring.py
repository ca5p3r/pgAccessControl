"""Time-limited access: grants and role memberships that are revoked automatically at a set time.

PostgreSQL has no expiry for privileges (only for passwords), so the app keeps a schedule and a background
job performs the REVOKE when the time comes. Key safety property: when a grant is made temporary, only the
privileges that were *not already held* are scheduled for revocation, so a permanent grant is never taken
away by an expiring one that happened to overlap with it.

If the app is down at the deadline, the access is removed on the next run after it starts again.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg

from ..audit import _error_text, audited_system
from ..errors import AppError, NotFound
from ..schemas import PermissionChange
from . import permissions as perm
from . import roles as roles_svc

log = logging.getLogger("pgac.expiry")

MIN_LEAD = timedelta(seconds=30)
MAX_LEAD = timedelta(days=365 * 5)
_SIMPLE = {"database", "schema", "table", "sequence", "function", "column"}
_GONE = {"42704", "42P01", "42883", "3F000", "3D000"}  # object/role no longer exists: the access is gone anyway


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def check_expiry(value: datetime) -> datetime:
    """Validate and normalise (to UTC) a requested expiry time."""
    dt = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    if dt < now() + MIN_LEAD:
        raise AppError("The expiry time must be in the future.", 422)
    if dt > now() + MAX_LEAD:
        raise AppError("The expiry time is too far away (5 years at most).", 422)
    return dt


# ---------------------------------------------------------------------------
# Planning: what must be undone when a grant expires?
# ---------------------------------------------------------------------------
def _held_sql(object_type: str) -> str:
    base = {
        "table": """SELECT a.privilege_type AS priv, a.is_grantable AS grantable
                      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                      CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) a
                     WHERE n.nspname = %(schema)s AND c.relname = %(name)s AND a.grantee = %(grantee)s""",
        "sequence": """SELECT a.privilege_type AS priv, a.is_grantable AS grantable
                         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                         CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl, acldefault('s', c.relowner))) a
                        WHERE n.nspname = %(schema)s AND c.relname = %(name)s AND a.grantee = %(grantee)s""",
        "function": """SELECT a.privilege_type AS priv, a.is_grantable AS grantable
                         FROM pg_proc p CROSS JOIN LATERAL aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) a
                        WHERE p.oid = %(oid)s AND a.grantee = %(grantee)s""",
        "schema": """SELECT a.privilege_type AS priv, a.is_grantable AS grantable
                       FROM pg_namespace n CROSS JOIN LATERAL aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) a
                      WHERE n.nspname = %(name)s AND a.grantee = %(grantee)s""",
        "database": """SELECT a.privilege_type AS priv, a.is_grantable AS grantable
                         FROM pg_database d CROSS JOIN LATERAL aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a
                        WHERE d.datname = %(name)s AND a.grantee = %(grantee)s""",
        "column": """SELECT att.attname AS col, a.privilege_type AS priv, a.is_grantable AS grantable
                       FROM pg_attribute att JOIN pg_class c ON c.oid = att.attrelid
                       JOIN pg_namespace n ON n.oid = c.relnamespace
                       CROSS JOIN LATERAL aclexplode(att.attacl) a
                      WHERE n.nspname = %(schema)s AND c.relname = %(name)s AND att.attname = ANY(%(cols)s)
                        AND a.grantee = %(grantee)s""",
    }
    return base[object_type]


def _target_label(ch: PermissionChange) -> str:
    if ch.object_type == "column":
        return f"{ch.schema_name}.{ch.name} ({', '.join(ch.columns or [])})"
    if ch.object_type in ("table", "sequence"):
        return f"{ch.schema_name}.{ch.name}"
    if ch.object_type == "function":
        return f"function #{ch.oid}"
    return f"{ch.object_type} {ch.name}"


async def plan(conn: psycopg.AsyncConnection, role: str, changes: list[PermissionChange]) -> dict[str, Any]:
    """Work out the revocations that undo ``changes`` at expiry. Call *before* applying them."""
    grants = [c for c in changes if c.action == "grant"]
    if not grants:
        raise AppError("Only grants can be made temporary; this change contains none.", 400)
    if len(grants) != len(changes):
        raise AppError("A temporary change may only contain grants (revokes cannot expire).", 400)
    flags = await perm.get_role_flags(conn, role)
    grantee = 0
    if not flags["is_public"]:
        cur = await conn.execute("SELECT oid FROM pg_roles WHERE rolname = %s", (role,))
        grantee = (await cur.fetchone())["oid"]
    catalog = perm.privilege_catalog(conn.info.server_version)

    revokes: list[dict[str, Any]] = []
    expiring: list[str] = []
    skipped: list[str] = []

    def add(ch: PermissionChange, privs: list[str], *, cols: list[str] | None = None, option_only: bool = False) -> None:
        d = ch.model_copy(update={"action": "revoke", "privileges": privs, "with_grant_option": False,
                                  "revoke_grant_option": option_only, **({"columns": cols} if cols is not None else {})})
        revokes.append(d.model_dump(by_alias=True, exclude_none=True, mode="json"))
        shown = ch.model_copy(update={"columns": cols if cols is not None else ch.columns})
        expiring.append(f"{'grant option on ' if option_only else ''}{'/'.join(privs)} on {_target_label(shown)}")

    for ch in grants:
        if ch.object_type not in _SIMPLE:
            raise AppError("Expiry is only available for changes to individual objects, not for bulk or default privileges.", 400)
        names = perm._priv_names(ch, catalog)
        if names == ["ALL PRIVILEGES"]:
            names = catalog[perm._PRIV_FAMILY[ch.object_type]]
        params: dict[str, Any] = {"grantee": grantee, "schema": ch.schema_name, "name": ch.name, "oid": ch.oid, "cols": ch.columns or []}
        cur = await conn.execute(_held_sql(ch.object_type), params)
        rows = await cur.fetchall()

        if ch.object_type == "column":
            held: dict[str, dict[str, bool]] = {}
            for r in rows:
                held.setdefault(r["col"], {})[r["priv"]] = r["grantable"]
            for p in names:
                new_cols = [c for c in ch.columns or [] if p not in held.get(c, {})]
                opt_cols = [c for c in ch.columns or [] if p in held.get(c, {}) and not held[c][p] and ch.with_grant_option]
                kept = [c for c in ch.columns or [] if c not in new_cols and c not in opt_cols]
                if new_cols:
                    add(ch, [p], cols=new_cols)
                if opt_cols:
                    add(ch, [p], cols=opt_cols, option_only=True)
                if kept:
                    skipped.append(f"{p} on {_target_label(ch.model_copy(update={'columns': kept}))}")
        else:
            held_p = {r["priv"]: r["grantable"] for r in rows}
            new = [p for p in names if p not in held_p]
            opt = [p for p in names if p in held_p and not held_p[p] and ch.with_grant_option]
            kept = [p for p in names if p in held_p and p not in opt]
            if new:
                add(ch, new)
            if opt:
                add(ch, opt, option_only=True)
            if kept:
                skipped.append(f"{'/'.join(kept)} on {_target_label(ch)}")
    return {"revokes": revokes, "expiring": expiring, "skipped": skipped}


# ---------------------------------------------------------------------------
# Storage (sync functions, run through AppStore.run)
# ---------------------------------------------------------------------------
def _dict(r: sqlite3.Row) -> dict[str, Any]:
    d = dict(r)
    d["spec"] = json.loads(d.pop("revoke_spec"))
    return d


def db_insert(c: sqlite3.Connection, server_id: str, kind: str, grantee: str, database: str | None, description: str,
              spec: dict[str, Any], created_by: str, expires_at: str) -> int:
    cur = c.execute(
        """INSERT INTO expiring_access (server_id, kind, grantee, database, description, revoke_spec, created_at, created_by, expires_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (server_id, kind, grantee, database, description, json.dumps(spec), iso(now()), created_by, expires_at),
    )
    return int(cur.lastrowid)


def db_get(c: sqlite3.Connection, schedule_id: int) -> dict[str, Any] | None:
    r = c.execute("SELECT * FROM expiring_access WHERE id = ?", (schedule_id,)).fetchone()
    return _dict(r) if r else None


def db_list(c: sqlite3.Connection, status: str, involving: str | None, limit: int, server_id: str | None = None) -> list[dict[str, Any]]:
    where, p = [], []
    if server_id:
        where.append("server_id = ?")
        p.append(server_id)
    if status == "pending":
        where.append("status IN ('pending', 'running')")
    elif status == "history":
        where.append("status NOT IN ('pending', 'running')")
    if involving:
        where.append("(grantee = ? OR json_extract(revoke_spec, '$.role') = ?)")
        p += [involving, involving]
    sql_ = "SELECT * FROM expiring_access" + (" WHERE " + " AND ".join(where) if where else "")
    order = "expires_at ASC" if status == "pending" else "COALESCE(finished_at, expires_at) DESC"
    return [_dict(r) for r in c.execute(f"{sql_} ORDER BY {order}, id DESC LIMIT ?", (*p, limit))]


def db_set_status(c: sqlite3.Connection, schedule_id: int, status: str, error: str | None = None) -> None:
    c.execute("UPDATE expiring_access SET status = ?, error = ?, finished_at = ? WHERE id = ?", (status, error, iso(now()), schedule_id))


def db_claim_due(c: sqlite3.Connection, now_iso: str, limit: int) -> list[dict[str, Any]]:
    """Atomically take due schedules so several workers never run the same one twice."""
    rows = c.execute(
        """UPDATE expiring_access SET status = 'running'
            WHERE id IN (SELECT id FROM expiring_access WHERE status = 'pending' AND expires_at <= ?
                            AND server_id NOT IN (SELECT id FROM servers WHERE disabled = 1)
                          ORDER BY expires_at LIMIT ?)
              AND status = 'pending' RETURNING *""",
        (now_iso, limit),
    ).fetchall()
    return [_dict(r) for r in rows]


def db_claim_one(c: sqlite3.Connection, schedule_id: int) -> dict[str, Any] | None:
    r = c.execute(
        "UPDATE expiring_access SET status = 'running' WHERE id = ? AND status IN ('pending', 'failed') RETURNING *", (schedule_id,)
    ).fetchone()
    return _dict(r) if r else None


def db_reset_stuck(c: sqlite3.Connection) -> int:
    return c.execute("UPDATE expiring_access SET status = 'pending' WHERE status = 'running'").rowcount


def db_set_expiry(c: sqlite3.Connection, schedule_id: int, expires_at: str) -> bool:
    return c.execute("UPDATE expiring_access SET expires_at = ? WHERE id = ? AND status IN ('pending', 'failed')", (expires_at, schedule_id)).rowcount > 0


def db_cancel(c: sqlite3.Connection, schedule_id: int) -> bool:
    return c.execute(
        "UPDATE expiring_access SET status = 'cancelled', finished_at = ? WHERE id = ? AND status IN ('pending', 'failed')",
        (iso(now()), schedule_id),
    ).rowcount > 0


def db_find_membership(c: sqlite3.Connection, server_id: str, role: str, member: str) -> dict[str, Any] | None:
    r = c.execute(
        """SELECT * FROM expiring_access WHERE server_id = ? AND kind = 'membership' AND grantee = ?
              AND json_extract(revoke_spec, '$.role') = ? AND status IN ('pending', 'running')""",
        (server_id, member, role),
    ).fetchone()
    return _dict(r) if r else None


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------
async def _perform(app: Any, row: dict[str, Any], profile: Any) -> None:
    spec = row["spec"]
    pools = await app.state.servers.manager(profile)  # the server the access was granted on, not "the" server
    if row["kind"] == "grant":
        changes = [PermissionChange.model_validate(c) for c in spec["changes"]]
        async with pools.connection(row["database"]) as conn:
            await perm.apply_changes(conn, row["grantee"], changes, dry_run=False)
    else:
        async with pools.connection() as conn:
            await roles_svc._revoke_role(conn, spec["role"], row["grantee"])


async def run_row(app: Any, row: dict[str, Any], *, actor: str = "scheduler", action: str = "access.expired") -> None:
    """Perform one revocation, record it in the audit history and finish the schedule row."""
    store = app.state.store
    verb = "ended" if action == "access.expired" else "revoked now"
    status, error = "expired", None
    profile = await app.state.servers.get(row["server_id"])
    try:
        if profile is None:
            raise AppError("The server this access was granted on is no longer configured.", 409)
        async with audited_system(
            app.state.audit, action, target=row["grantee"], target_type="permission" if row["kind"] == "grant" else "role",
            database=row["database"], actor=actor, server=profile,
        ) as a:
            a.summary = f"Temporary access {verb} for {row['grantee']}: {row['description']}"
            a.details = {"schedule_id": row["id"], "expires_at": row["expires_at"], "created_by": row["created_by"]}
            try:
                await _perform(app, row, profile)
            except NotFound:  # the role was deleted meanwhile: its access is gone with it
                a.details["note"] = "already removed (role or object no longer exists)"
            except psycopg.Error as exc:
                if exc.sqlstate not in _GONE:
                    raise
                a.details["note"] = "already removed (role or object no longer exists)"
    except Exception as exc:  # noqa: BLE001
        status, error = "failed", _error_text(exc)
        log.warning("Could not end temporary access #%s: %s", row["id"], error)
    await store.run(db_set_status, row["id"], status, error)
    if status == "failed":
        raise AppError(f"Could not revoke: {error}", 409)


async def run_due(app: Any, limit: int = 50) -> int:
    rows = await app.state.store.run(db_claim_due, iso(now()), limit)
    for row in rows:
        try:
            await run_row(app, row)
        except AppError:
            pass  # recorded on the row and in the audit log
    return len(rows)

