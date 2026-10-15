"""Permission snapshots and drift detection.

A snapshot is the complete access configuration of one database (roles, memberships, explicit privileges,
default privileges) at a point in time. Comparing a snapshot with the live server (or with another snapshot)
shows exactly what was added, removed or changed since - whoever did it and with whatever tool, including
direct ``psql`` changes the audit history cannot see.

Passwords are never part of a snapshot (they cannot be read, and are not compared).
"""

from __future__ import annotations

import gzip
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg

from ..audit import audited_system
from ..errors import NotFound
from . import expiring
from . import reports as rep

ROLE_FIELDS = ["login", "superuser", "inherit", "createrole", "createdb", "replication", "bypassrls", "connection_limit", "valid_until", "comment"]
SECTIONS = ("roles", "memberships", "privileges", "defaults")


# ---------------------------------------------------------------------------
# Capture & normalise
# ---------------------------------------------------------------------------
def normalise(data: dict[str, Any]) -> dict[str, Any]:
    """JSON-safe, order-stable form of ``export_data`` output (datetimes in UTC, grantor ignored)."""

    def fix(row: dict[str, Any]) -> dict[str, Any]:
        out = {}
        for k, v in row.items():
            out[k] = v.astimezone(timezone.utc).isoformat(timespec="seconds") if isinstance(v, datetime) else v
        return out

    privileges = [{k: v for k, v in fix(r).items() if k != "grantor"} for r in data["privileges"]]
    return {
        "captured_at": data["generated_at"],
        "server_version": data["server_version"],
        "database": data["database"],
        "roles": [fix(r) for r in data["roles"]],
        "memberships": [fix(r) for r in data["memberships"]],
        "privileges": privileges,
        "defaults": [fix(r) for r in data["default_privileges"]],
    }


async def capture(conn: psycopg.AsyncConnection) -> dict[str, Any]:
    return normalise(await rep.export_data(conn, None))


def pack(data: dict[str, Any]) -> bytes:
    return gzip.compress(json.dumps(data, separators=(",", ":")).encode(), compresslevel=6)


def unpack(blob: bytes) -> dict[str, Any]:
    return json.loads(gzip.decompress(blob))


def counts(data: dict[str, Any]) -> dict[str, int]:
    return {k: len(data[k]) for k in SECTIONS}


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------
_KEYS = {
    "roles": lambda r: (r["name"],),
    "memberships": lambda r: (r["role"], r["member"]),
    "privileges": lambda r: (r["object_type"], r["schema"], r["name"], r["args"], r["col"], r["grantee"], r["privilege"]),
    "defaults": lambda r: (r["for_role"], r["schema"], r["object_type"], r["grantee"], r["privilege"]),
}
_VALUE_FIELDS = {
    "roles": ROLE_FIELDS,
    "memberships": ["admin_option"],
    "privileges": ["grantable"],
    "defaults": ["grantable"],
}


def compare(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """What differs going from ``old`` to ``new``. ``added`` = present now but not before."""
    out: dict[str, Any] = {}
    total = 0
    for sec in SECTIONS:
        key, fields = _KEYS[sec], _VALUE_FIELDS[sec]
        a = {key(r): r for r in old[sec]}
        b = {key(r): r for r in new[sec]}
        added = [b[k] for k in sorted(b.keys() - a.keys(), key=str)]
        removed = [a[k] for k in sorted(a.keys() - b.keys(), key=str)]
        changed = []
        for k in sorted(a.keys() & b.keys(), key=str):
            diff = {f: [a[k].get(f), b[k].get(f)] for f in fields if a[k].get(f) != b[k].get(f)}
            if diff:
                changed.append({"item": b[k], "changes": diff})
        out[sec] = {"added": added, "removed": removed, "changed": changed}
        total += len(added) + len(removed) + len(changed)
    out["total"] = total
    out["summary"] = {sec: {k: len(out[sec][k]) for k in ("added", "removed", "changed")} for sec in SECTIONS}
    out["digest"] = hashlib.sha256(
        json.dumps({sec: [[str(_KEYS[sec](r)) for r in out[sec]["added"]], [str(_KEYS[sec](r)) for r in out[sec]["removed"]],
                          [[str(_KEYS[sec](c["item"])), c["changes"]] for c in out[sec]["changed"]]] for sec in SECTIONS},
                   sort_keys=True, default=str).encode()
    ).hexdigest()[:16]
    return out


def capped(diff: dict[str, Any], limit: int) -> dict[str, Any]:
    """Limit the lists returned to the UI (counts stay exact)."""
    res = {k: v for k, v in diff.items()}
    truncated = False
    for sec in SECTIONS:
        res[sec] = {}
        for k in ("added", "removed", "changed"):
            items = diff[sec][k]
            res[sec][k] = items[:limit]
            truncated = truncated or len(items) > limit
    res["truncated"] = truncated
    return res


# ---------------------------------------------------------------------------
# Remediation SQL: what to run to bring the live server back to the old state
# ---------------------------------------------------------------------------
def _priv_stmt(conn: psycopg.AsyncConnection, row: dict[str, Any], *, grant: bool, option_only: bool = False) -> str:
    q, grantee = rep._q, rep._grantee(conn, row["grantee"])
    if row["object_type"] == "column":
        priv = f"{row['privilege']} ({q(conn, row['col'])})"
        target = f"TABLE {q(conn, row['schema'])}.{q(conn, row['name'])}"
    else:
        priv = row["privilege"]
        target = rep._target(conn, row)
    if grant:
        return f"GRANT {priv} ON {target} TO {grantee}{' WITH GRANT OPTION' if row.get('grantable') else ''};"
    return f"REVOKE {'GRANT OPTION FOR ' if option_only else ''}{priv} ON {target} FROM {grantee};"


def remediation(conn: psycopg.AsyncConnection, diff: dict[str, Any], database: str) -> Iterator[str]:
    q, lit = rep._q, rep._lit
    yield (f"-- Remediation: restores the state of the baseline snapshot in database {q(conn, database)}.\n"
           "-- Review before running. Nothing here is executed automatically.\n")
    r = diff["roles"]
    if r["removed"] or r["changed"]:
        yield "\n-- Roles\n"
        for role in r["removed"]:
            opts = [
                "LOGIN" if role["login"] else "NOLOGIN", "SUPERUSER" if role["superuser"] else "NOSUPERUSER",
                "CREATEDB" if role["createdb"] else "NOCREATEDB", "CREATEROLE" if role["createrole"] else "NOCREATEROLE",
                "INHERIT" if role["inherit"] else "NOINHERIT", "REPLICATION" if role["replication"] else "NOREPLICATION",
                "BYPASSRLS" if role["bypassrls"] else "NOBYPASSRLS", f"CONNECTION LIMIT {int(role['connection_limit'])}",
            ]
            yield f"CREATE ROLE {q(conn, role['name'])} WITH {' '.join(opts)};  -- the password cannot be restored\n"
        for c in r["changed"]:
            name, ch = c["item"]["name"], c["changes"]
            flag = {"login": ("LOGIN", "NOLOGIN"), "superuser": ("SUPERUSER", "NOSUPERUSER"), "inherit": ("INHERIT", "NOINHERIT"),
                    "createrole": ("CREATEROLE", "NOCREATEROLE"), "createdb": ("CREATEDB", "NOCREATEDB"),
                    "replication": ("REPLICATION", "NOREPLICATION"), "bypassrls": ("BYPASSRLS", "NOBYPASSRLS")}
            opts = [flag[f][0] if old else flag[f][1] for f, (old, _new) in ch.items() if f in flag]
            if "connection_limit" in ch:
                opts.append(f"CONNECTION LIMIT {int(ch['connection_limit'][0])}")
            if "valid_until" in ch:
                opts.append(f"VALID UNTIL {lit(conn, ch['valid_until'][0] or 'infinity')}")
            if opts:
                yield f"ALTER ROLE {q(conn, name)} WITH {' '.join(opts)};\n"
            if "comment" in ch:
                old_comment = ch["comment"][0]
                yield f"COMMENT ON ROLE {q(conn, name)} IS {lit(conn, old_comment) if old_comment else 'NULL'};\n"
    m = diff["memberships"]
    if m["removed"] or m["changed"] or m["added"]:
        yield "\n-- Role memberships\n"
        for x in m["removed"]:
            yield f"GRANT {q(conn, x['role'])} TO {q(conn, x['member'])}{' WITH ADMIN OPTION' if x['admin_option'] else ''};\n"
        for c in m["changed"]:
            x, was = c["item"], c["changes"]["admin_option"][0]
            yield (f"GRANT {q(conn, x['role'])} TO {q(conn, x['member'])} WITH ADMIN OPTION;\n" if was
                   else f"REVOKE ADMIN OPTION FOR {q(conn, x['role'])} FROM {q(conn, x['member'])};\n")
        for x in m["added"]:
            yield f"REVOKE {q(conn, x['role'])} FROM {q(conn, x['member'])};\n"
    p = diff["privileges"]
    if p["removed"] or p["changed"] or p["added"]:
        yield "\n-- Privileges\n"
        for x in p["removed"]:
            yield _priv_stmt(conn, x, grant=True) + "\n"
        for c in p["changed"]:
            was = c["changes"]["grantable"][0]
            yield (_priv_stmt(conn, {**c["item"], "grantable": True}, grant=True) if was else _priv_stmt(conn, c["item"], grant=False, option_only=True)) + "\n"
        for x in p["added"]:
            yield _priv_stmt(conn, x, grant=False) + "\n"
    d = diff["defaults"]
    if d["removed"] or d["added"] or d["changed"]:
        yield "\n-- Default privileges\n"

        def default_stmt(x: dict[str, Any], grant: bool, option_only: bool = False) -> str:
            scope = f" IN SCHEMA {q(conn, x['schema'])}" if x["schema"] else ""
            kind = x["object_type"].upper()
            head = f"ALTER DEFAULT PRIVILEGES FOR ROLE {q(conn, x['for_role'])}{scope}"
            who = rep._grantee(conn, x["grantee"])
            if grant:
                return f"{head} GRANT {x['privilege']} ON {kind} TO {who}{' WITH GRANT OPTION' if x.get('grantable') else ''};\n"
            return f"{head} REVOKE {'GRANT OPTION FOR ' if option_only else ''}{x['privilege']} ON {kind} FROM {who};\n"

        for x in d["removed"]:
            yield default_stmt(x, True)
        for c in d["changed"]:
            was = c["changes"]["grantable"][0]
            yield default_stmt({**c["item"], "grantable": True}, True) if was else default_stmt(c["item"], False, True)
        for x in d["added"]:
            yield default_stmt(x, False)
    if r["added"]:
        yield "\n-- Roles that did not exist in the baseline (NOT removed automatically: dropping a role is destructive)\n"
        for role in r["added"]:
            yield f"-- DROP ROLE {q(conn, role['name'])};\n"
    if diff["total"] == 0:
        yield "\n-- No differences: nothing to do.\n"


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------
def _meta(r: sqlite3.Row) -> dict[str, Any]:
    d = {k: r[k] for k in ("id", "server_id", "name", "note", "database", "created_at", "created_by")}
    d["baseline"] = bool(r["baseline"])
    d["counts"] = json.loads(r["counts"])
    d["last_check"] = json.loads(r["last_check"]) if r["last_check"] else None
    return d


def db_list(c: sqlite3.Connection, server_id: str | None = None) -> list[dict[str, Any]]:
    if server_id:
        rows = c.execute("SELECT * FROM snapshots WHERE server_id = ? ORDER BY created_at DESC, id DESC", (server_id,))
    else:
        rows = c.execute("SELECT * FROM snapshots ORDER BY created_at DESC, id DESC")
    return [_meta(r) for r in rows]


def db_get(c: sqlite3.Connection, snapshot_id: int) -> tuple[dict[str, Any], dict[str, Any]] | None:
    r = c.execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    return (_meta(r), unpack(r["data"])) if r else None


def db_insert(c: sqlite3.Connection, server_id: str, name: str, note: str | None, database: str, created_by: str, baseline: bool, data: dict[str, Any]) -> int:
    if baseline:
        c.execute("UPDATE snapshots SET baseline = 0 WHERE server_id = ? AND database = ?", (server_id, database))
    cur = c.execute(
        "INSERT INTO snapshots (server_id, name, note, database, created_at, created_by, baseline, counts, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (server_id, name, note, database, expiring.iso(expiring.now()), created_by, int(baseline), json.dumps(counts(data)), pack(data)),
    )
    return int(cur.lastrowid)


def db_delete(c: sqlite3.Connection, snapshot_id: int) -> bool:
    return c.execute("DELETE FROM snapshots WHERE id = ?", (snapshot_id,)).rowcount > 0


def db_set_baseline(c: sqlite3.Connection, snapshot_id: int, baseline: bool) -> bool:
    r = c.execute("SELECT database, server_id FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
    if r is None:
        return False
    if baseline:
        c.execute("UPDATE snapshots SET baseline = 0 WHERE server_id = ? AND database = ?", (r["server_id"], r["database"]))
    c.execute("UPDATE snapshots SET baseline = ?, last_check = NULL WHERE id = ?", (int(baseline), snapshot_id))
    return True


def db_set_last_check(c: sqlite3.Connection, snapshot_id: int, summary: dict[str, Any]) -> None:
    c.execute("UPDATE snapshots SET last_check = ? WHERE id = ?", (json.dumps(summary), snapshot_id))


async def load(app: Any, snapshot_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
    got = await app.state.store.run(db_get, snapshot_id)
    if got is None:
        raise NotFound(f"Snapshot {snapshot_id} does not exist")
    return got


# ---------------------------------------------------------------------------
# Scheduled drift checks
# ---------------------------------------------------------------------------
async def check_baselines(app: Any) -> int:
    """Compare every baseline snapshot with the live server; record a change in the audit history once."""
    snaps = [s for s in await app.state.store.run(db_list) if s["baseline"]]
    reported = 0
    for meta in snaps:
        profile = await app.state.servers.get(meta["server_id"])
        if profile is None or profile.disabled:
            continue
        try:
            _, old = await load(app, meta["id"])
            pools = await app.state.servers.manager(profile)
            async with pools.connection(meta["database"]) as conn:
                live = await capture(conn)
            diff = compare(old, live)
        except Exception:  # noqa: BLE001 - an unreachable server or database must not stop the other checks
            continue
        last = meta["last_check"] or {}
        if diff["total"] and last.get("digest") != diff["digest"]:
            async with audited_system(app.state.audit, "drift.detected", target=meta["name"], target_type="snapshot", database=meta["database"], server=profile) as a:
                s = diff["summary"]
                a.summary = f"{diff['total']} difference{'' if diff['total'] == 1 else 's'} from baseline “{meta['name']}” in {meta['database']}"
                a.details = {"snapshot_id": meta["id"], "summary": s}
            reported += 1
        elif not diff["total"] and last.get("total"):
            async with audited_system(app.state.audit, "drift.cleared", target=meta["name"], target_type="snapshot", database=meta["database"], server=profile) as a:
                a.summary = f"Permissions match baseline “{meta['name']}” again in {meta['database']}"
        await app.state.store.run(db_set_last_check, meta["id"], {"at": expiring.iso(expiring.now()), "total": diff["total"], "digest": diff["digest"]})
    return reported
