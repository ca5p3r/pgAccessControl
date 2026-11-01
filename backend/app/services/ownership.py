"""Who owns what: browse object owners, hand objects to another role, and move everything one role owns.

Ownership matters because an owner can always re-grant, alter and drop its object, whatever the ACL says, and
because a role that still owns objects cannot be dropped. Reads are set-based like the rest of the app (one
paginated catalog query per page). Changes run in a single transaction: either every object is handed over or
none is.

PostgreSQL facts this module relies on (verified against a live server):

* ``ALTER TABLE ... OWNER TO`` also moves the table's indexes and the sequences owned by its columns, and
  refuses to move such a sequence on its own. Those sequences are therefore reported, never altered directly.
* ``ALTER TYPE ... OWNER TO`` works for domains too.
* ``REASSIGN OWNED`` also hands over *databases* and tablespaces owned by the role, whichever database it runs in.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg import sql

from ..audit import note, record_statement
from ..db import PoolManager
from ..errors import AppError, NotFound
from ..schemas import OwnerFilter, OwnerItem
from . import roles as roles_svc
from .permissions import _SYSTEM_SCHEMA, _kind_label, _like, is_public

Conn = psycopg.AsyncConnection

MAX_EXPAND = 5000  # objects one "change everything matching this filter" request may touch


def _ext(catalog: str, oid: str) -> str:
    """Name of the extension an object belongs to (those objects must stay with the extension's owner)."""
    return (
        "(SELECT e.extname FROM pg_depend d JOIN pg_extension e ON e.oid = d.refobjid "
        f"WHERE d.classid = '{catalog}'::regclass AND d.objid = {oid} AND d.deptype = 'e' LIMIT 1)"
    )


_SEQ_LINK = (
    "FROM pg_depend d JOIN pg_class t ON t.oid = d.refobjid JOIN pg_namespace tn ON tn.oid = t.relnamespace"
    " WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.refclassid = 'pg_class'::regclass"
    " AND d.deptype IN ('a', 'i') LIMIT 1"
)
_SEQ_TABLE = f"(SELECT quote_ident(tn.nspname) || '.' || quote_ident(t.relname) {_SEQ_LINK})"
_SEQ_TABLE_OID = f"(SELECT t.oid {_SEQ_LINK})"

# Per object type: columns (oid, schema, name, kind, owner, args, extension, linked_to), source and filters.
_CFG: dict[str, dict[str, str]] = {
    "table": {
        "cols": "c.oid, n.nspname AS schema, c.relname AS name, c.relkind::text AS kind, pg_get_userbyid(c.relowner) AS owner,"
        f" '' AS args, {_ext('pg_class', 'c.oid')} AS extension, NULL::text AS linked_to, NULL::oid AS linked_oid",
        "frm": "pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
        "where": "c.relkind IN ('r', 'p', 'v', 'm', 'f')",
        "oid": "c.oid", "owner": "c.relowner", "schema": "n.nspname", "name": "c.relname", "order": "n.nspname, c.relname",
    },
    "sequence": {
        "cols": "c.oid, n.nspname AS schema, c.relname AS name, 'S' AS kind, pg_get_userbyid(c.relowner) AS owner,"
        f" '' AS args, {_ext('pg_class', 'c.oid')} AS extension, {_SEQ_TABLE} AS linked_to, {_SEQ_TABLE_OID} AS linked_oid",
        "frm": "pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
        "where": "c.relkind = 'S'",
        "oid": "c.oid", "owner": "c.relowner", "schema": "n.nspname", "name": "c.relname", "order": "n.nspname, c.relname",
    },
    "function": {
        "cols": "p.oid, n.nspname AS schema, p.proname AS name, p.prokind::text AS kind, pg_get_userbyid(p.proowner) AS owner,"
        f" pg_get_function_identity_arguments(p.oid) AS args, {_ext('pg_proc', 'p.oid')} AS extension, NULL::text AS linked_to, NULL::oid AS linked_oid",
        "frm": "pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace",
        "where": "p.prokind IN ('f', 'p')",
        "oid": "p.oid", "owner": "p.proowner", "schema": "n.nspname", "name": "p.proname", "order": "n.nspname, p.proname, 6",
    },
    "type": {
        "cols": "t.oid, n.nspname AS schema, t.typname AS name,"
        " CASE t.typtype WHEN 'e' THEN 'enum' WHEN 'd' THEN 'domain' WHEN 'r' THEN 'range' WHEN 'm' THEN 'multirange'"
        " ELSE 'composite' END AS kind, pg_get_userbyid(t.typowner) AS owner,"
        f" '' AS args, {_ext('pg_type', 't.oid')} AS extension, NULL::text AS linked_to, NULL::oid AS linked_oid",
        "frm": "pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace LEFT JOIN pg_class c ON c.oid = t.typrelid",
        "where": "(t.typtype IN ('e', 'd', 'r', 'm') OR (t.typtype = 'c' AND c.relkind = 'c'))",
        "oid": "t.oid", "owner": "t.typowner", "schema": "n.nspname", "name": "t.typname", "order": "n.nspname, t.typname",
    },
    "schema": {
        "cols": "n.oid, n.nspname AS schema, n.nspname AS name, 'n' AS kind, pg_get_userbyid(n.nspowner) AS owner,"
        f" '' AS args, {_ext('pg_namespace', 'n.oid')} AS extension, NULL::text AS linked_to, NULL::oid AS linked_oid",
        "frm": "pg_namespace n",
        "where": "TRUE",
        "oid": "n.oid", "owner": "n.nspowner", "schema": "n.nspname", "name": "n.nspname", "order": "n.nspname",
    },
    "database": {
        "cols": "d.oid, '' AS schema, d.datname AS name, 'd' AS kind, pg_get_userbyid(d.datdba) AS owner,"
        " '' AS args, NULL::text AS extension, NULL::text AS linked_to, NULL::oid AS linked_oid",
        "frm": "pg_database d",
        "where": "NOT d.datistemplate",
        "oid": "d.oid", "owner": "d.datdba", "schema": "''", "name": "d.datname", "order": "d.datname",
    },
}


def _item(object_type: str, r: dict[str, Any]) -> dict[str, Any]:
    return {
        "oid": r["oid"], "type": object_type, "schema": r["schema"], "name": r["name"],
        "kind": r["kind"] if object_type == "type" else _kind_label(object_type, r["kind"]),
        "owner": r["owner"], "args": r["args"], "extension": r["extension"], "linked_to": r["linked_to"],
        "linked_oid": r["linked_oid"],
    }


def _where(cfg: dict[str, str], object_type: str, f: OwnerFilter) -> tuple[str, dict[str, Any]]:
    where, params = [cfg["where"]], {}
    if object_type not in ("database",) and not f.include_system:
        where.append(_SYSTEM_SCHEMA.format(col=cfg["schema"]))
    if f.schema_name and object_type in ("table", "sequence", "function", "type"):
        where.append(f"{cfg['schema']} = %(schema)s")
        params["schema"] = f.schema_name
    if f.owner:
        where.append(f"{cfg['owner']} = (SELECT oid FROM pg_roles WHERE rolname = %(owner)s)")
        params["owner"] = f.owner
    if f.q:  # "sales.ord" finds sales.orders: schema-bearing objects are matched on their qualified name
        subject = f"({cfg['schema']} || '.' || {cfg['name']})" if object_type not in ("database", "schema") else cfg["name"]
        where.append(f"{subject} ILIKE %(q)s")
        params["q"] = _like(f.q)
    return " AND ".join(where), params


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
async def list_objects(conn: Conn, f: OwnerFilter, *, limit: int, offset: int) -> dict[str, Any]:
    cfg = _CFG[f.object_type]
    where, params = _where(cfg, f.object_type, f)
    cur = await conn.execute(
        f"""SELECT {cfg['cols']}, count(*) OVER () AS total FROM {cfg['frm']}
             WHERE {where} ORDER BY {cfg['order']} LIMIT %(limit)s OFFSET %(offset)s""",
        {**params, "limit": limit, "offset": offset},
    )
    rows = await cur.fetchall()
    total = rows[0]["total"] if rows else 0
    if not rows and offset:  # paged past the end: still report the real total
        cur = await conn.execute(f"SELECT count(*) AS n FROM {cfg['frm']} WHERE {where}", params)
        total = (await cur.fetchone())["n"]
    return {"items": [_item(f.object_type, r) for r in rows], "total": total}


async def summary(conn: Conn, include_system: bool = False) -> dict[str, Any]:
    """Who owns how many objects of each type in this database (databases are server-wide)."""
    parts = []
    for t in ("table", "sequence", "function", "type", "schema"):
        cfg = _CFG[t]
        where = cfg["where"] + ("" if include_system else " AND " + _SYSTEM_SCHEMA.format(col=cfg["schema"]))
        parts.append(f"SELECT {cfg['owner']} AS owner, '{t}' AS kind FROM {cfg['frm']} WHERE {where}")
    d = _CFG["database"]
    parts.append(f"SELECT {d['owner']}, 'database' FROM {d['frm']} WHERE {d['where']}")
    cur = await conn.execute(
        f"""SELECT r.rolname AS owner, r.rolcanlogin AS login, r.rolsuper AS superuser, o.kind, count(*)::int AS n
              FROM ({' UNION ALL '.join(parts)}) o JOIN pg_roles r ON r.oid = o.owner
             GROUP BY 1, 2, 3, 4 ORDER BY 1"""
    )
    owners: dict[str, dict[str, Any]] = {}
    for r in await cur.fetchall():
        o = owners.setdefault(
            r["owner"], {"owner": r["owner"], "kind": "user" if r["login"] else "role", "superuser": r["superuser"], "counts": {}, "total": 0}
        )
        o["counts"][r["kind"]] = r["n"]
        o["total"] += r["n"]
    return {"owners": sorted(owners.values(), key=lambda o: (-o["total"], o["owner"]))}


# ---------------------------------------------------------------------------
# Changing the owner of selected objects
# ---------------------------------------------------------------------------
def guard_new_owner(name: str) -> None:
    if is_public(name):
        raise AppError("PUBLIC cannot own objects.")
    if name.startswith("pg_"):
        raise AppError(f'"{name}" is a predefined PostgreSQL role and cannot own objects.')


async def resolve(conn: Conn, items: list[OwnerItem] | None, f: OwnerFilter | None) -> list[dict[str, Any]]:
    """The objects a request is about, read fresh from the catalog (so names, kinds and owners are current)."""
    found: list[dict[str, Any]] = []
    if items:
        by_type: dict[str, list[int]] = {}
        for i in items:
            by_type.setdefault(i.object_type, []).append(i.oid)
        for t, oids in by_type.items():
            cfg = _CFG[t]
            cur = await conn.execute(
                f"SELECT {cfg['cols']} FROM {cfg['frm']} WHERE {cfg['where']} AND {cfg['oid']} = ANY(%(oids)s) ORDER BY {cfg['order']}",
                {"oids": list(set(oids))},
            )
            rows = await cur.fetchall()
            if len(rows) != len(set(oids)):
                gone = len(set(oids)) - len(rows)
                raise NotFound(f"{gone} of the selected {t} object{'s' if gone != 1 else ''} no longer exist. Refresh the list and try again.")
            found += [_item(t, r) for r in rows]
    else:
        assert f is not None
        cfg = _CFG[f.object_type]
        where, params = _where(cfg, f.object_type, f)
        cur = await conn.execute(
            f"SELECT {cfg['cols']} FROM {cfg['frm']} WHERE {where} ORDER BY {cfg['order']} LIMIT %(cap)s", {**params, "cap": MAX_EXPAND + 1}
        )
        rows = await cur.fetchall()
        if len(rows) > MAX_EXPAND:
            raise AppError(f"More than {MAX_EXPAND:,} objects match. Narrow the filter (schema, current owner or name) and try again.")
        found = [_item(f.object_type, r) for r in rows]
    return found


def _alter(o: dict[str, Any], new_owner: str) -> sql.Composable:
    owner = sql.Identifier(new_owner)
    t, kind = o["type"], o["kind"]
    qualified = sql.SQL("{}.{}").format(sql.Identifier(o["schema"]), sql.Identifier(o["name"]))
    if t == "database":
        target = sql.SQL("DATABASE {}").format(sql.Identifier(o["name"]))
    elif t == "schema":
        target = sql.SQL("SCHEMA {}").format(sql.Identifier(o["name"]))
    elif t == "table":
        word = {"view": "VIEW", "matview": "MATERIALIZED VIEW", "foreign": "FOREIGN TABLE"}.get(kind, "TABLE")
        target = sql.SQL("{} {}").format(sql.SQL(word), qualified)
    elif t == "sequence":
        target = sql.SQL("SEQUENCE {}").format(qualified)
    elif t == "function":
        # ROUTINE covers functions and procedures; the argument list comes from the catalog, never from the client.
        target = sql.SQL("ROUTINE {}.{}({})").format(sql.Identifier(o["schema"]), sql.Identifier(o["name"]), sql.SQL(o["args"]))
    else:
        target = sql.SQL("TYPE {}").format(qualified)
    return sql.SQL("ALTER {} OWNER TO {}").format(target, owner)


def describe(o: dict[str, Any]) -> str:
    if o["type"] in ("database", "schema"):
        return f"{o['type']} {o['name']}"
    args = f"({o['args']})" if o["type"] == "function" else ""
    word = o["kind"] if o["kind"] != o["type"] else o["type"]
    return f"{word} {o['schema']}.{o['name']}{args}"


async def plan_change(conn: Conn, new_owner: str, objects: list[dict[str, Any]]) -> dict[str, Any]:
    """Split the objects into those to alter and those to leave alone, and say why."""
    guard_new_owner(new_owner)
    if not await roles_svc.role_exists(conn, new_owner):
        raise NotFound(f'Role "{new_owner}" does not exist')
    selected_tables = {o["oid"] for o in objects if o["type"] == "table"}
    change, skipped = [], []
    for o in objects:
        label = describe(o)
        if o["owner"] == new_owner:
            skipped.append({"object": label, "reason": "already owned by " + new_owner})
        elif o["extension"]:
            skipped.append({"object": label, "reason": f"belongs to extension {o['extension']}"})
        elif o["linked_to"]:
            how = "changes together with its table" if o["linked_oid"] in selected_tables else "follows its table; change the table's owner instead"
            skipped.append({"object": label, "reason": f"sequence owned by {o['linked_to']}: {how}"})
        else:
            change.append(o)
    return {"change": change, "skipped": skipped, "statements": [_alter(o, new_owner) for o in change]}


async def change_owner(conn: Conn, plan: dict[str, Any], *, dry_run: bool) -> list[str]:
    rendered = [s.as_string(conn).strip() + ";" for s in plan["statements"]]
    if not dry_run:
        for stmt in plan["statements"]:
            record_statement(stmt, conn)  # recorded before running so a failed attempt still shows what was tried
            await conn.execute(stmt)
    return rendered


# ---------------------------------------------------------------------------
# Handing over everything a role owns
# ---------------------------------------------------------------------------
async def plan_reassign(pools: PoolManager, source: str, target: str, database: str | None) -> dict[str, Any]:
    guard_new_owner(target)
    if source == target:
        raise AppError("Choose two different roles.")
    if source.startswith("pg_"):
        raise AppError(f'"{source}" is a predefined PostgreSQL role.')
    async with pools.connection() as conn:
        for r in (source, target):
            if not await roles_svc.role_exists(conn, r):
                raise NotFound(f'Role "{r}" does not exist')
        report = await roles_svc.get_dependencies(conn, source)
    places: dict[str, int] = {}
    for d in report.dependencies:
        if d.owned_objects:  # shared objects (databases, tablespaces) are handled from the maintenance database
            key = d.database or pools.default_database
            places[key] = places.get(key, 0) + d.owned_objects
    if database is not None:
        # Whichever database it runs in, REASSIGN OWNED also moves databases and tablespaces owned by the role.
        places = {database: places.get(database, 0)}
    return {"places": places}


async def reassign(pools: PoolManager, source: str, target: str, databases: list[str], *, dry_run: bool) -> list[str]:
    statement = sql.SQL("REASSIGN OWNED BY {} TO {}").format(sql.Identifier(source), sql.Identifier(target))
    done: list[str] = []
    rendered: list[str] = []
    for dbname in databases:
        try:
            async with pools.connection(dbname) as conn:
                rendered.append(f"-- in database {dbname}\n{statement.as_string(conn)};")
                if dry_run:
                    continue
                note(f'in database "{dbname}"')
                record_statement(statement, conn)
                await conn.execute(statement)
                done.append(dbname)
        except psycopg.Error as exc:
            hint = f" Already handed over: {', '.join(done)}." if done else ""
            raise AppError(f'Reassigning in database "{dbname}" failed: {exc.diag.message_primary or exc}.{hint}', 409) from exc
    return rendered
