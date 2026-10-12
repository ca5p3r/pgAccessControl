"""Reading and changing privileges on databases, schemas, tables, sequences and functions.

Reads are set-based: ACLs are expanded with ``aclexplode`` inside a single paginated query, so the
cost is one round trip per page regardless of how many objects or privileges there are. Objects with
no explicit ACL fall back to ``acldefault`` (the implicit owner privileges).

"Deny" does not exist in PostgreSQL; access is removed with REVOKE. Effective access is the union of
direct grants, grants to PUBLIC and grants to every role the role inherits from.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg import sql

from ..audit import add_statements
from ..errors import AppError, NotFound
from ..schemas import PermissionChange

Conn = psycopg.AsyncConnection

PUBLIC = "PUBLIC"


def is_public(role: str) -> bool:
    return role.upper() == PUBLIC


def privilege_catalog(server_version: int) -> dict[str, list[str]]:
    table = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"]
    if server_version >= 170000:
        table.append("MAINTAIN")
    return {
        "database": ["CONNECT", "CREATE", "TEMPORARY"],
        "schema": ["USAGE", "CREATE"],
        "table": table,
        "sequence": ["USAGE", "SELECT", "UPDATE"],
        "function": ["EXECUTE"],
    }


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
_SYSTEM_SCHEMA = "{col} NOT IN ('pg_catalog', 'information_schema') AND {col} !~ '^pg_(toast|temp)'"

_RELKIND = {"r": "table", "p": "partitioned", "v": "view", "m": "matview", "f": "foreign"}
_PROKIND = {"f": "function", "p": "procedure"}


def _kind_label(object_type: str, code: str) -> str:
    if object_type == "table":
        return _RELKIND.get(code, code)
    if object_type == "function":
        return _PROKIND.get(code, code)
    return object_type

# Per object type: how to select and ACL-expand the catalog rows.
_KINDS: dict[str, dict[str, str]] = {
    "table": {
        "cols": "c.oid, n.nspname AS schema, c.relname AS name, c.relkind::text AS kind,"
        " pg_get_userbyid(c.relowner) AS owner, '' AS args",
        "frm": "pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
        "where": "c.relkind IN ('r', 'p', 'v', 'm', 'f')",
        "schema_col": "n.nspname",
        "name_col": "c.relname",
        "acl": "COALESCE(c.relacl, acldefault('r', c.relowner))",
        "order": "n.nspname, c.relname",
    },
    "sequence": {
        "cols": "c.oid, n.nspname AS schema, c.relname AS name, 'S' AS kind,"
        " pg_get_userbyid(c.relowner) AS owner, '' AS args",
        "frm": "pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
        "where": "c.relkind = 'S'",
        "schema_col": "n.nspname",
        "name_col": "c.relname",
        "acl": "COALESCE(c.relacl, acldefault('s', c.relowner))",
        "order": "n.nspname, c.relname",
    },
    "function": {
        "cols": "p.oid, n.nspname AS schema, p.proname AS name, p.prokind::text AS kind,"
        " pg_get_userbyid(p.proowner) AS owner, pg_get_function_identity_arguments(p.oid) AS args",
        "frm": "pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace",
        "where": "p.prokind IN ('f', 'p')",
        "schema_col": "n.nspname",
        "name_col": "p.proname",
        "acl": "COALESCE(p.proacl, acldefault('f', p.proowner))",
        "order": "n.nspname, p.proname, 6",
    },
    "schema": {
        "cols": "n.oid, n.nspname AS schema, n.nspname AS name, 'n' AS kind,"
        " pg_get_userbyid(n.nspowner) AS owner, '' AS args",
        "frm": "pg_namespace n",
        "where": "TRUE",
        "schema_col": "n.nspname",
        "name_col": "n.nspname",
        "acl": "COALESCE(n.nspacl, acldefault('n', n.nspowner))",
        "order": "n.nspname",
    },
    "database": {
        "cols": "d.oid, '' AS schema, d.datname AS name, 'd' AS kind,"
        " pg_get_userbyid(d.datdba) AS owner, '' AS args",
        "frm": "pg_database d",
        "where": "NOT d.datistemplate",
        "schema_col": "''",
        "name_col": "d.datname",
        "acl": "COALESCE(d.datacl, acldefault('d', d.datdba))",
        "order": "d.datname",
    },
}


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


async def get_role_flags(conn: Conn, role: str) -> dict[str, Any]:
    if is_public(role):
        return {"is_public": True, "superuser": False, "login": False}
    cur = await conn.execute("SELECT rolsuper, rolcanlogin FROM pg_roles WHERE rolname = %s", (role,))
    row = await cur.fetchone()
    if row is None:
        raise NotFound(f'Role "{role}" does not exist')
    return {"is_public": False, "superuser": row["rolsuper"], "login": row["rolcanlogin"]}


async def list_objects(
    conn: Conn,
    role: str,
    object_type: str,
    *,
    schema: str | None,
    q: str | None,
    granted_only: bool,
    include_system: bool,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    cfg = _KINDS[object_type]
    flags = await get_role_flags(conn, role)

    # Which ACL entries are relevant to this role: its own, PUBLIC's and any inherited role's.
    if flags["is_public"]:
        grantee_filter = "a.grantee = 0"
    else:
        grantee_filter = "(a.grantee = 0 OR pg_has_role(%(role)s::name, a.grantee, 'USAGE'))"

    params: dict[str, Any] = {"role": role, "limit": limit, "offset": offset}
    where = [cfg["where"]]
    if object_type in ("table", "sequence", "function", "schema") and not include_system:
        where.append(_SYSTEM_SCHEMA.format(col=cfg["schema_col"]))
    if schema and object_type in ("table", "sequence", "function"):
        where.append(f"{cfg['schema_col']} = %(schema)s")
        params["schema"] = schema
    if q:
        where.append(f"{cfg['name_col']} ILIKE %(q)s")
        params["q"] = _like(q)
    if granted_only:
        where.append(f"EXISTS (SELECT 1 FROM aclexplode({cfg['acl']}) a WHERE {grantee_filter})")

    query = f"""
        WITH base AS (
            SELECT {cfg['cols']}, {cfg['acl']} AS acl, count(*) OVER () AS total
              FROM {cfg['frm']}
             WHERE {' AND '.join(where)}
             ORDER BY {cfg['order']}
             LIMIT %(limit)s OFFSET %(offset)s
        )
        SELECT b.oid, b.schema, b.name, b.kind, b.owner, b.args, b.total,
               COALESCE((
                   SELECT jsonb_agg(jsonb_build_object(
                              'g', CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                              'p', a.privilege_type,
                              'o', a.is_grantable))
                     FROM aclexplode(b.acl) a
                    WHERE {grantee_filter}
               ), '[]'::jsonb) AS grants
          FROM base b
    """
    cur = await conn.execute(query, params)
    rows = await cur.fetchall()

    items = []
    for r in rows:
        direct: list[str] = []
        grantable: list[str] = []
        inherited: dict[str, list[str]] = {}
        for g in r["grants"]:
            if g["g"] == role or (flags["is_public"] and g["g"] == PUBLIC):
                direct.append(g["p"])
                if g["o"]:
                    grantable.append(g["p"])
            else:
                inherited.setdefault(g["p"], []).append(g["g"])
        items.append(
            {
                "oid": r["oid"],
                "schema": r["schema"],
                "name": r["name"],
                "kind": _kind_label(object_type, r["kind"]),
                "owner": r["owner"],
                "args": r["args"],
                "direct": sorted(direct),
                "grantable": sorted(grantable),
                "inherited": inherited,
            }
        )
    total = rows[0]["total"] if rows else 0
    if not rows and offset:
        # Page past the end: still report the real total.
        cur = await conn.execute(
            f"SELECT count(*) AS n FROM {cfg['frm']} WHERE {' AND '.join(where)}", params
        )
        total = (await cur.fetchone())["n"]
    return {
        "items": items,
        "total": total,
        "role_superuser": flags["superuser"],
        "privileges": privilege_catalog(conn.info.server_version)[object_type],
    }


async def list_schemas(conn: Conn, include_system: bool = False) -> list[str]:
    where = "TRUE" if include_system else _SYSTEM_SCHEMA.format(col="nspname")
    cur = await conn.execute(f"SELECT nspname FROM pg_namespace WHERE {where} ORDER BY nspname")
    return [r["nspname"] for r in await cur.fetchall()]


_DEFACL_TYPES = {"r": "table", "S": "sequence", "f": "function", "n": "schema", "T": "type"}


async def list_default_privileges(conn: Conn, role: str) -> list[dict[str, Any]]:
    await get_role_flags(conn, role)
    if is_public(role):
        grantee_filter = "a.grantee = 0"
    else:
        grantee_filter = "a.grantee = (SELECT oid FROM pg_roles WHERE rolname = %(role)s)"
    cur = await conn.execute(
        f"""
        SELECT pg_get_userbyid(d.defaclrole) AS for_role, n.nspname AS schema, d.defaclobjtype::text AS objtype,
               array_agg(a.privilege_type ORDER BY a.privilege_type) AS privileges
          FROM pg_default_acl d
          LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
          CROSS JOIN LATERAL aclexplode(d.defaclacl) a
         WHERE {grantee_filter}
         GROUP BY 1, 2, 3
         ORDER BY 1, 2 NULLS FIRST, 3
        """,
        {"role": role},
    )
    return [
        {
            "for_role": r["for_role"],
            "schema": r["schema"],
            "object_type": _DEFACL_TYPES.get(r["objtype"], r["objtype"]),
            "privileges": r["privileges"],
        }
        for r in await cur.fetchall()
    ]


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
_PRIV_FAMILY = {
    "database": "database",
    "schema": "schema",
    "table": "table",
    "sequence": "sequence",
    "function": "function",
    "all_tables": "table",
    "all_sequences": "sequence",
    "all_functions": "function",
    "default_tables": "table",
    "default_sequences": "sequence",
    "default_functions": "function",
    "default_schemas": "schema",
}

_BULK_TARGET = {"all_tables": "TABLES", "all_sequences": "SEQUENCES", "all_functions": "FUNCTIONS"}
_DEFAULT_TARGET = {
    "default_tables": "TABLES",
    "default_sequences": "SEQUENCES",
    "default_functions": "FUNCTIONS",
    "default_schemas": "SCHEMAS",
}


def _privileges(change: PermissionChange, catalog: dict[str, list[str]]) -> sql.Composable:
    allowed = catalog[_PRIV_FAMILY[change.object_type]]
    wanted = [p.strip().upper() for p in change.privileges]
    if any(p in ("ALL", "ALL PRIVILEGES") for p in wanted):
        return sql.SQL("ALL PRIVILEGES")
    bad = [p for p in wanted if p not in allowed]
    if bad:
        raise AppError(
            f"Invalid privilege(s) {', '.join(bad)} for {change.object_type}. Allowed: {', '.join(allowed)}."
        )
    return sql.SQL(", ").join(sql.SQL(p) for p in dict.fromkeys(wanted))


def _require(change: PermissionChange, *fields: str) -> None:
    for f in fields:
        if getattr(change, f) in (None, ""):
            raise AppError(f'"{f}" is required for object_type "{change.object_type}".')


async def _target(conn: Conn, change: PermissionChange) -> sql.Composable:
    t = change.object_type
    if t == "database":
        _require(change, "name")
        return sql.SQL("DATABASE {}").format(sql.Identifier(change.name))
    if t == "schema":
        _require(change, "name")
        return sql.SQL("SCHEMA {}").format(sql.Identifier(change.name))
    if t in ("table", "sequence"):
        _require(change, "schema_name", "name")
        return sql.SQL("{} {}.{}").format(
            sql.SQL(t.upper()), sql.Identifier(change.schema_name), sql.Identifier(change.name)
        )
    if t == "function":
        _require(change, "oid")
        cur = await conn.execute(
            """SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid) AS args
                 FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE p.oid = %s""",
            (change.oid,),
        )
        row = await cur.fetchone()
        if row is None:
            raise NotFound(f"Function with oid {change.oid} no longer exists")
        # ROUTINE covers functions, procedures and aggregates. The argument list comes from the
        # catalog (already type-quoted by PostgreSQL), never from the client.
        return sql.SQL("ROUTINE {}.{}({})").format(
            sql.Identifier(row["nspname"]), sql.Identifier(row["proname"]), sql.SQL(row["args"])
        )
    if t in _BULK_TARGET:
        _require(change, "schema_name")
        return sql.SQL("ALL {} IN SCHEMA {}").format(
            sql.SQL(_BULK_TARGET[t]), sql.Identifier(change.schema_name)
        )
    raise AppError(f"Unsupported object type {t}")


async def build_statements(conn: Conn, role: str, changes: list[PermissionChange]) -> list[sql.Composable]:
    catalog = privilege_catalog(conn.info.server_version)
    grantee = sql.SQL("PUBLIC") if is_public(role) else sql.Identifier(role)
    statements: list[sql.Composable] = []
    for change in changes:
        privs = _privileges(change, catalog)
        grant = change.action == "grant"
        parts: list[sql.Composable] = []
        if change.object_type in _DEFAULT_TARGET:
            if change.object_type == "default_schemas" and change.schema_name:
                raise AppError("Default privileges on schemas cannot be limited to a schema.")
            parts.append(sql.SQL("ALTER DEFAULT PRIVILEGES"))
            if change.for_role:
                parts.append(sql.SQL("FOR ROLE {}").format(sql.Identifier(change.for_role)))
            if change.schema_name:
                parts.append(sql.SQL("IN SCHEMA {}").format(sql.Identifier(change.schema_name)))
            on = sql.SQL(_DEFAULT_TARGET[change.object_type])
        else:
            on = await _target(conn, change)
        if grant:
            parts.append(sql.SQL("GRANT {} ON {} TO {}").format(privs, on, grantee))
            if change.with_grant_option:
                parts.append(sql.SQL("WITH GRANT OPTION"))
        else:
            parts.append(sql.SQL("REVOKE {} ON {} FROM {}").format(privs, on, grantee))
        statements.append(sql.SQL(" ").join(parts))
    return statements


async def apply_changes(
    conn: Conn, role: str, changes: list[PermissionChange], *, dry_run: bool
) -> tuple[list[str], bool]:
    await get_role_flags(conn, role)
    statements = await build_statements(conn, role, changes)
    rendered = [s.as_string(conn).strip() + ";" for s in statements]
    if dry_run:
        return rendered, False
    add_statements(rendered)  # recorded before running so a failed attempt still shows what was tried
    for stmt in statements:
        await conn.execute(stmt)
    return rendered, True
