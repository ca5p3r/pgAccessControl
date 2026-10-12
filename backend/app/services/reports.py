"""Reporting: reverse access lookup ("who can access this object?") and permission exports.

Like the permission reads, everything is set-based: effective access is computed by PostgreSQL itself
(``has_*_privilege``), so ownership, PUBLIC, role inheritance, superuser and predefined roles such as
``pg_read_all_data`` are all accounted for exactly as the server would. Sources are then attributed from
the object's ACL.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterator

import psycopg
from psycopg import sql

from ..errors import AppError, NotFound
from .permissions import _KINDS, _SYSTEM_SCHEMA, _kind_label, _like, is_public, privilege_catalog

Conn = psycopg.AsyncConnection

_OID_COL = {"table": "c.oid", "sequence": "c.oid", "function": "p.oid", "schema": "n.oid", "database": "d.oid"}
_HAS_PRIV = {
    "table": "has_table_privilege",
    "sequence": "has_sequence_privilege",
    "function": "has_function_privilege",
    "schema": "has_schema_privilege",
    "database": "has_database_privilege",
}
REPORT_CAP = 20_000  # role x privilege rows


# ---------------------------------------------------------------------------
# Object picker
# ---------------------------------------------------------------------------
async def search_objects(
    conn: Conn, object_type: str, *, schema: str | None, q: str | None, limit: int, offset: int
) -> dict[str, Any]:
    cfg = _KINDS[object_type]
    where, params = [cfg["where"]], {"limit": limit, "offset": offset}
    if object_type != "database":
        where.append(_SYSTEM_SCHEMA.format(col=cfg["schema_col"]))
    if schema and object_type in ("table", "sequence", "function"):
        where.append(f"{cfg['schema_col']} = %(schema)s")
        params["schema"] = schema
    if q:
        where.append(f"{cfg['name_col']} ILIKE %(q)s")
        params["q"] = _like(q)
    cur = await conn.execute(
        f"""SELECT {cfg['cols']}, count(*) OVER () AS total FROM {cfg['frm']}
             WHERE {' AND '.join(where)} ORDER BY {cfg['order']} LIMIT %(limit)s OFFSET %(offset)s""",
        params,
    )
    rows = await cur.fetchall()
    return {
        "items": [
            {"oid": r["oid"], "schema": r["schema"], "name": r["name"], "kind": _kind_label(object_type, r["kind"]),
             "owner": r["owner"], "args": r["args"]}
            for r in rows
        ],
        "total": rows[0]["total"] if rows else 0,
    }


# ---------------------------------------------------------------------------
# Who can access this object?
# ---------------------------------------------------------------------------
async def access_report(conn: Conn, object_type: str, oid: int) -> dict[str, Any]:
    cfg = _KINDS[object_type]
    privs = privilege_catalog(conn.info.server_version)[object_type]

    cur = await conn.execute(
        f"""SELECT {cfg['cols']},
                   COALESCE((SELECT jsonb_agg(jsonb_build_object(
                                'grantee', CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,
                                'privilege', a.privilege_type, 'grantable', a.is_grantable,
                                'grantor', pg_get_userbyid(a.grantor)))
                       FROM aclexplode({cfg['acl']}) a), '[]'::jsonb) AS grants
              FROM {cfg['frm']} WHERE {cfg['where']} AND {_OID_COL[object_type]} = %(oid)s""",
        {"oid": oid},
    )
    obj = await cur.fetchone()
    if obj is None:
        raise NotFound(f"{object_type.capitalize()} with oid {oid} no longer exists")

    fn = _HAS_PRIV[object_type]
    cur = await conn.execute(
        f"""
        WITH obj AS (SELECT {cfg['acl']} AS acl FROM {cfg['frm']} WHERE {cfg['where']} AND {_OID_COL[object_type]} = %(oid)s),
        g AS (SELECT a.grantee, a.privilege_type AS priv FROM obj, aclexplode(obj.acl) a),
        eff AS (
            SELECT r.oid AS roid, r.rolname, r.rolcanlogin, r.rolsuper, p.priv
              FROM pg_roles r CROSS JOIN unnest(%(privs)s::text[]) AS p(priv)
             WHERE r.rolname !~ '^pg_' AND {fn}(r.oid, %(oid)s::oid, p.priv)
        )
        SELECT e.rolname, e.rolcanlogin, e.rolsuper, e.priv,
               COALESCE(array_agg(DISTINCT CASE WHEN g.grantee = 0 THEN 'PUBLIC'
                                                WHEN g.grantee = e.roid THEN ''
                                                ELSE pg_get_userbyid(g.grantee) END)
                        FILTER (WHERE g.grantee IS NOT NULL), '{{}}') AS sources
          FROM eff e
          LEFT JOIN g ON g.priv = e.priv
                     AND (g.grantee = 0 OR g.grantee = e.roid OR pg_has_role(e.roid, g.grantee, 'USAGE'))
         GROUP BY e.rolname, e.rolcanlogin, e.rolsuper, e.priv
         ORDER BY e.rolname, e.priv
         LIMIT %(cap)s
        """,
        {"oid": oid, "privs": privs, "cap": REPORT_CAP + 1},
    )
    rows = await cur.fetchall()
    truncated = len(rows) > REPORT_CAP

    principals: dict[str, dict[str, Any]] = {}
    for r in rows[:REPORT_CAP]:
        p = principals.setdefault(
            r["rolname"],
            {"name": r["rolname"], "kind": "user" if r["rolcanlogin"] else "role", "superuser": r["rolsuper"],
             "is_owner": r["rolname"] == obj["owner"], "privileges": {}},
        )
        sources = ["direct" if s == "" else s for s in r["sources"]]
        if r["rolsuper"]:
            # Superusers count as members of every role, which would list them all as "inherited" sources.
            sources = [s for s in sources if s in ("direct", "PUBLIC")] + ["superuser"]
        elif not sources:  # no ACL entry explains it
            sources = ["predefined role (e.g. pg_read_all_data)"]
        p["privileges"][r["priv"]] = sources

    return {
        "object": {"oid": obj["oid"], "type": object_type, "schema": obj["schema"], "name": obj["name"],
                   "kind": _kind_label(object_type, obj["kind"]), "owner": obj["owner"], "args": obj["args"]},
        "privilege_names": privs,
        "grants": obj["grants"],
        "principals": list(principals.values()),
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
_PRIV_SQL = """
SELECT object_type, schema, name, args, owner,
       CASE WHEN grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(grantee) END AS grantee,
       privilege_type AS privilege, is_grantable AS grantable, pg_get_userbyid(grantor) AS grantor
  FROM (
    SELECT 'table' AS object_type, n.nspname AS schema, c.relname AS name, '' AS args,
           pg_get_userbyid(c.relowner) AS owner, a.grantee, a.privilege_type, a.is_grantable, a.grantor
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(c.relacl) a
     WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.grantee <> c.relowner AND {sys_n}
    UNION ALL
    SELECT 'sequence', n.nspname, c.relname, '', pg_get_userbyid(c.relowner), a.grantee, a.privilege_type, a.is_grantable, a.grantor
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      CROSS JOIN LATERAL aclexplode(c.relacl) a
     WHERE c.relkind = 'S' AND a.grantee <> c.relowner AND {sys_n}
    UNION ALL
    SELECT 'function', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid), pg_get_userbyid(p.proowner),
           a.grantee, a.privilege_type, a.is_grantable, a.grantor
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
      CROSS JOIN LATERAL aclexplode(p.proacl) a
     WHERE p.prokind IN ('f', 'p') AND a.grantee <> p.proowner AND {sys_n}
    UNION ALL
    SELECT 'schema', n.nspname, n.nspname, '', pg_get_userbyid(n.nspowner), a.grantee, a.privilege_type, a.is_grantable, a.grantor
      FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a
     WHERE a.grantee <> n.nspowner AND {sys_n}
    UNION ALL
    SELECT 'database', '', d.datname, '', pg_get_userbyid(d.datdba), a.grantee, a.privilege_type, a.is_grantable, a.grantor
      FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a
     WHERE d.datname = current_database() AND a.grantee <> d.datdba
  ) u
 WHERE (%(grantee)s::oid IS NULL OR u.grantee = %(grantee)s::oid)
 ORDER BY 1, 2, 3, 4, 6, 7
""".format(sys_n=_SYSTEM_SCHEMA.format(col="n.nspname"))

_DEFAULTS_SQL = """
SELECT pg_get_userbyid(d.defaclrole) AS for_role, n.nspname AS schema, d.defaclobjtype::text AS objtype,
       CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END AS grantee,
       a.privilege_type AS privilege, a.is_grantable AS grantable
  FROM pg_default_acl d
  LEFT JOIN pg_namespace n ON n.oid = d.defaclnamespace
  CROSS JOIN LATERAL aclexplode(d.defaclacl) a
 WHERE (%(grantee)s::oid IS NULL OR a.grantee = %(grantee)s::oid)
 ORDER BY 1, 2 NULLS FIRST, 3, 4, 5
"""

_DEFACL_TYPE = {"r": "TABLES", "S": "SEQUENCES", "f": "FUNCTIONS", "n": "SCHEMAS", "T": "TYPES"}


async def export_data(conn: Conn, role: str | None) -> dict[str, Any]:
    """Collect roles, memberships, explicit privileges and default privileges (optionally for one role)."""
    grantee: int | None = None
    if role:
        if is_public(role):
            grantee = 0
        else:
            cur = await conn.execute("SELECT oid FROM pg_roles WHERE rolname = %s", (role,))
            row = await cur.fetchone()
            if row is None:
                raise NotFound(f'Role "{role}" does not exist')
            grantee = row["oid"]

    roles: list[dict[str, Any]] = []
    memberships: list[dict[str, Any]] = []
    if not (role and is_public(role)):
        cur = await conn.execute(
            """SELECT r.rolname AS name, r.rolcanlogin AS login, r.rolsuper AS superuser, r.rolinherit AS inherit,
                      r.rolcreaterole AS createrole, r.rolcreatedb AS createdb, r.rolreplication AS replication,
                      r.rolbypassrls AS bypassrls, r.rolconnlimit AS connection_limit,
                      NULLIF(r.rolvaliduntil, 'infinity'::timestamptz) AS valid_until,
                      shobj_description(r.oid, 'pg_authid') AS comment
                 FROM pg_roles r
                WHERE r.rolname !~ '^pg_' AND (%(role)s::text IS NULL OR r.rolname = %(role)s)
                ORDER BY r.rolname""",
            {"role": role},
        )
        roles = await cur.fetchall()
        cur = await conn.execute(
            """SELECT g.rolname AS role, m.rolname AS member, bool_or(am.admin_option) AS admin_option
                 FROM pg_auth_members am
                 JOIN pg_roles g ON g.oid = am.roleid
                 JOIN pg_roles m ON m.oid = am.member
                WHERE %(role)s::text IS NULL OR m.rolname = %(role)s OR g.rolname = %(role)s
                GROUP BY g.rolname, m.rolname ORDER BY 1, 2""",
            {"role": role},
        )
        memberships = await cur.fetchall()

    cur = await conn.execute(_PRIV_SQL, {"grantee": grantee})
    privileges = await cur.fetchall()
    cur = await conn.execute(_DEFAULTS_SQL, {"grantee": grantee})
    defaults = await cur.fetchall()
    for d in defaults:
        d["object_type"] = _DEFACL_TYPE.get(d.pop("objtype"), "?").lower()

    cur = await conn.execute("SELECT current_database() AS db, current_setting('server_version') AS v")
    info = await cur.fetchone()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "server_version": info["v"],
        "database": info["db"],
        "scope": role or "all roles",
        "roles": roles,
        "memberships": memberships,
        "privileges": privileges,
        "default_privileges": defaults,
    }


def _q(conn: Conn, ident: str) -> str:
    return sql.Identifier(ident).as_string(conn)


def _lit(conn: Conn, value: str) -> str:
    return sql.Literal(value).as_string(conn)


def _grantee(conn: Conn, name: str) -> str:
    return "PUBLIC" if name == "PUBLIC" else _q(conn, name)


def _target(conn: Conn, p: dict[str, Any]) -> str:
    t = p["object_type"]
    if t in ("table", "sequence"):
        return f"{t.upper()} {_q(conn, p['schema'])}.{_q(conn, p['name'])}"
    if t == "function":
        return f"ROUTINE {_q(conn, p['schema'])}.{_q(conn, p['name'])}({p['args']})"
    return f"{t.upper()} {_q(conn, p['name'])}"


def render_sql(conn: Conn, data: dict[str, Any]) -> Iterator[str]:
    yield (
        f"-- pgAccessControl permission export\n-- generated {data['generated_at']} (UTC) from PostgreSQL {data['server_version']}\n"
        f"-- database: {data['database']}    scope: {data['scope']}\n"
        "--\n-- Notes: passwords are NOT exported. Only explicit grants are listed (not the implicit owner\n"
        "-- privileges); revokes of default PUBLIC privileges are not reproduced.\n"
    )
    if data["roles"]:
        yield "\n-- Roles\n"
        for r in data["roles"]:
            opts = [
                "LOGIN" if r["login"] else "NOLOGIN",
                "SUPERUSER" if r["superuser"] else "NOSUPERUSER",
                "CREATEDB" if r["createdb"] else "NOCREATEDB",
                "CREATEROLE" if r["createrole"] else "NOCREATEROLE",
                "INHERIT" if r["inherit"] else "NOINHERIT",
                "REPLICATION" if r["replication"] else "NOREPLICATION",
                "BYPASSRLS" if r["bypassrls"] else "NOBYPASSRLS",
                f"CONNECTION LIMIT {int(r['connection_limit'])}",
            ]
            if r["valid_until"]:
                opts.append(f"VALID UNTIL {_lit(conn, r['valid_until'].isoformat())}")
            yield f"CREATE ROLE {_q(conn, r['name'])} WITH {' '.join(opts)};\n"
            if r["comment"]:
                yield f"COMMENT ON ROLE {_q(conn, r['name'])} IS {_lit(conn, r['comment'])};\n"
    if data["memberships"]:
        yield "\n-- Role memberships\n"
        for m in data["memberships"]:
            admin = " WITH ADMIN OPTION" if m["admin_option"] else ""
            yield f"GRANT {_q(conn, m['role'])} TO {_q(conn, m['member'])}{admin};\n"
    if data["privileges"]:
        yield f"\n-- Privileges (database {_q(conn, data['database'])})\n"
        grouped: dict[tuple, list[str]] = {}
        for p in data["privileges"]:
            grouped.setdefault((p["object_type"], p["schema"], p["name"], p["args"], p["grantee"], p["grantable"]), []).append(p["privilege"])
        for (otype, schema, name, args, grantee, grantable), privs in grouped.items():
            target = _target(conn, {"object_type": otype, "schema": schema, "name": name, "args": args})
            opt = " WITH GRANT OPTION" if grantable else ""
            yield f"GRANT {', '.join(privs)} ON {target} TO {_grantee(conn, grantee)}{opt};\n"
    if data["default_privileges"]:
        yield "\n-- Default privileges\n"
        grouped2: dict[tuple, list[str]] = {}
        for d in data["default_privileges"]:
            grouped2.setdefault((d["for_role"], d["schema"], d["object_type"], d["grantee"], d["grantable"]), []).append(d["privilege"])
        for (for_role, schema, otype, grantee, grantable), privs in grouped2.items():
            scope = f" IN SCHEMA {_q(conn, schema)}" if schema else ""
            opt = " WITH GRANT OPTION" if grantable else ""
            yield (
                f"ALTER DEFAULT PRIVILEGES FOR ROLE {_q(conn, for_role)}{scope} "
                f"GRANT {', '.join(privs)} ON {otype.upper()} TO {_grantee(conn, grantee)}{opt};\n"
            )
    if not any(data[k] for k in ("roles", "memberships", "privileges", "default_privileges")):
        yield "\n-- (nothing to export)\n"


CSV_DATASETS: dict[str, tuple[list[str], list[str]]] = {
    "privileges": (
        ["object_type", "schema", "object", "arguments", "owner", "grantee", "privilege", "grantable", "grantor"],
        ["object_type", "schema", "name", "args", "owner", "grantee", "privilege", "grantable", "grantor"],
    ),
    "roles": (
        ["name", "login", "superuser", "inherit", "createrole", "createdb", "replication", "bypassrls", "connection_limit", "valid_until", "comment"],
        ["name", "login", "superuser", "inherit", "createrole", "createdb", "replication", "bypassrls", "connection_limit", "valid_until", "comment"],
    ),
    "memberships": (["role", "member", "admin_option"], ["role", "member", "admin_option"]),
    "defaults": (
        ["created_by_role", "schema", "object_type", "grantee", "privilege", "grantable"],
        ["for_role", "schema", "object_type", "grantee", "privilege", "grantable"],
    ),
}
_DATASET_KEY = {"privileges": "privileges", "roles": "roles", "memberships": "memberships", "defaults": "default_privileges"}


def csv_rows(data: dict[str, Any], dataset: str) -> tuple[list[str], list[list[Any]]]:
    if dataset not in CSV_DATASETS:
        raise AppError(f"Unknown dataset {dataset!r}. Use one of: {', '.join(CSV_DATASETS)}.")
    header, keys = CSV_DATASETS[dataset]
    rows = [[(r[k].isoformat() if hasattr(r[k], "isoformat") else r[k]) for k in keys] for r in data[_DATASET_KEY[dataset]]]
    return header, rows
