"""What a role *holds*: owned objects, privileges, default privileges and the grants it has given to others.

This is the list behind the "N grants are held by this role" message when deleting a role. PostgreSQL tracks
it in ``pg_shdepend``; the counts come from there, the detail from the object ACLs (the same expansion the
export uses, so it also covers column privileges and default privileges).
"""

from __future__ import annotations

import re
from typing import Any

import psycopg

from . import reports as rep
from . import roles as roles_svc

Conn = psycopg.AsyncConnection

# Same catalog query as the export, but matching the *grantor* instead of the grantee.
_GRANTED_BY_SQL = rep._PRIV_SQL.replace("u.grantee = %(grantee)s::oid", "u.grantor = %(grantee)s::oid")

_KIND = re.compile(r"^(materialized view|foreign table|foreign-data wrapper|text search \w+|[a-z]+)")


def _described(rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    out = []
    for r in rows:
        m = _KIND.match(r["object"])
        out.append({"kind": m.group(1) if m else "object", "description": r["object"]})
    return sorted(out, key=lambda x: (x["kind"], x["description"]))


async def summary(conn: Conn, name: str) -> dict[str, Any]:
    """Counts per database (from pg_shdepend) plus everything that is cluster-wide (databases, tablespaces)."""
    row = await roles_svc._fetch_role(conn, name)
    deps = await roles_svc.get_dependencies(conn, name)
    oid = row["oid"]

    cur = await conn.execute(
        """SELECT pg_describe_object(d.classid, d.objid, d.objsubid) AS object
             FROM pg_shdepend d
            WHERE d.dbid = 0 AND d.refclassid = 'pg_authid'::regclass AND d.refobjid = %s AND d.deptype = 'o'""",
        (oid,),
    )
    owned = _described(await cur.fetchall())

    cur = await conn.execute(
        """SELECT 'database' AS kind, d.datname AS name, a.privilege_type AS privilege, a.is_grantable AS grantable,
                  pg_get_userbyid(a.grantor) AS grantor
             FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a
            WHERE a.grantee = %(oid)s AND a.grantor <> %(oid)s
           UNION ALL
           SELECT 'tablespace', t.spcname, a.privilege_type, a.is_grantable, pg_get_userbyid(a.grantor)
             FROM pg_tablespace t CROSS JOIN LATERAL aclexplode(t.spcacl) a
            WHERE a.grantee = %(oid)s AND a.grantor <> %(oid)s
           ORDER BY 1, 2, 3""",
        {"oid": oid},
    )
    privileges = await cur.fetchall()
    cur = await conn.execute(
        """SELECT 'database' AS kind, d.datname AS name, a.privilege_type AS privilege, a.is_grantable AS grantable,
                  pg_get_userbyid(a.grantee)  AS grantee
             FROM pg_database d CROSS JOIN LATERAL aclexplode(d.datacl) a
            WHERE a.grantor = %(oid)s AND a.grantee <> %(oid)s ORDER BY 2, 3""",
        {"oid": oid},
    )
    given = await cur.fetchall()
    return {
        "role": name,
        "is_superuser": row["rolsuper"],
        "databases": [d.model_dump() for d in deps.dependencies if d.database],
        "cluster": {"owned": owned, "privileges": privileges, "granted_to_others": given},
        "owns_objects": deps.owns_objects,
    }


async def detail(conn: Conn, name: str) -> dict[str, Any]:
    """Everything the role holds in the database ``conn`` is connected to."""
    data = await rep.export_data(conn, name)  # privileges and defaults where the role is the grantee
    cur = await conn.execute("SELECT oid FROM pg_roles WHERE rolname = %s", (name,))
    oid = (await cur.fetchone())["oid"]

    cur = await conn.execute(
        """SELECT d.deptype, pg_describe_object(d.classid, d.objid, d.objsubid) AS object
             FROM pg_shdepend d
            WHERE d.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
              AND d.refclassid = 'pg_authid'::regclass AND d.refobjid = %s AND d.deptype IN ('o', 'r')""",
        (oid,),
    )
    rows = await cur.fetchall()
    cur = await conn.execute(_GRANTED_BY_SQL, {"grantee": oid})
    granted = [r for r in await cur.fetchall() if r["grantee"] != name]
    return {
        "database": data["database"],
        "owned": _described([r for r in rows if r["deptype"] == "o"]),
        "policies": _described([r for r in rows if r["deptype"] == "r"]),
        # Database-level grants are cluster-wide and shown by the summary, not per database.
        "privileges": [p for p in data["privileges"] if p["object_type"] != "database"],
        "default_privileges": data["default_privileges"],
        "granted_to_others": [g for g in granted if g["object_type"] != "database"],
    }
