"""Role / user management.

In PostgreSQL "users" and "roles" are the same object: a user is a role that has LOGIN. This module
manages both; the ``kind`` filter / ``login`` attribute distinguishes them.
"""

from __future__ import annotations

from typing import Any

import psycopg
from psycopg import sql

from ..db import PoolManager
from ..errors import AppError, NotFound
from ..schemas import (
    Dependency,
    DependencyReport,
    Membership,
    RoleAttributes,
    RoleCreate,
    RoleDetail,
    RoleList,
    RoleSummary,
    RoleUpdate,
)
from .scram import scram_sha256_verifier

Conn = psycopg.AsyncConnection

_BASE_COLUMNS = """
    r.oid, r.rolname AS name, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
    r.rolreplication, r.rolbypassrls, r.rolconnlimit,
    NULLIF(r.rolvaliduntil, 'infinity'::timestamptz) AS valid_until,
    (r.rolname = current_user) AS is_current_user
"""

# Aggregates are computed in an outer query so they only run for the rows that survive LIMIT.
_ENRICH = """
    SELECT b.*,
           shobj_description(b.oid, 'pg_authid') AS comment,
           COALESCE((SELECT array_agg(DISTINCT g.rolname ORDER BY g.rolname)
                       FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                      WHERE m.member = b.oid), '{}') AS member_of,
           (SELECT count(DISTINCT m.member) FROM pg_auth_members m WHERE m.roleid = b.oid)::int AS member_count
      FROM base b
"""


def _like(q: str) -> str:
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _summary(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": row["name"],
        "oid": row["oid"],
        "kind": "user" if row["rolcanlogin"] else "role",
        "is_system": row["name"].startswith("pg_"),
        "superuser": row["rolsuper"],
        "inherit": row["rolinherit"],
        "createrole": row["rolcreaterole"],
        "createdb": row["rolcreatedb"],
        "login": row["rolcanlogin"],
        "replication": row["rolreplication"],
        "bypassrls": row["rolbypassrls"],
        "connection_limit": row["rolconnlimit"],
        "valid_until": row["valid_until"],
        "comment": row["comment"],
        "member_of": row["member_of"],
        "member_count": row["member_count"],
    }


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------
async def list_roles(
    conn: Conn, *, kind: str, q: str | None, include_system: bool, limit: int, offset: int
) -> RoleList:
    where = ["TRUE"]
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if kind == "user":
        where.append("r.rolcanlogin")
    elif kind == "role":
        where.append("NOT r.rolcanlogin")
    if not include_system:
        where.append("r.rolname !~ '^pg_'")
    if q:
        where.append("r.rolname ILIKE %(q)s")
        params["q"] = _like(q)
    query = f"""
        WITH base AS (
            SELECT {_BASE_COLUMNS}, count(*) OVER () AS total
              FROM pg_roles r
             WHERE {' AND '.join(where)}
             ORDER BY r.rolname
             LIMIT %(limit)s OFFSET %(offset)s
        )
        {_ENRICH} ORDER BY b.name
    """
    cur = await conn.execute(query, params)
    rows = await cur.fetchall()
    total = rows[0]["total"] if rows else 0
    if not rows and offset:
        cur = await conn.execute(
            f"SELECT count(*) AS n FROM pg_roles r WHERE {' AND '.join(where)}", params
        )
        total = (await cur.fetchone())["n"]
    return RoleList(items=[RoleSummary(**_summary(r)) for r in rows], total=total)


async def _fetch_role(conn: Conn, name: str) -> dict[str, Any]:
    query = f"""
        WITH base AS (SELECT {_BASE_COLUMNS} FROM pg_roles r WHERE r.rolname = %(name)s)
        {_ENRICH}
    """
    cur = await conn.execute(query, {"name": name})
    row = await cur.fetchone()
    if row is None:
        raise NotFound(f'Role "{name}" does not exist')
    return row


async def _memberships(conn: Conn, oid: int, *, direction: str) -> list[Membership]:
    # direction "up": roles this role belongs to; "down": members of this role
    if direction == "up":
        query = """SELECT g.rolname AS role, bool_or(m.admin_option) AS admin_option
                     FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                    WHERE m.member = %s GROUP BY g.rolname ORDER BY g.rolname"""
    else:
        query = """SELECT g.rolname AS role, bool_or(m.admin_option) AS admin_option
                     FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.member
                    WHERE m.roleid = %s GROUP BY g.rolname ORDER BY g.rolname"""
    cur = await conn.execute(query, (oid,))
    return [Membership(**r) for r in await cur.fetchall()]


async def get_role(conn: Conn, name: str) -> RoleDetail:
    row = await _fetch_role(conn, name)
    return RoleDetail(
        **_summary(row),
        memberships=await _memberships(conn, row["oid"], direction="up"),
        members=await _memberships(conn, row["oid"], direction="down"),
        is_current_user=row["is_current_user"],
    )


async def role_exists(conn: Conn, name: str) -> bool:
    cur = await conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (name,))
    return await cur.fetchone() is not None


# ---------------------------------------------------------------------------
# Statement building
# ---------------------------------------------------------------------------
_FLAGS = [
    ("login", "LOGIN", "NOLOGIN"),
    ("superuser", "SUPERUSER", "NOSUPERUSER"),
    ("createdb", "CREATEDB", "NOCREATEDB"),
    ("createrole", "CREATEROLE", "NOCREATEROLE"),
    ("inherit", "INHERIT", "NOINHERIT"),
    ("replication", "REPLICATION", "NOREPLICATION"),
    ("bypassrls", "BYPASSRLS", "NOBYPASSRLS"),
]


def _attribute_options(attrs: RoleAttributes, fields_set: set[str]) -> list[sql.Composable]:
    parts: list[sql.Composable] = []
    for field, on, off in _FLAGS:
        value = getattr(attrs, field)
        if value is not None:
            parts.append(sql.SQL(on if value else off))
    if attrs.connection_limit is not None:
        parts.append(sql.SQL("CONNECTION LIMIT {}").format(sql.Literal(attrs.connection_limit)))
    if "valid_until" in fields_set:
        value = attrs.valid_until.isoformat() if attrs.valid_until else "infinity"
        parts.append(sql.SQL("VALID UNTIL {}").format(sql.Literal(value)))
    return parts


def _password_option(password: str | None, remove: bool = False) -> sql.Composable | None:
    if remove:
        return sql.SQL("PASSWORD NULL")
    if password:
        return sql.SQL("PASSWORD {}").format(sql.Literal(scram_sha256_verifier(password) or password))
    return None


async def _set_comment(conn: Conn, name: str, comment: str | None) -> None:
    await conn.execute(
        sql.SQL("COMMENT ON ROLE {} IS {}").format(
            sql.Identifier(name), sql.Literal(comment) if comment else sql.SQL("NULL")
        )
    )


def _guard_not_system(name: str) -> None:
    if name.startswith("pg_"):
        raise AppError(f'"{name}" is a predefined PostgreSQL role and cannot be modified.', 400)


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------
async def create_role(conn: Conn, data: RoleCreate) -> None:
    options = _attribute_options(data, data.model_fields_set)
    pw = _password_option(data.password)
    if pw:
        options.append(pw)
    stmt = sql.SQL("CREATE ROLE {}").format(sql.Identifier(data.name))
    if options:
        stmt = sql.SQL("{} WITH {}").format(stmt, sql.SQL(" ").join(options))
    await conn.execute(stmt)
    if data.comment:
        await _set_comment(conn, data.name, data.comment)
    for parent in dict.fromkeys(data.member_of):
        await _grant_role(conn, parent, data.name)
    for member in dict.fromkeys(data.members):
        await _grant_role(conn, data.name, member)


async def update_role(conn: Conn, name: str, data: RoleUpdate) -> str:
    row = await _fetch_role(conn, name)
    _guard_not_system(row["name"])
    options = _attribute_options(data, data.model_fields_set)
    pw = _password_option(data.password, data.remove_password)
    if pw:
        options.append(pw)
    if options:
        await conn.execute(
            sql.SQL("ALTER ROLE {} WITH {}").format(sql.Identifier(name), sql.SQL(" ").join(options))
        )
    if "comment" in data.model_fields_set:
        await _set_comment(conn, name, data.comment)
    final = name
    if data.rename_to and data.rename_to != name:
        await conn.execute(
            sql.SQL("ALTER ROLE {} RENAME TO {}").format(sql.Identifier(name), sql.Identifier(data.rename_to))
        )
        final = data.rename_to
    return final


async def _grant_role(conn: Conn, role: str, member: str) -> None:
    await conn.execute(sql.SQL("GRANT {} TO {}").format(sql.Identifier(role), sql.Identifier(member)))


async def _revoke_role(conn: Conn, role: str, member: str) -> None:
    await conn.execute(sql.SQL("REVOKE {} FROM {}").format(sql.Identifier(role), sql.Identifier(member)))


async def set_member_of(conn: Conn, name: str, roles: list[str]) -> None:
    """Make ``name`` a member of exactly ``roles`` (grants missing, revokes extra)."""
    row = await _fetch_role(conn, name)
    _guard_not_system(name)
    desired = set(roles)
    if name in desired:
        raise AppError("A role cannot be a member of itself.")
    current = {m.role for m in await _memberships(conn, row["oid"], direction="up")}
    for role in sorted(desired - current):
        await _grant_role(conn, role, name)
    for role in sorted(current - desired):
        await _revoke_role(conn, role, name)


async def set_members(conn: Conn, name: str, members: list[str]) -> None:
    """Make ``members`` the complete set of direct members of role ``name``."""
    row = await _fetch_role(conn, name)
    _guard_not_system(name)
    desired = set(members)
    if name in desired:
        raise AppError("A role cannot be a member of itself.")
    current = {m.role for m in await _memberships(conn, row["oid"], direction="down")}
    for member in sorted(desired - current):
        await _grant_role(conn, name, member)
    for member in sorted(current - desired):
        await _revoke_role(conn, name, member)


# ---------------------------------------------------------------------------
# Deletion
# ---------------------------------------------------------------------------
async def get_dependencies(conn: Conn, name: str) -> DependencyReport:
    row = await _fetch_role(conn, name)
    cur = await conn.execute(
        """
        SELECT COALESCE(db.datname, '') AS database,
               count(*) FILTER (WHERE d.deptype = 'o')::int AS owned_objects,
               count(*) FILTER (WHERE d.deptype IN ('a', 'r'))::int AS privileges
          FROM pg_shdepend d LEFT JOIN pg_database db ON db.oid = d.dbid
         WHERE d.refclassid = 'pg_authid'::regclass AND d.refobjid = %s
           AND d.deptype IN ('o', 'a', 'r')
         GROUP BY 1 ORDER BY 1
        """,
        (row["oid"],),
    )
    deps = [Dependency(**r) for r in await cur.fetchall()]
    return DependencyReport(dependencies=deps, owns_objects=any(d.owned_objects for d in deps))


async def delete_role(pools: PoolManager, name: str, reassign_to: str | None) -> None:
    default_db = pools.default_database
    async with pools.connection() as conn:
        row = await _fetch_role(conn, name)
        _guard_not_system(name)
        if row["is_current_user"]:
            raise AppError("You cannot delete the role this application is connected as.", 400)
        report = await get_dependencies(conn, name)
        if reassign_to is not None:
            if reassign_to == name:
                raise AppError("Cannot reassign objects to the role being deleted.")
            if not await role_exists(conn, reassign_to):
                raise NotFound(f'Role "{reassign_to}" does not exist')
        if report.owns_objects and reassign_to is None:
            owners = ", ".join(d.database or "(cluster-wide)" for d in report.dependencies if d.owned_objects)
            raise AppError(
                f'Role "{name}" owns objects in: {owners}.',
                409,
                hint="Choose a role that should take ownership of them before deleting.",
            )

    # Shared objects (databases, tablespaces) are cleaned up from the maintenance database.
    targets = {d.database or default_db for d in report.dependencies}
    for dbname in sorted(targets):
        try:
            async with pools.connection(dbname) as conn:
                if reassign_to is not None:
                    await conn.execute(
                        sql.SQL("REASSIGN OWNED BY {} TO {}").format(
                            sql.Identifier(name), sql.Identifier(reassign_to)
                        )
                    )
                # After the reassign only privileges / default ACLs / policies remain to be dropped.
                await conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(name)))
        except psycopg.Error as exc:
            raise AppError(
                f'Cleaning up database "{dbname}" failed: {exc.diag.message_primary or exc}', 409
            ) from exc

    async with pools.connection() as conn:
        await conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(name)))
