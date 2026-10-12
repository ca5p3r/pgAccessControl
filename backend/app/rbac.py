"""Privilege-escalation guards for the operator role.

Operators manage everyday access (grants, memberships, ordinary roles) but must not be able to hand out or
take over powerful roles, otherwise "operator" would just be a slower way of becoming admin.
"""

from __future__ import annotations

import psycopg
from fastapi import HTTPException

from .security import Principal

# Predefined roles that grant broad or server-level power.
DANGEROUS_PREDEFINED = {
    "pg_execute_server_program",
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_read_all_data",
    "pg_write_all_data",
    "pg_signal_backend",
    "pg_create_subscription",
    "pg_database_owner",
}

# Attributes only an admin may set on a role.
PRIVILEGED_ATTRIBUTES = ("superuser", "createrole", "replication", "bypassrls")


def deny(what: str) -> HTTPException:
    return HTTPException(403, f"Only an admin may {what}.")


async def is_privileged(conn: psycopg.AsyncConnection, name: str) -> bool:
    """True for roles an operator must not modify or hand out."""
    if name in DANGEROUS_PREDEFINED:
        return True
    cur = await conn.execute(
        "SELECT rolsuper OR rolcreaterole OR rolreplication OR rolbypassrls AS p FROM pg_roles WHERE rolname = %s", (name,)
    )
    row = await cur.fetchone()
    return bool(row and row["p"])


def ensure_attributes_allowed(me: Principal, requested: dict[str, object]) -> None:
    if me.can("admin"):
        return
    bad = [a for a in PRIVILEGED_ATTRIBUTES if requested.get(a) is True]
    if bad:
        raise deny(f"grant the {', '.join(bad)} attribute")


async def ensure_roles_grantable(conn: psycopg.AsyncConnection, me: Principal, roles: list[str]) -> None:
    """Operators may not add anyone to a privileged role."""
    if me.can("admin"):
        return
    for r in roles:
        if await is_privileged(conn, r):
            raise deny(f'grant membership of the privileged role "{r}"')


async def ensure_role_editable(conn: psycopg.AsyncConnection, me: Principal, name: str) -> None:
    """Operators may not edit (e.g. reset the password of) a privileged role."""
    if me.can("admin"):
        return
    if await is_privileged(conn, name):
        raise deny(f'modify the privileged role "{name}"')
