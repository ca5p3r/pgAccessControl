from __future__ import annotations

from fastapi import APIRouter, Depends

from ..db import PoolManager
from ..deps import get_pools
from ..services.permissions import privilege_catalog

router = APIRouter(tags=["meta"])


@router.get("/meta")
async def meta(pools: PoolManager = Depends(get_pools)) -> dict:
    """Server facts the UI needs: version, who we are connected as, available privilege names."""
    async with pools.connection() as conn:
        cur = await conn.execute(
            """SELECT current_setting('server_version') AS version, current_user AS user,
                      r.rolsuper, r.rolcreaterole
                 FROM pg_roles r WHERE r.rolname = current_user"""
        )
        row = await cur.fetchone()
        version_num = conn.info.server_version
    return {
        "server_version": row["version"],
        "connected_as": row["user"],
        "is_superuser": row["rolsuper"],
        "can_create_roles": row["rolsuper"] or row["rolcreaterole"],
        "host": pools.settings.pg_host,
        "port": pools.settings.pg_port,
        "database": pools.settings.pg_database,
        "privileges": privilege_catalog(version_num),
    }


@router.get("/databases")
async def databases(pools: PoolManager = Depends(get_pools)) -> list[dict]:
    async with pools.connection() as conn:
        cur = await conn.execute(
            """SELECT datname AS name, pg_get_userbyid(datdba) AS owner,
                      has_database_privilege(current_user, oid, 'CONNECT') AS connectable
                 FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname"""
        )
        return await cur.fetchall()


@router.get("/stats")
async def stats(pools: PoolManager = Depends(get_pools)) -> dict:
    async with pools.connection() as conn:
        cur = await conn.execute(
            """SELECT
                 count(*) FILTER (WHERE rolcanlogin AND rolname !~ '^pg_')::int AS users,
                 count(*) FILTER (WHERE NOT rolcanlogin AND rolname !~ '^pg_')::int AS roles,
                 count(*) FILTER (WHERE rolsuper)::int AS superusers,
                 count(*) FILTER (WHERE rolcanlogin AND rolname !~ '^pg_' AND rolvaliduntil < now())::int AS expired,
                 (SELECT count(*) FROM pg_database WHERE NOT datistemplate)::int AS databases
               FROM pg_roles"""
        )
        return await cur.fetchone()
