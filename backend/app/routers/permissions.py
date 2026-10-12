from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query

from ..db import PoolManager
from ..deps import get_pools
from ..schemas import ApplyRequest, ApplyResult
from ..security import require_auth
from ..services import permissions as svc

log = logging.getLogger("pgac.audit")
router = APIRouter(tags=["permissions"])


@router.get("/schemas")
async def schemas(
    database: str, include_system: bool = False, pools: PoolManager = Depends(get_pools)
) -> list[str]:
    async with pools.connection(database) as conn:
        return await svc.list_schemas(conn, include_system)


@router.get("/permissions/{role:path}/objects")
async def objects(
    role: str,
    database: str,
    type: Literal["database", "schema", "table", "sequence", "function"] = "table",
    schema: str | None = None,
    q: str | None = Query(None, max_length=100),
    granted_only: bool = False,
    include_system: bool = False,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pools: PoolManager = Depends(get_pools),
) -> dict:
    async with pools.connection(database) as conn:
        return await svc.list_objects(
            conn,
            role,
            type,
            schema=schema,
            q=q,
            granted_only=granted_only,
            include_system=include_system,
            limit=limit,
            offset=offset,
        )


@router.get("/permissions/{role:path}/default-privileges")
async def default_privileges(
    role: str, database: str, pools: PoolManager = Depends(get_pools)
) -> list[dict]:
    async with pools.connection(database) as conn:
        return await svc.list_default_privileges(conn, role)


@router.post("/permissions/{role:path}/apply", response_model=ApplyResult)
async def apply(
    role: str,
    body: ApplyRequest,
    pools: PoolManager = Depends(get_pools),
    actor: str = Depends(require_auth),
) -> ApplyResult:
    # One transaction: either every change is applied or none is.
    async with pools.connection(body.database) as conn:
        statements, applied = await svc.apply_changes(conn, role, body.changes, dry_run=body.dry_run)
    if applied:
        for stmt in statements:
            log.info("%s on %s: %s", actor, body.database, stmt)
    return ApplyResult(statements=statements, applied=applied)
