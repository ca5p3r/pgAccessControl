from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query, Request

from ..audit import audited
from ..db import PoolManager
from ..deps import get_pools
from ..schemas import ApplyRequest, ApplyResult
from ..security import require_auth
from ..services import permissions as svc

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
    request: Request,
    pools: PoolManager = Depends(get_pools),
    actor: str = Depends(require_auth),
) -> ApplyResult:
    if body.dry_run:  # previews change nothing, so they are not audited
        async with pools.connection(body.database) as conn:
            statements, applied = await svc.apply_changes(conn, role, body.changes, dry_run=True)
        return ApplyResult(statements=statements, applied=applied)

    grants = sum(c.action == "grant" for c in body.changes)
    revokes = len(body.changes) - grants
    async with audited(request, actor, "permission.apply", target=role, target_type="permission", database=body.database) as a:
        parts = [f"{n} {word}{'' if n == 1 else 's'}" for n, word in ((grants, "grant"), (revokes, "revoke")) if n]
        a.summary = f"{', '.join(parts)} for {role} in {body.database}"
        a.details = {"grants": grants, "revokes": revokes}
        # One transaction: either every change is applied or none is.
        async with pools.connection(body.database) as conn:
            statements, applied = await svc.apply_changes(conn, role, body.changes, dry_run=False)
    return ApplyResult(statements=statements, applied=applied)
