from __future__ import annotations

import logging
from typing import Literal

from fastapi import APIRouter, Depends, Query

from ..db import PoolManager
from ..deps import get_pools
from ..schemas import (
    DependencyReport,
    MembershipUpdate,
    RoleCreate,
    RoleDetail,
    RoleList,
    RoleUpdate,
)
from ..security import require_auth
from ..services import roles as svc

log = logging.getLogger("pgac.audit")
router = APIRouter(prefix="/roles", tags=["roles"])

# Role names may contain "/" so detail routes use the :path converter; the longer, suffixed routes
# are declared first so they win.


@router.get("", response_model=RoleList)
async def list_roles(
    kind: Literal["all", "user", "role"] = "all",
    q: str | None = Query(None, max_length=100),
    include_system: bool = False,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pools: PoolManager = Depends(get_pools),
) -> RoleList:
    async with pools.connection() as conn:
        return await svc.list_roles(
            conn, kind=kind, q=q, include_system=include_system, limit=limit, offset=offset
        )


@router.post("", response_model=RoleDetail, status_code=201)
async def create_role(
    body: RoleCreate, pools: PoolManager = Depends(get_pools), actor: str = Depends(require_auth)
) -> RoleDetail:
    async with pools.connection() as conn:
        await svc.create_role(conn, body)
    log.info("%s created role %r (login=%s)", actor, body.name, body.login)
    async with pools.connection() as conn:
        return await svc.get_role(conn, body.name)


@router.get("/{name:path}/dependencies", response_model=DependencyReport)
async def role_dependencies(name: str, pools: PoolManager = Depends(get_pools)) -> DependencyReport:
    async with pools.connection() as conn:
        return await svc.get_dependencies(conn, name)


@router.put("/{name:path}/member-of", response_model=RoleDetail)
async def set_member_of(
    name: str,
    body: MembershipUpdate,
    pools: PoolManager = Depends(get_pools),
    actor: str = Depends(require_auth),
) -> RoleDetail:
    async with pools.connection() as conn:
        await svc.set_member_of(conn, name, body.roles)
    log.info("%s set %r member-of %s", actor, name, body.roles)
    async with pools.connection() as conn:
        return await svc.get_role(conn, name)


@router.put("/{name:path}/members", response_model=RoleDetail)
async def set_members(
    name: str,
    body: MembershipUpdate,
    pools: PoolManager = Depends(get_pools),
    actor: str = Depends(require_auth),
) -> RoleDetail:
    async with pools.connection() as conn:
        await svc.set_members(conn, name, body.roles)
    log.info("%s set members of %r to %s", actor, name, body.roles)
    async with pools.connection() as conn:
        return await svc.get_role(conn, name)


@router.get("/{name:path}", response_model=RoleDetail)
async def get_role(name: str, pools: PoolManager = Depends(get_pools)) -> RoleDetail:
    async with pools.connection() as conn:
        return await svc.get_role(conn, name)


@router.patch("/{name:path}", response_model=RoleDetail)
async def update_role(
    name: str,
    body: RoleUpdate,
    pools: PoolManager = Depends(get_pools),
    actor: str = Depends(require_auth),
) -> RoleDetail:
    async with pools.connection() as conn:
        final = await svc.update_role(conn, name, body)
    log.info("%s updated role %r (fields: %s)", actor, name, sorted(body.model_fields_set - {"password"}))
    async with pools.connection() as conn:
        return await svc.get_role(conn, final)


@router.delete("/{name:path}", status_code=204)
async def delete_role(
    name: str,
    reassign_to: str | None = None,
    pools: PoolManager = Depends(get_pools),
    actor: str = Depends(require_auth),
) -> None:
    await svc.delete_role(pools, name, reassign_to)
    log.info("%s deleted role %r (reassigned to %r)", actor, name, reassign_to)
