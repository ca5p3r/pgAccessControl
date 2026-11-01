from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from ..audit import audited
from ..db import PoolManager
from ..deps import get_pools
from ..rbac import ensure_ownership_change
from ..schemas import OwnedType, OwnerChange, OwnerFilter, OwnerReassign
from ..security import Principal, require_admin, require_operator
from ..services import ownership as svc

router = APIRouter(prefix="/ownership", tags=["ownership"])


@router.get("/objects")
async def objects(
    database: str,
    type: OwnedType = "table",
    schema: str | None = None,
    owner: str | None = Query(None, max_length=200),
    q: str | None = Query(None, max_length=100),
    include_system: bool = False,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    pools: PoolManager = Depends(get_pools),
) -> dict:
    """Objects of one type with their owner, filterable by schema, current owner and name."""
    flt = OwnerFilter(object_type=type, schema=schema, owner=owner, q=q, include_system=include_system)
    async with pools.connection(database) as conn:
        return await svc.list_objects(conn, flt, limit=limit, offset=offset)


@router.get("/summary")
async def summary(database: str, include_system: bool = False, pools: PoolManager = Depends(get_pools)) -> dict:
    """How many objects of each type every role owns in a database."""
    async with pools.connection(database) as conn:
        return await svc.summary(conn, include_system)


def _counts(objs: list[dict]) -> str:
    kinds: dict[str, int] = {}
    for o in objs:
        kinds[o["type"]] = kinds.get(o["type"], 0) + 1
    return ", ".join(f"{n} {k}{'' if n == 1 else 's'}" for k, n in kinds.items())


@router.post("/change")
async def change(
    body: OwnerChange, request: Request, pools: PoolManager = Depends(get_pools), me: Principal = Depends(require_operator)
) -> dict:
    """Make a role the owner of the selected objects (``ALTER ... OWNER TO``), all in one transaction."""
    async with pools.connection(body.database) as conn:
        objs = await svc.resolve(conn, body.items, body.filter)
        plan = await svc.plan_change(conn, body.new_owner, objs)
        await ensure_ownership_change(conn, me, body.new_owner, objs)
        out = {
            "changed": len(plan["change"]), "skipped": plan["skipped"],
            "objects": [{"object": svc.describe(o), "from": o["owner"]} for o in plan["change"]],
        }
        if body.dry_run:  # previews change nothing, so they are not audited
            return {**out, "applied": False, "statements": await svc.change_owner(conn, plan, dry_run=True)}

    if not plan["change"]:  # nothing to do (all skipped): no statements ran, so there is nothing to record
        return {**out, "applied": True, "statements": []}
    froms = sorted({o["owner"] for o in plan["change"]})
    async with audited(request, me.username, "ownership.change", target=body.new_owner, target_type="ownership", database=body.database) as a:
        a.summary = f"Made {body.new_owner} the owner of {_counts(plan['change'])} in {body.database} (from {', '.join(froms)})"
        a.details = {"new_owner": body.new_owner, "from": froms, "objects": out["objects"][:200], "count": out["changed"], "skipped": len(plan["skipped"])}
        async with pools.connection(body.database) as conn:
            statements = await svc.change_owner(conn, plan, dry_run=False)
    return {**out, "applied": True, "statements": statements}


@router.post("/reassign")
async def reassign(
    body: OwnerReassign, request: Request, pools: PoolManager = Depends(get_pools), me: Principal = Depends(require_admin)
) -> dict:
    """Hand everything one role owns (in one database, or in all of them) to another role: ``REASSIGN OWNED``."""
    plan = await svc.plan_reassign(pools, body.from_role, body.to_role, body.database)
    places = sorted(plan["places"])
    if body.dry_run:
        return {"applied": False, "places": plan["places"], "statements": await svc.reassign(pools, body.from_role, body.to_role, places, dry_run=True)}
    async with audited(request, me.username, "ownership.reassign", target=body.to_role, target_type="ownership", database=body.database) as a:
        where = body.database or ("all databases" if len(places) != 1 else places[0])
        a.summary = f"Handed everything {body.from_role} owns ({where}) to {body.to_role}"
        a.details = {"from": body.from_role, "to": body.to_role, "databases": places, "owned_objects": plan["places"]}
        statements = await svc.reassign(pools, body.from_role, body.to_role, places, dry_run=False)
    return {"applied": True, "places": plan["places"], "statements": statements}
