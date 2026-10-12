"""Temporary access: list, schedule, extend, cancel or end early."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from ..audit import audited
from ..deps import get_pools
from ..db import PoolManager
from ..errors import AppError, NotFound
from ..security import Principal, require_operator
from ..services import expiring as ex

router = APIRouter(prefix="/temporary", tags=["temporary"])


class MembershipExpiry(BaseModel):
    role: str  # the group role
    member: str  # the user or role that holds the membership
    expires_at: datetime | None = None  # None removes an existing expiry


class Extend(BaseModel):
    expires_at: datetime


@router.get("")
async def list_schedules(
    request: Request,
    status: Literal["pending", "history", "all"] = "pending",
    involving: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
) -> dict:
    items = await request.app.state.store.run(ex.db_list, status, involving, limit)
    return {"items": items}


async def _get(request: Request, schedule_id: int) -> dict[str, Any]:
    row = await request.app.state.store.run(ex.db_get, schedule_id)
    if row is None:
        raise NotFound(f"Schedule {schedule_id} does not exist")
    return row


@router.put("/membership")
async def set_membership_expiry(
    body: MembershipExpiry, request: Request, pools: PoolManager = Depends(get_pools), me: Principal = Depends(require_operator)
) -> dict:
    """Make a role membership temporary (or permanent again with ``expires_at: null``)."""
    store = request.app.state.store
    existing = await store.run(ex.db_find_membership, body.role, body.member)
    async with audited(request, me.username, "access.schedule", target=body.member) as a:
        if body.expires_at is None:
            if existing:
                await store.run(ex.db_cancel, existing["id"])
            a.summary = f"Membership of {body.member} in {body.role} is now permanent"
            return {"schedule": None}
        when = ex.check_expiry(body.expires_at)
        async with pools.connection() as conn:
            cur = await conn.execute(
                "SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member "
                "WHERE g.rolname = %s AND u.rolname = %s",
                (body.role, body.member),
            )
            if await cur.fetchone() is None:
                raise NotFound(f"{body.member} is not a member of {body.role}")
        a.summary = f"{body.member} will lose membership of {body.role} on {ex.iso(when)}"
        a.details = {"role": body.role, "expires_at": ex.iso(when)}
        if existing:
            await store.run(ex.db_set_expiry, existing["id"], ex.iso(when))
            sid = existing["id"]
        else:
            sid = await store.run(
                ex.db_insert, "membership", body.member, None, f"membership of {body.role}", {"role": body.role}, me.username, ex.iso(when)
            )
        return {"schedule": await store.run(ex.db_get, sid)}


@router.post("/{schedule_id}/cancel")
async def cancel(schedule_id: int, request: Request, me: Principal = Depends(require_operator)) -> dict:
    """Keep the access permanently: the scheduled revocation is dropped."""
    row = await _get(request, schedule_id)
    async with audited(request, me.username, "access.cancel", target=row["grantee"]) as a:
        a.summary = f"Expiry cancelled for {row['grantee']}: {row['description']} (access stays)"
        if not await request.app.state.store.run(ex.db_cancel, schedule_id):
            raise AppError("This schedule is no longer active.", 409)
    return await _get(request, schedule_id)


@router.post("/{schedule_id}/extend")
async def extend(schedule_id: int, body: Extend, request: Request, me: Principal = Depends(require_operator)) -> dict:
    row = await _get(request, schedule_id)
    when = ex.check_expiry(body.expires_at)
    async with audited(request, me.username, "access.extend", target=row["grantee"]) as a:
        a.summary = f"Expiry for {row['grantee']} ({row['description']}) moved to {ex.iso(when)}"
        a.details = {"from": row["expires_at"], "to": ex.iso(when)}
        if not await request.app.state.store.run(ex.db_set_expiry, schedule_id, ex.iso(when)):
            raise AppError("This schedule is no longer active.", 409)
    return await _get(request, schedule_id)


@router.post("/{schedule_id}/revoke-now")
async def revoke_now(schedule_id: int, request: Request, me: Principal = Depends(require_operator)) -> dict:
    """End the access immediately (also retries a failed revocation)."""
    row = await request.app.state.store.run(ex.db_claim_one, schedule_id)
    if row is None:
        raise AppError("This schedule is no longer active.", 409)
    await ex.run_row(request.app, row, actor=me.username, action="access.revoke_now")
    return await _get(request, schedule_id)
