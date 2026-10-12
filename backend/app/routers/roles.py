from __future__ import annotations

from datetime import timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request

from ..audit import audited
from ..db import PoolManager
from ..deps import get_pools
from ..schemas import (
    DependencyReport,
    MembershipSpec,
    MembershipUpdate,
    RoleCreate,
    RoleDetail,
    RoleList,
    RoleUpdate,
)
from ..rbac import ensure_attributes_allowed, ensure_role_editable, ensure_roles_grantable
from ..security import Principal, require_admin, require_operator
from ..services import roles as svc

router = APIRouter(prefix="/roles", tags=["roles"])

# Role names may contain "/" so detail routes use the :path converter; the longer, suffixed routes
# are declared first so they win.

_TRACKED = ["login", "superuser", "createdb", "createrole", "inherit", "replication", "bypassrls", "connection_limit", "valid_until", "comment"]
_LABELS = {"connection_limit": "connection limit", "valid_until": "expires", "login": "can log in"}


def _snapshot(d: RoleDetail) -> dict[str, Any]:
    snap = {f: getattr(d, f) for f in _TRACKED}
    if d.valid_until:  # always UTC, so entries read the same whatever the server's timezone
        snap["valid_until"] = d.valid_until.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    snap["member_of"] = sorted(m.role for m in d.memberships)
    snap["members"] = sorted(m.role for m in d.members)
    return snap


def _fmt(v: Any) -> str:
    if isinstance(v, bool):
        return "yes" if v else "no"
    if v is None or v == "":
        return "none"
    return str(v)


def _diff(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[Any]]:
    return {k: [before[k], after[k]] for k in after if before.get(k) != after[k]}


async def _safe_get(pools: PoolManager, name: str) -> RoleDetail | None:
    """Read a role for before/after snapshots; auditing must never fail the request."""
    try:
        async with pools.connection() as conn:
            return await svc.get_role(conn, name)
    except Exception:  # noqa: BLE001
        return None


@router.get("", response_model=RoleList)
async def list_roles(
    kind: Literal["all", "user", "role"] = "all",
    q: str | None = Query(None, max_length=100),
    include_system: bool = False,
    sort: Literal["name", "member_of", "members", "expires", "conn_limit", "privilege"] = "name",
    order: Literal["asc", "desc"] = "asc",
    attr: Literal[
        "all", "superuser", "createrole", "createdb", "replication", "bypassrls", "expired", "no_memberships"
    ] = "all",
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    pools: PoolManager = Depends(get_pools),
) -> RoleList:
    async with pools.connection() as conn:
        return await svc.list_roles(
            conn,
            kind=kind,
            q=q,
            include_system=include_system,
            limit=limit,
            offset=offset,
            sort=sort,
            order=order,
            attr=attr,
        )


@router.post("", response_model=RoleDetail, status_code=201)
async def create_role(
    body: RoleCreate, request: Request, pools: PoolManager = Depends(get_pools), me: Principal = Depends(require_operator)
) -> RoleDetail:
    kind = "user" if body.login else "role"
    ensure_attributes_allowed(me, body.model_dump())
    async with pools.connection() as conn:
        await ensure_roles_grantable(conn, me, body.member_of)
    async with audited(request, me.username, "role.create", target=body.name) as a:
        a.summary = f"Created {kind} {body.name}"
        a.details = {
            "attributes": body.model_dump(include=set(_TRACKED), exclude_none=True, mode="json"),
            "password": "set" if body.password else "none",
            "member_of": body.member_of,
            "members": body.members,
        }
        async with pools.connection() as conn:
            await svc.create_role(conn, body)
    async with pools.connection() as conn:
        return await svc.get_role(conn, body.name)


@router.get("/{name:path}/dependencies", response_model=DependencyReport)
async def role_dependencies(name: str, pools: PoolManager = Depends(get_pools)) -> DependencyReport:
    async with pools.connection() as conn:
        return await svc.get_dependencies(conn, name)


def _opts(m: Any) -> dict[str, Any]:
    return {"admin": m.admin_option, "inherit": m.inherit_option, "set": m.set_option}


async def _membership(
    request: Request, pools: PoolManager, me: Principal, name: str, specs: list[MembershipSpec], direction: str
) -> RoleDetail:
    up = direction == "member-of"
    actor = me.username
    async with audited(request, actor, "role.membership", target=name) as a:
        before = await _safe_get(pools, name)
        cur = {m.role: m for m in ((before.memberships if up else before.members) if before else [])}
        old = sorted(cur)
        new = sorted({s.role for s in specs})
        added, removed = [r for r in new if r not in old], [r for r in old if r not in new]
        changed = [
            s.role
            for s in specs
            if s.role in cur
            and any(
                getattr(s, f"{k}_option") is not None and getattr(s, f"{k}_option") != getattr(cur[s.role], f"{k}_option")
                for k in ("admin", "inherit", "set")
            )
        ]
        a.summary = f"Changed {'roles of' if up else 'members of'} {name}: " + (
            ", ".join([f"+{r}" for r in added] + [f"−{r}" for r in removed] + [f"~{r} (options)" for r in changed])
            or "no change"
        )
        a.details = {
            "direction": direction,
            "before": old,
            "after": new,
            "added": added,
            "removed": removed,
            "options_changed": {
                s.role: {"from": _opts(cur[s.role]), "to": s.model_dump(exclude={"role"}, exclude_none=True)}
                for s in specs
                if s.role in changed
            },
        }
        async with pools.connection() as conn:
            if added or changed:  # operators may not hand out powerful roles (nor change who holds them)
                await ensure_roles_grantable(conn, me, added + changed if up else [name])
            await (svc.set_member_of if up else svc.set_members)(conn, name, specs)
    async with pools.connection() as conn:
        return await svc.get_role(conn, name)


@router.put("/{name:path}/member-of", response_model=RoleDetail)
async def set_member_of(
    name: str, body: MembershipUpdate, request: Request, pools: PoolManager = Depends(get_pools), me: Principal = Depends(require_operator)
) -> RoleDetail:
    return await _membership(request, pools, me, name, body.specs(), "member-of")


@router.put("/{name:path}/members", response_model=RoleDetail)
async def set_members(
    name: str, body: MembershipUpdate, request: Request, pools: PoolManager = Depends(get_pools), me: Principal = Depends(require_operator)
) -> RoleDetail:
    return await _membership(request, pools, me, name, body.specs(), "members")


@router.get("/{name:path}", response_model=RoleDetail)
async def get_role(name: str, pools: PoolManager = Depends(get_pools)) -> RoleDetail:
    async with pools.connection() as conn:
        return await svc.get_role(conn, name)


@router.patch("/{name:path}", response_model=RoleDetail)
async def update_role(
    name: str, body: RoleUpdate, request: Request, pools: PoolManager = Depends(get_pools), me: Principal = Depends(require_operator)
) -> RoleDetail:
    final = name
    ensure_attributes_allowed(me, body.model_dump(exclude_none=True))
    async with pools.connection() as conn:
        await ensure_role_editable(conn, me, name)  # also stops password resets of privileged roles
    async with audited(request, me.username, "role.update", target=name) as a:
        before = await _safe_get(pools, name)
        a.summary = f"Updated {name}"
        async with pools.connection() as conn:
            final = await svc.update_role(conn, name, body)
        after = await _safe_get(pools, final)
        changes: dict[str, list[Any]] = {}
        if before and after:
            changes = _diff(_snapshot(before), _snapshot(after))
        if final != name:
            changes["name"] = [name, final]
        parts = [f"{_LABELS.get(k, k)}: {_fmt(v[0])} → {_fmt(v[1])}" for k, v in changes.items() if k not in ("member_of", "members")]
        if body.password:
            parts.append("password changed")
        if body.remove_password:
            parts.append("password removed")
        a.summary = f"Updated {name}" + (": " + ", ".join(parts) if parts else "")
        a.details = {"changes": changes, "password": "changed" if body.password else "removed" if body.remove_password else "unchanged"}
    async with pools.connection() as conn:
        return await svc.get_role(conn, final)


@router.delete("/{name:path}", status_code=204)
async def delete_role(
    name: str,
    request: Request,
    reassign_to: str | None = None,
    pools: PoolManager = Depends(get_pools),
    me: Principal = Depends(require_admin),
) -> None:
    async with audited(request, me.username, "role.delete", target=name) as a:
        before = await _safe_get(pools, name)
        kind = before.kind if before else "role"
        a.summary = f"Deleted {kind} {name}" + (f" (ownership transferred to {reassign_to})" if reassign_to else "")
        a.details = {"before": _snapshot(before) if before else None, "reassign_to": reassign_to}
        await svc.delete_role(pools, name, reassign_to)
