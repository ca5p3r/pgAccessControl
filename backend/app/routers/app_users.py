"""Accounts for the web console itself (admin only)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..audit import audited
from ..security import Principal, require_admin

router = APIRouter(prefix="/app-users", tags=["app-users"])


class AppUserCreate(BaseModel):
    username: str = Field(min_length=1, max_length=100)
    password: str = Field(max_length=256)
    role: str = "viewer"


class AppUserUpdate(BaseModel):
    role: str | None = None
    disabled: bool | None = None
    password: str | None = Field(None, max_length=256)


@router.get("")
async def list_users(request: Request, me: Principal = Depends(require_admin)) -> dict:
    accounts = await request.app.state.accounts.list()
    return {"items": [a.public() for a in accounts], "me": me.username}


@router.post("", status_code=201)
async def create_user(body: AppUserCreate, request: Request, me: Principal = Depends(require_admin)) -> dict:
    async with audited(request, me.username, "account.create", target=body.username, target_type="account") as a:
        a.summary = f"Created {body.role} account {body.username}"
        a.details = {"role": body.role}
        acct = await request.app.state.accounts.create(body.username, body.password, body.role, me.username)
    return acct.public()


@router.patch("/{username}")
async def update_user(username: str, body: AppUserUpdate, request: Request, me: Principal = Depends(require_admin)) -> dict:
    if username.lower() == me.username.lower() and (body.disabled or (body.role and body.role != me.role)):
        raise HTTPException(400, "You cannot disable or demote your own account.")
    async with audited(request, me.username, "account.update", target=username, target_type="account") as a:
        before = await request.app.state.accounts.get(username)
        acct = await request.app.state.accounts.update(username, role=body.role, disabled=body.disabled, password=body.password)
        parts = []
        if before and body.role and body.role != before.role:
            parts.append(f"role {before.role} → {body.role}")
        if body.disabled is not None and before and body.disabled != before.disabled:
            parts.append("disabled" if body.disabled else "enabled")
        if body.password:
            parts.append("password reset")
        a.summary = f"Updated account {username}" + (": " + ", ".join(parts) if parts else "")
        a.details = {"changes": parts}
    return acct.public()


@router.delete("/{username}", status_code=204)
async def delete_user(username: str, request: Request, me: Principal = Depends(require_admin)) -> None:
    if username.lower() == me.username.lower():
        raise HTTPException(400, "You cannot delete your own account.")
    async with audited(request, me.username, "account.delete", target=username, target_type="account") as a:
        a.summary = f"Deleted account {username}"
        await request.app.state.accounts.delete(username)
