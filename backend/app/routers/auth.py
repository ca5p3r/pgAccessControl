from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from ..audit import log_event
from ..config import get_settings
from ..security import (
    COOKIE_NAME,
    check_login_allowed,
    clear_login_failures,
    create_token,
    read_token,
    record_login_failure,
    verify_credentials,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.get("/me")
async def me(request: Request) -> dict:
    settings = get_settings()
    if not settings.auth_enabled:
        return {"auth_enabled": False, "authenticated": True, "username": None}
    user = read_token(settings, request.cookies.get(COOKIE_NAME))
    return {"auth_enabled": True, "authenticated": user is not None, "username": user}


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response) -> dict:
    settings = get_settings()
    client = request.client.host if request.client else "unknown"
    check_login_allowed(client)
    if not settings.auth_enabled:
        return {"authenticated": True}
    if not verify_credentials(settings, body.username, body.password):
        record_login_failure(client)
        await log_event(request, body.username[:100], "auth.login_failed", "Failed sign-in attempt", "failed")
        raise HTTPException(401, "Invalid username or password")
    clear_login_failures(client)
    await log_event(request, body.username, "auth.login", "Signed in")
    response.set_cookie(
        COOKIE_NAME,
        create_token(settings, body.username),
        max_age=settings.session_ttl_minutes * 60,
        httponly=True,
        samesite="strict",
        secure=settings.cookie_secure,
        path="/",
    )
    return {"authenticated": True, "username": body.username}


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict:
    user = read_token(get_settings(), request.cookies.get(COOKIE_NAME))
    if user:
        await log_event(request, user, "auth.logout", "Signed out")
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"authenticated": False}
