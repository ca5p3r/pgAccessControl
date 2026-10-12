from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field

from ..accounts import validate_password, verify_password_async
from ..audit import log_event
from ..config import Settings, get_settings
from ..oidc import OIDCError, new_pkce
from ..security import (
    COOKIE_NAME,
    Principal,
    check_login_allowed,
    clear_login_failures,
    create_token,
    current_principal,
    record_login_failure,
    require_auth,
    verify_credentials,
)

log = logging.getLogger("pgac.auth")
router = APIRouter(prefix="/auth", tags=["auth"])

_OIDC_COOKIE = "pgac_oidc"


class LoginRequest(BaseModel):
    username: str
    password: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(max_length=256)


def _set_session(response: Response, settings: Settings, p: Principal) -> None:
    response.set_cookie(
        COOKIE_NAME, create_token(settings, p), max_age=settings.session_ttl_minutes * 60,
        httponly=True, samesite="strict", secure=settings.cookie_secure, path="/",
    )


@router.get("/me")
async def me(request: Request) -> dict:
    s = get_settings()
    p = await current_principal(request)
    return {
        "auth_enabled": s.auth_enabled,
        "authenticated": p is not None,
        "username": p.username if p and s.auth_enabled else None,
        "role": p.role if p else None,
        "source": p.source if p else None,
        "local_login": s.local_login_enabled,
        "oidc_enabled": s.oidc_enabled,
        "oidc_label": s.oidc_button_label,
    }


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response) -> dict:
    s = get_settings()
    client = request.client.host if request.client else "unknown"
    if not s.auth_enabled:
        return {"authenticated": True}
    if not s.local_login_enabled:
        raise HTTPException(403, "Password sign-in is disabled. Use single sign-on.")
    check_login_allowed(client)

    principal: Principal | None = None
    if verify_credentials(s, body.username, body.password):
        principal = Principal(s.admin_username, "admin", "env")
    else:
        acct = await request.app.state.accounts.authenticate(body.username, body.password)
        if acct:
            principal = Principal(acct.username, acct.role, "local")
    if principal is None:
        record_login_failure(client)
        await log_event(request, body.username[:100], "auth.login_failed", "Failed sign-in attempt", "failed")
        raise HTTPException(401, "Invalid username or password")

    clear_login_failures(client)
    await log_event(request, principal.username, "auth.login", f"Signed in as {principal.role}")
    _set_session(response, s, principal)
    return {"authenticated": True, "username": principal.username, "role": principal.role}


@router.post("/logout")
async def logout(request: Request, response: Response) -> dict:
    p = await current_principal(request)
    if p and p.source != "none":
        await log_event(request, p.username, "auth.logout", "Signed out")
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"authenticated": False}


@router.post("/password")
async def change_password(body: PasswordChange, request: Request, me: Principal = Depends(require_auth)) -> dict:
    if me.source != "local":
        raise HTTPException(400, "Only app accounts can change their password here.")
    accounts = request.app.state.accounts
    acct = await accounts.get(me.username)
    if acct is None or not await verify_password_async(body.current_password, acct.password_hash):
        raise HTTPException(400, "The current password is incorrect.")
    validate_password(body.new_password)
    await accounts.update(me.username, role=None, disabled=None, password=body.new_password)
    await log_event(request, me.username, "account.password", "Changed own password")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Single sign-on (OpenID Connect)
# ---------------------------------------------------------------------------
def _redirect_uri(request: Request, s: Settings) -> str:
    return s.oidc_redirect_uri or str(request.base_url).rstrip("/") + "/api/auth/oidc/callback"


def _client(request: Request):
    oidc = getattr(request.app.state, "oidc", None)
    if oidc is None:
        raise HTTPException(404, "Single sign-on is not configured.")
    return oidc


def _back_to_app(error: str | None = None) -> HTMLResponse:
    # A client-side redirect (rather than a 302) keeps the SameSite=Strict session cookie working: the
    # browser treats it as a fresh same-site navigation instead of a continuation of the cross-site one.
    target = "/" + (f"?sso_error={error}" if error else "")
    html = (
        f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={target}">'
        f'<title>Signing in…</title><script>location.replace("{target}")</script><a href="{target}">Continue</a>'
    )
    return HTMLResponse(html)


@router.get("/oidc/login")
async def oidc_login(request: Request) -> RedirectResponse:
    s = get_settings()
    oidc = _client(request)
    verifier, challenge = new_pkce()
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    try:
        url = await oidc.authorize_url(state=state, nonce=nonce, challenge=challenge, redirect_uri=_redirect_uri(request, s))
    except Exception as exc:  # noqa: BLE001
        log.error("OIDC discovery failed: %s", exc)
        raise HTTPException(502, "Could not reach the single sign-on provider.") from exc
    cookie = jwt.encode(
        {"state": state, "nonce": nonce, "verifier": verifier, "exp": datetime.now(timezone.utc) + timedelta(minutes=10)},
        s.secret_key, algorithm="HS256",
    )
    resp = RedirectResponse(url, status_code=302)
    # Lax (not Strict): this cookie must come back on the cross-site redirect from the provider.
    resp.set_cookie(_OIDC_COOKIE, cookie, max_age=600, httponly=True, samesite="lax", secure=s.cookie_secure, path="/api/auth/oidc")
    return resp


@router.get("/oidc/callback")
async def oidc_callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None) -> HTMLResponse:
    s = get_settings()
    oidc = _client(request)
    try:
        saved = jwt.decode(request.cookies.get(_OIDC_COOKIE, ""), s.secret_key, algorithms=["HS256"])
    except jwt.PyJWTError:
        saved = None

    def done(page: HTMLResponse) -> HTMLResponse:
        page.delete_cookie(_OIDC_COOKIE, path="/api/auth/oidc")
        return page

    if error or not code or not state or not saved or not secrets.compare_digest(state, saved["state"]):
        await log_event(request, "sso", "auth.login_failed", f"SSO sign-in failed ({error or 'invalid state'})", "failed")
        return done(_back_to_app("access_denied" if error == "access_denied" else "failed"))
    try:
        tokens = await oidc.exchange(code, saved["verifier"], _redirect_uri(request, s))
        claims = await oidc.validate_id_token(tokens.get("id_token", ""), saved["nonce"])
    except Exception as exc:  # noqa: BLE001 - OIDCError and network errors alike
        log.warning("OIDC sign-in rejected: %s", exc)
        await log_event(request, "sso", "auth.login_failed", "SSO sign-in failed (token validation)", "failed")
        return done(_back_to_app("failed"))

    username = oidc.username(claims)
    role = oidc.role_for(claims)
    if role is None:
        await log_event(request, username, "auth.login_failed", "SSO user has no access (no matching group)", "failed")
        return done(_back_to_app("no_access"))
    await log_event(request, username, "auth.login", f"Signed in via SSO as {role}")
    page = done(_back_to_app())
    _set_session(page, s, Principal(username, role, "oidc"))
    return page
