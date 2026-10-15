"""Authentication and authorization for the web app itself (not PostgreSQL authentication).

Who can sign in:
  * the built-in administrator from ADMIN_USERNAME / ADMIN_PASSWORD ("env"), a break-glass account,
  * app accounts created in the UI ("local"), each a viewer, operator or admin,
  * users of an OpenID Connect provider ("oidc"), mapped to a role through their groups.

A successful sign-in sets a signed JWT in an HttpOnly, SameSite=Strict cookie, so the SPA never handles
the token. Local accounts are re-checked in the database on every request, so disabling an account or
changing its role takes effect immediately.
"""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request

from .accounts import RANK
from .config import Settings, get_settings

COOKIE_NAME = "pgac_session"
_ALGORITHM = "HS256"

_MAX_FAILURES = 5
_WINDOW_SECONDS = 60
_failures: dict[str, deque[float]] = defaultdict(deque)


@dataclass(frozen=True)
class Principal:
    username: str
    role: str = "admin"  # viewer < operator < admin
    source: str = "env"  # env | local | oidc | none (authentication disabled)
    capped: bool = False  # True when the selected server is read-only and the role was lowered to viewer

    def can(self, minimum: str) -> bool:
        return RANK[self.role] >= RANK[minimum]


def verify_credentials(settings: Settings, username: str, password: str) -> bool:
    """The built-in administrator. Both comparisons run so timing does not reveal which one failed."""
    user_ok = hmac.compare_digest(username.encode(), settings.admin_username.encode())
    pass_ok = hmac.compare_digest(password.encode(), settings.admin_password.encode())
    return bool(settings.admin_password) and user_ok and pass_ok


def create_token(settings: Settings, p: Principal) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": p.username, "role": p.role, "src": p.source,
        "iat": now, "exp": now + timedelta(minutes=settings.session_ttl_minutes),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=_ALGORITHM)


def read_claims(settings: Settings, token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[_ALGORITHM])
    except jwt.PyJWTError:
        return None


def check_login_allowed(client: str) -> None:
    now = time.monotonic()
    attempts = _failures[client]
    while attempts and now - attempts[0] > _WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= _MAX_FAILURES:
        raise HTTPException(429, "Too many failed attempts. Try again in a minute.")


def record_login_failure(client: str) -> None:
    _failures[client].append(time.monotonic())


def clear_login_failures(client: str) -> None:
    _failures.pop(client, None)


async def current_principal(request: Request) -> Principal | None:
    """The signed-in principal, or None. Does not raise."""
    settings = get_settings()
    if not settings.auth_enabled:
        return Principal("anonymous", "admin", "none")
    claims = read_claims(settings, request.cookies.get(COOKIE_NAME))
    if not claims or claims.get("role") not in RANK:
        return None
    p = Principal(claims["sub"], claims["role"], claims.get("src", "env"))
    if p.source == "local":
        acct = await request.app.state.accounts.get(p.username)
        if acct is None or acct.disabled:
            return None
        p = Principal(p.username, acct.role, "local")  # the database is the source of truth for the role
    return p


async def require_auth(request: Request) -> Principal:
    p = await current_principal(request)
    if p is None:
        raise HTTPException(401, "Authentication required")
    return p


async def effective_principal(request: Request) -> Principal:
    """Who is acting, as adjusted for the selected server (a read-only server caps everyone to viewer).
    Server-scoped routers set ``request.state.principal`` first; other routes use the plain identity."""
    p = getattr(request.state, "principal", None)
    return p if p is not None else await require_auth(request)


def require_role(minimum: str):
    async def dependency(p: Principal = Depends(effective_principal)) -> Principal:
        if not p.can(minimum):
            if p.capped:
                raise HTTPException(403, "This server is read-only in the console, so changes are not allowed here.")
            raise HTTPException(403, f"This needs the {minimum} role; you are signed in as {p.role}.")
        return p

    return dependency


require_operator = require_role("operator")
require_admin = require_role("admin")
