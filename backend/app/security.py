"""Authentication for the web app itself (not PostgreSQL authentication).

A single admin account is configured through environment variables. A successful login sets a signed
JWT in an HttpOnly, SameSite=Strict cookie, so the SPA never handles the token directly.
"""

from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Request

from .config import Settings, get_settings

COOKIE_NAME = "pgac_session"
_ALGORITHM = "HS256"

_MAX_FAILURES = 5
_WINDOW_SECONDS = 60
_failures: dict[str, deque[float]] = defaultdict(deque)


def verify_credentials(settings: Settings, username: str, password: str) -> bool:
    # Evaluate both comparisons to keep timing independent of which one failed.
    user_ok = hmac.compare_digest(username.encode(), settings.admin_username.encode())
    pass_ok = hmac.compare_digest(password.encode(), settings.admin_password.encode())
    return user_ok and pass_ok


def create_token(settings: Settings, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {"sub": username, "iat": now, "exp": now + timedelta(minutes=settings.session_ttl_minutes)}
    return jwt.encode(payload, settings.secret_key, algorithm=_ALGORITHM)


def read_token(settings: Settings, token: str | None) -> str | None:
    if not token:
        return None
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[_ALGORITHM])["sub"]
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


async def require_auth(request: Request) -> str:
    settings = get_settings()
    if not settings.auth_enabled:
        return "anonymous"
    user = read_token(settings, request.cookies.get(COOKIE_NAME))
    if user is None:
        raise HTTPException(401, "Authentication required")
    return user
