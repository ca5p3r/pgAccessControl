"""App accounts: users of this web console (not PostgreSQL roles), each with a viewer/operator/admin role."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .errors import AppError, NotFound
from .store import AppStore

ROLES = ("viewer", "operator", "admin")
RANK = {"viewer": 1, "operator": 2, "admin": 3}
MIN_PASSWORD = 10

_N, _R, _P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(got, base64.b64decode(digest))
    except Exception:  # noqa: BLE001 - malformed hash
        return False


# scrypt is deliberately slow (~50 ms): keep it off the event loop.
async def hash_password_async(password: str) -> str:
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(password: str, stored: str) -> bool:
    return await asyncio.to_thread(verify_password, password, stored)


_DUMMY = hash_password("not-a-real-password")  # burned when the user does not exist, to hide that fact by timing


@dataclass
class Account:
    id: int
    username: str
    role: str
    disabled: bool
    created_at: str
    created_by: str | None
    last_login: str | None
    password_hash: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id, "username": self.username, "role": self.role, "disabled": self.disabled,
            "created_at": self.created_at, "created_by": self.created_by, "last_login": self.last_login,
        }


def _row(r: sqlite3.Row | None) -> Account | None:
    if r is None:
        return None
    return Account(r["id"], r["username"], r["role"], bool(r["disabled"]), r["created_at"], r["created_by"], r["last_login"], r["password_hash"])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AppError(f"Password must be at least {MIN_PASSWORD} characters.", 422)
    if len(password) > 256:
        raise AppError("Password is too long.", 422)


class Accounts:
    def __init__(self, store: AppStore, reserved_username: str = "") -> None:
        self.store = store
        self.reserved = reserved_username.lower()

    async def list(self) -> list[Account]:
        def q(c: sqlite3.Connection) -> list[Account]:
            return [_row(r) for r in c.execute("SELECT * FROM app_users ORDER BY username COLLATE NOCASE")]  # type: ignore[misc]
        return await self.store.run(q)

    async def get(self, username: str) -> Account | None:
        return await self.store.run(lambda c: _row(c.execute("SELECT * FROM app_users WHERE username = ?", (username,)).fetchone()))

    async def create(self, username: str, password: str, role: str, created_by: str) -> Account:
        username = username.strip()
        if not username or len(username) > 100:
            raise AppError("Username must be 1-100 characters.", 422)
        if role not in ROLES:
            raise AppError(f"Role must be one of: {', '.join(ROLES)}.", 422)
        if username.lower() == self.reserved:
            raise AppError("That username is reserved for the built-in administrator.", 409)
        validate_password(password)
        hashed = await hash_password_async(password)

        def q(c: sqlite3.Connection) -> Account:
            try:
                c.execute(
                    "INSERT INTO app_users (username, password_hash, role, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
                    (username, hashed, role, _now(), created_by),
                )
            except sqlite3.IntegrityError:
                raise AppError(f'An account named "{username}" already exists.', 409) from None
            return _row(c.execute("SELECT * FROM app_users WHERE username = ?", (username,)).fetchone())  # type: ignore[return-value]

        return await self.store.run(q)

    async def update(self, username: str, *, role: str | None, disabled: bool | None, password: str | None) -> Account:
        if role is not None and role not in ROLES:
            raise AppError(f"Role must be one of: {', '.join(ROLES)}.", 422)
        hashed = None
        if password is not None:
            validate_password(password)
            hashed = await hash_password_async(password)

        def q(c: sqlite3.Connection) -> Account:
            acct = _row(c.execute("SELECT * FROM app_users WHERE username = ?", (username,)).fetchone())
            if acct is None:
                raise NotFound(f'Account "{username}" does not exist')
            c.execute(
                "UPDATE app_users SET role = ?, disabled = ?, password_hash = ? WHERE id = ?",
                (role or acct.role, int(acct.disabled if disabled is None else disabled), hashed or acct.password_hash, acct.id),
            )
            return _row(c.execute("SELECT * FROM app_users WHERE id = ?", (acct.id,)).fetchone())  # type: ignore[return-value]

        return await self.store.run(q)

    async def delete(self, username: str) -> None:
        def q(c: sqlite3.Connection) -> None:
            if c.execute("DELETE FROM app_users WHERE username = ?", (username,)).rowcount == 0:
                raise NotFound(f'Account "{username}" does not exist')
        await self.store.run(q)

    async def authenticate(self, username: str, password: str) -> Account | None:
        acct = await self.get(username)
        ok = await verify_password_async(password, acct.password_hash if acct else _DUMMY)
        if not acct or not ok or acct.disabled:
            return None
        await self.store.run(lambda c: c.execute("UPDATE app_users SET last_login = ? WHERE id = ?", (_now(), acct.id)))
        return acct

