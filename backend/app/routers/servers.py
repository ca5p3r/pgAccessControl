"""Server profiles: list what you may use, check health, and (admins) add / change / test / remove servers."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..audit import audited
from ..config import get_settings
from ..crypto import SecretsUnavailable
from ..db import ConnectionProfile
from ..errors import AppError, NotFound
from .. import servers as sv
from ..security import Principal, require_admin, require_auth

router = APIRouter(prefix="/servers", tags=["servers"])

Environment = Literal["production", "staging", "development", "other"]
SslMode = Literal["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]
Role = Literal["viewer", "operator", "admin"]


class ServerInput(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    description: str | None = Field(None, max_length=300)
    environment: Environment = "other"
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(5432, ge=1, le=65535)
    user: str = Field(min_length=1, max_length=63)
    password: str | None = Field(None, max_length=1024)
    database: str = Field("postgres", min_length=1, max_length=63)
    sslmode: SslMode = "verify-full"
    ssl_ca: str | None = Field(None, max_length=65536)
    connect_timeout: int = Field(5, ge=1, le=30)
    read_only: bool = False
    min_role: Role = "viewer"
    disabled: bool = False


class ServerUpdate(BaseModel):
    """Only fields present in the request are changed. The password is write-only."""

    name: str | None = Field(None, min_length=1, max_length=60)
    description: str | None = Field(None, max_length=300)
    environment: Environment | None = None
    host: str | None = Field(None, min_length=1, max_length=253)
    port: int | None = Field(None, ge=1, le=65535)
    user: str | None = Field(None, min_length=1, max_length=63)
    password: str | None = Field(None, max_length=1024)
    clear_password: bool = False
    database: str | None = Field(None, min_length=1, max_length=63)
    sslmode: SslMode | None = None
    ssl_ca: str | None = Field(None, max_length=65536)
    connect_timeout: int | None = Field(None, ge=1, le=30)
    read_only: bool | None = None
    min_role: Role | None = None
    disabled: bool | None = None


class ServerTest(ServerInput):
    """A connection test. With ``server_id`` and no password, the saved password is used - but only for the
    address it was saved for."""

    server_id: str | None = None
    name: str = Field("test", max_length=60)


# ---------------------------------------------------------------------------
def _registry(request: Request) -> sv.ServerRegistry:
    return request.app.state.servers


def _manage(request: Request) -> None:
    if not get_settings().server_management_enabled:
        raise HTTPException(403, "Server management is turned off on this console (SERVER_MANAGEMENT_ENABLED=false).")


def _visible(p: sv.ServerProfile, me: Principal) -> bool:
    return me.can(p.min_role) and (not p.disabled or me.can("admin"))


async def _profile(request: Request, server_id: str, *, editable: bool = False) -> sv.ServerProfile:
    p = await _registry(request).get(server_id)
    if p is None:
        raise NotFound("Unknown server")
    if editable and p.is_default:
        raise AppError("The default server is configured with environment variables (PG_*) and cannot be changed here.", 400)
    return p


def _safe_password(registry: sv.ServerRegistry, p: sv.ServerProfile) -> str | None:
    if not p.password_enc:
        return None
    if registry.box is None:
        raise SecretsUnavailable()
    return registry.box.decrypt(p.password_enc, f"server:{p.id}:password").plaintext


def _warnings(sslmode: str, environment: str, result: dict[str, Any] | None = None) -> list[str]:
    out = []
    if sslmode in sv.UNENCRYPTED_MODES:
        out.append(f"SSL mode “{sslmode}” can fall back to an unencrypted connection. Use verify-full (or at least require) for anything that crosses a network.")
    elif sslmode == "require":
        out.append("SSL mode “require” encrypts the connection but does not verify the server's identity. verify-full is stronger.")
    if result and result.get("ok"):
        if not result.get("can_create_roles"):
            out.append("This account cannot create roles, so managing users here will be limited. A superuser (or a role with CREATEROLE) works best.")
        if result.get("ssl") is False and sslmode not in ("disable",):
            out.append("The connection that was just made is not encrypted.")
    if environment == "production" and sslmode in sv.UNENCRYPTED_MODES:
        out.append("This is marked as production and is not guaranteed to be encrypted.")
    return out


# ---------------------------------------------------------------------------
# What you may use
# ---------------------------------------------------------------------------
@router.get("")
async def list_servers(request: Request, me: Principal = Depends(require_auth)) -> dict:
    registry, s = _registry(request), get_settings()
    admin = me.can("admin")
    return {
        "items": [p.public(admin=admin) for p in await registry.all() if _visible(p, me)],
        "management_enabled": s.server_management_enabled and admin,
        "encryption": {"ready": registry.box is not None, "fallback_to_secret_key": bool(registry.box and registry.box.from_secret_key)},
        "max": s.max_server_profiles,
        "allowlist_active": bool(s.server_host_allowlist.strip()),
    }


_status_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_STATUS_TTL = 8.0


async def _status_of(registry: sv.ServerRegistry, p: sv.ServerProfile) -> dict[str, Any]:
    hit = _status_cache.get(f"{p.id}:{p.fingerprint()}")
    if hit and time.monotonic() - hit[0] < _STATUS_TTL:
        return hit[1]
    try:
        result = await sv.probe(registry.connection_profile(p))
    except AppError as exc:  # e.g. password cannot be decrypted
        result = {"ok": False, "error": exc.message, "hint": None}
    _status_cache[f"{p.id}:{p.fingerprint()}"] = (time.monotonic(), result)
    return result


@router.get("/status")
async def status(request: Request, me: Principal = Depends(require_auth)) -> dict:
    """Health of every server you may see (checked in parallel, cached for a few seconds)."""
    registry = _registry(request)
    profiles = [p for p in await registry.all() if _visible(p, me) and not p.disabled]
    results = await asyncio.gather(*(_status_of(registry, p) for p in profiles))
    admin = me.can("admin")
    out = {}
    for p, r in zip(profiles, results):
        out[p.id] = r if admin else {k: r[k] for k in ("ok", "latency_ms", "server_version") if k in r}
    return {"items": out}


# ---------------------------------------------------------------------------
# Administration
# ---------------------------------------------------------------------------
async def _check_target(request: Request, host: str) -> str:
    return await sv.validate_host(get_settings(), host)


@router.post("/test")
async def test_connection(body: ServerTest, request: Request, me: Principal = Depends(require_admin)) -> dict:
    """Try a connection without saving anything."""
    _manage(request)
    sv.check_test_rate(me.username)
    registry = _registry(request)
    host = await _check_target(request, body.host)
    ca = sv.validate_ca(body.ssl_ca)
    password = body.password
    if password is None and body.server_id:
        saved = await _profile(request, body.server_id)
        if (saved.host, saved.port, saved.user) != (host, body.port, body.user):
            raise AppError(
                "The saved password is only used for the address it was saved for. Enter the password to test a different host, port or user.", 422
            )
        password = _safe_password(registry, saved) if not saved.is_default else registry.connection_profile(saved).password
    draft = sv.ServerProfile(
        id=f"test-{abs(hash(ca or '')) % 10**8}", name=body.name, description=None, environment=body.environment, host=host,
        port=body.port, user=body.user, database=body.database, sslmode=body.sslmode, ssl_ca=ca,
        connect_timeout=body.connect_timeout, read_only=False, min_role="viewer", disabled=False, source="db", has_password=bool(password),
    )
    result = await sv.probe(registry.connection_profile(draft, password=password or ""))
    async with audited(request, me.username, "server.test", target=f"{host}:{body.port}", target_type="server", server=None) as a:
        a.summary = f"Tested connection to {host}:{body.port} as {body.user}: " + ("ok" if result["ok"] else "failed")
        a.details = {"ok": result["ok"], "sslmode": body.sslmode}
    return {**result, "warnings": _warnings(body.sslmode, body.environment, result)}


@router.post("", status_code=201)
async def create_server(body: ServerInput, request: Request, me: Principal = Depends(require_admin)) -> dict:
    _manage(request)
    registry, s = _registry(request), get_settings()
    if await registry.store.run(sv.db_count) >= s.max_server_profiles:
        raise AppError(f"At most {s.max_server_profiles} servers can be configured.", 409)
    host = await _check_target(request, body.host)
    server_id = sv.new_id(body.name)
    enc = None
    if body.password:
        if registry.box is None:
            raise SecretsUnavailable()
        enc = registry.box.encrypt(body.password, f"server:{server_id}:password")
    profile = sv.ServerProfile(
        id=server_id, name=body.name.strip(), description=(body.description or None), environment=body.environment, host=host,
        port=body.port, user=body.user.strip(), database=body.database.strip(), sslmode=body.sslmode, ssl_ca=sv.validate_ca(body.ssl_ca),
        connect_timeout=body.connect_timeout, read_only=body.read_only, min_role=body.min_role, disabled=body.disabled,
        source="db", has_password=bool(enc), password_enc=enc,
    )
    async with audited(request, me.username, "server.create", target=profile.name, target_type="server", server=profile) as a:
        a.summary = f"Added server “{profile.name}” ({profile.environment}, {host}:{profile.port})"
        a.details = {"environment": profile.environment, "sslmode": profile.sslmode, "read_only": profile.read_only, "min_role": profile.min_role, "password": "set" if enc else "none"}
        await registry.store.run(sv.db_insert, profile, me.username)
    registry.invalidate()
    return profile.public(admin=True)


@router.patch("/{server_id}")
async def update_server(server_id: str, body: ServerUpdate, request: Request, me: Principal = Depends(require_admin)) -> dict:
    _manage(request)
    registry = _registry(request)
    old = await _profile(request, server_id, editable=True)
    given = body.model_fields_set
    new = replace(old)
    if body.name is not None:
        new.name = body.name.strip()
    if "description" in given:
        new.description = (body.description or "").strip() or None
    if body.environment is not None:
        new.environment = body.environment
    if body.host is not None:
        new.host = await _check_target(request, body.host)
    if body.port is not None:
        new.port = body.port
    if body.user is not None:
        new.user = body.user.strip()
    if body.database is not None:
        new.database = body.database.strip()
    if body.sslmode is not None:
        new.sslmode = body.sslmode
    if "ssl_ca" in given:
        new.ssl_ca = sv.validate_ca(body.ssl_ca)
    if body.connect_timeout is not None:
        new.connect_timeout = body.connect_timeout
    if body.read_only is not None:
        new.read_only = body.read_only
    if body.min_role is not None:
        new.min_role = body.min_role
    if body.disabled is not None:
        new.disabled = body.disabled

    # A saved password is only ever sent to the address it was saved for: moving the profile elsewhere means
    # proving you know the password. Otherwise an admin could redirect it to a machine they control.
    moved = (old.host, old.port, old.user) != (new.host, new.port, new.user)
    changes: dict[str, list[Any]] = {}
    pw_note = "unchanged"
    if body.clear_password:
        new.password_enc, new.has_password, pw_note = None, False, "removed"
    elif body.password:
        if registry.box is None:
            raise SecretsUnavailable()
        new.password_enc, new.has_password, pw_note = registry.box.encrypt(body.password, f"server:{old.id}:password"), True, "changed"
    elif moved and old.password_enc:
        raise AppError(
            "Enter the password again when you change the host, port or user. A saved password is only sent to the address it was saved for.", 422
        )

    for f in ("name", "description", "environment", "host", "port", "user", "database", "sslmode", "ssl_ca", "connect_timeout", "read_only", "min_role", "disabled"):
        if getattr(old, f) != getattr(new, f):
            changes[f] = ["(certificate)", "(certificate)"] if f == "ssl_ca" else [getattr(old, f), getattr(new, f)]
    async with audited(request, me.username, "server.update", target=new.name, target_type="server", server=new) as a:
        shown = [f"{k}: {v[0]} → {v[1]}" for k, v in changes.items() if k != "ssl_ca"] + ([f"password {pw_note}"] if pw_note != "unchanged" else [])
        a.summary = f"Updated server “{new.name}”" + (": " + ", ".join(shown) if shown else "")
        a.details = {"changes": changes, "password": pw_note}
        await registry.store.run(sv.db_update, new, me.username)
    registry.invalidate()
    await registry.drop(old.id)  # pools hold the old address/credentials
    return (await _profile(request, server_id)).public(admin=True)


@router.get("/{server_id}/usage")
async def usage(server_id: str, request: Request, me: Principal = Depends(require_admin)) -> dict:
    p = await _profile(request, server_id, editable=True)
    return await _registry(request).store.run(sv.db_usage, p.id)


@router.delete("/{server_id}", status_code=204)
async def delete_server(server_id: str, request: Request, me: Principal = Depends(require_admin)) -> None:
    _manage(request)
    registry = _registry(request)
    p = await _profile(request, server_id, editable=True)
    use = await registry.store.run(sv.db_usage, p.id)
    async with audited(request, me.username, "server.delete", target=p.name, target_type="server", server=p) as a:
        a.summary = f"Removed server “{p.name}”" + (f" ({use['pending_schedules']} scheduled expiries cancelled, {use['snapshots']} snapshots deleted)" if any(use.values()) else "")
        a.details = {"removed": use}
        await registry.store.run(sv.db_delete, p.id)
    registry.invalidate()
    await registry.drop(p.id)
