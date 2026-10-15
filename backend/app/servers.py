"""Server profiles: several PostgreSQL servers managed from one console.

* The server configured with ``PG_*`` environment variables is always available as the profile ``default``
  (its password never touches the database). More profiles are added in the UI by admins and stored in the
  app database, with passwords encrypted (see ``crypto.py``).
* Every API request names the server it is about (``?server=<id>``, or the ``X-PGAC-Server`` header); the
  server validates it on every request, so the browser is never trusted to say what it may use.
* A profile can be **read-only** (the console caps everyone to viewer on it, enforced here, not in the UI)
  and can require a **minimum role** to be seen at all.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import os
import re
import secrets
import socket
import sqlite3
import tempfile
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psycopg
from fastapi import HTTPException, Request

from .config import Settings
from .crypto import SecretBox, SecretsUnavailable
from .db import ConnectionProfile, PoolManager, build_conninfo
from .errors import AppError
from .security import Principal, require_auth
from .store import DEFAULT_SERVER, AppStore

log = logging.getLogger("pgac.servers")

ENVIRONMENTS = ("production", "staging", "development", "other")
SSL_MODES = ("disable", "allow", "prefer", "require", "verify-ca", "verify-full")
UNENCRYPTED_MODES = {"disable", "allow", "prefer"}  # may fall back to plain text
ROLE_ORDER = {"viewer": 1, "operator": 2, "admin": 3}

# Cloud metadata / link-local ranges: nobody legitimately runs PostgreSQL there, and they are the classic
# SSRF target (credentials of the machine the console runs on).
_BLOCKED_NETWORKS = [
    ipaddress.ip_network(n)
    for n in ("169.254.0.0/16", "fe80::/10", "fd00:ec2::/32", "0.0.0.0/8", "224.0.0.0/4", "ff00::/8", "::/128")
]
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9._-]{0,251}[A-Za-z0-9])?$")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
@dataclass
class ServerProfile:
    id: str
    name: str
    description: str | None
    environment: str
    host: str
    port: int
    user: str
    database: str
    sslmode: str
    ssl_ca: str | None
    connect_timeout: int
    read_only: bool
    min_role: str
    disabled: bool
    source: str  # "env" (PG_* variables) or "db" (added in the UI)
    has_password: bool
    password_enc: str | None = field(default=None, repr=False)
    created_at: str | None = None
    created_by: str | None = None
    updated_at: str | None = None
    updated_by: str | None = None

    @property
    def is_default(self) -> bool:
        return self.source == "env"

    def public(self, *, admin: bool) -> dict[str, Any]:
        """What the API returns. Secrets are never included; connection details only for admins."""
        d: dict[str, Any] = {
            "id": self.id, "name": self.name, "description": self.description, "environment": self.environment,
            "read_only": self.read_only, "min_role": self.min_role, "disabled": self.disabled,
            "is_default": self.is_default, "encrypted_connection": self.sslmode not in UNENCRYPTED_MODES,
        }
        if admin:
            d.update(
                host=self.host, port=self.port, user=self.user, database=self.database, sslmode=self.sslmode,
                ssl_ca=self.ssl_ca, connect_timeout=self.connect_timeout, has_password=self.has_password,
                created_at=self.created_at, created_by=self.created_by, updated_at=self.updated_at, updated_by=self.updated_by,
            )
        return d

    def fingerprint(self) -> str:
        parts = (self.host, self.port, self.user, self.database, self.sslmode, self.ssl_ca, self.connect_timeout, self.password_enc, self.source)
        return hashlib.sha256(repr(parts).encode()).hexdigest()


def env_profile(s: Settings) -> ServerProfile:
    return ServerProfile(
        id=DEFAULT_SERVER, name=s.pg_server_name, description=None, environment=s.pg_environment, host=s.pg_host,
        port=s.pg_port, user=s.pg_user, database=s.pg_database, sslmode=s.pg_sslmode, ssl_ca=None,
        connect_timeout=s.pg_connect_timeout, read_only=s.pg_read_only, min_role="viewer", disabled=False,
        source="env", has_password=bool(s.pg_password),
    )


# ---------------------------------------------------------------------------
# Validation (hosts, certificates, names)
# ---------------------------------------------------------------------------
def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(a[4][0].split("%")[0]) for a in socket.getaddrinfo(host, None)]
    except (socket.gaierror, ValueError, UnicodeError):
        return []


def _allowlist_match(entry: str, host: str, addrs: list[Any]) -> bool:
    entry = entry.strip().lower()
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            return False
        return any(a in net for a in addrs)
    if entry.startswith("*."):
        return host.lower().endswith(entry[1:])
    return host.lower() == entry


async def validate_host(settings: Settings, host: str) -> str:
    """Reject hosts the console must not connect to. Best effort: DNS can change after this check."""
    host = (host or "").strip()
    if not host or len(host) > 253:
        raise AppError("Enter a host name or IP address.", 422)
    literal: Any = None
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
        host = str(literal)
    except ValueError:
        if host.startswith("/") or not _HOST_RE.match(host):
            raise AppError("The host may only contain letters, digits, dots, hyphens and underscores (no paths or URLs).", 422) from None
    addrs = [literal] if literal else await asyncio.to_thread(_resolve, host)
    if any(a in net for a in addrs for net in _BLOCKED_NETWORKS):
        raise AppError("That address is not allowed (link-local and cloud metadata addresses are blocked).", 422)
    allow = [e for e in settings.server_host_allowlist.split(",") if e.strip()]
    if allow and not any(_allowlist_match(e, host, addrs) for e in allow):
        raise AppError("That host is not on this console's allowed list (SERVER_HOST_ALLOWLIST).", 403)
    return host


def validate_ca(pem: str | None) -> str | None:
    if pem is None or not pem.strip():
        return None
    pem = pem.strip().replace("\r\n", "\n")
    if "PRIVATE KEY" in pem:
        raise AppError("That looks like a private key. Paste only the public CA certificate.", 422)
    if "BEGIN CERTIFICATE" not in pem or "END CERTIFICATE" not in pem:
        raise AppError("The CA certificate must be PEM text (BEGIN CERTIFICATE … END CERTIFICATE).", 422)
    if not re.fullmatch(r"[A-Za-z0-9+/=\-\s]+", pem):
        raise AppError("The CA certificate contains unexpected characters.", 422)
    return pem + "\n"


def slugify(name: str) -> str:
    return (re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "server")[:28]


# ---------------------------------------------------------------------------
# Storage (sync functions, run through AppStore.run)
# ---------------------------------------------------------------------------
def _from_row(r: sqlite3.Row) -> ServerProfile:
    return ServerProfile(
        id=r["id"], name=r["name"], description=r["description"], environment=r["environment"], host=r["host"],
        port=r["port"], user=r["username"], database=r["database"], sslmode=r["sslmode"], ssl_ca=r["ssl_ca"],
        connect_timeout=r["connect_timeout"], read_only=bool(r["read_only"]), min_role=r["min_role"],
        disabled=bool(r["disabled"]), source="db", has_password=bool(r["password_enc"]), password_enc=r["password_enc"],
        created_at=r["created_at"], created_by=r["created_by"], updated_at=r["updated_at"], updated_by=r["updated_by"],
    )


def db_list(c: sqlite3.Connection) -> list[ServerProfile]:
    return [_from_row(r) for r in c.execute("SELECT * FROM servers ORDER BY name COLLATE NOCASE")]


def db_get(c: sqlite3.Connection, server_id: str) -> ServerProfile | None:
    r = c.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
    return _from_row(r) if r else None


def db_count(c: sqlite3.Connection) -> int:
    return int(c.execute("SELECT count(*) FROM servers").fetchone()[0])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def db_insert(c: sqlite3.Connection, p: ServerProfile, by: str) -> None:
    try:
        c.execute(
            """INSERT INTO servers (id, name, description, environment, host, port, username, password_enc, database, sslmode,
                                    ssl_ca, connect_timeout, read_only, min_role, disabled, created_at, created_by, updated_at, updated_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (p.id, p.name, p.description, p.environment, p.host, p.port, p.user, p.password_enc, p.database, p.sslmode,
             p.ssl_ca, p.connect_timeout, int(p.read_only), p.min_role, int(p.disabled), _now(), by, _now(), by),
        )
    except sqlite3.IntegrityError:
        raise AppError(f'A server named "{p.name}" already exists.', 409) from None


def db_update(c: sqlite3.Connection, p: ServerProfile, by: str) -> None:
    try:
        c.execute(
            """UPDATE servers SET name=?, description=?, environment=?, host=?, port=?, username=?, password_enc=?, database=?,
                      sslmode=?, ssl_ca=?, connect_timeout=?, read_only=?, min_role=?, disabled=?, updated_at=?, updated_by=?
                WHERE id=?""",
            (p.name, p.description, p.environment, p.host, p.port, p.user, p.password_enc, p.database, p.sslmode, p.ssl_ca,
             p.connect_timeout, int(p.read_only), p.min_role, int(p.disabled), _now(), by, p.id),
        )
    except sqlite3.IntegrityError:
        raise AppError(f'A server named "{p.name}" already exists.', 409) from None


def db_set_password(c: sqlite3.Connection, server_id: str, enc: str) -> None:
    c.execute("UPDATE servers SET password_enc = ? WHERE id = ?", (enc, server_id))


def db_usage(c: sqlite3.Connection, server_id: str) -> dict[str, int]:
    return {
        "pending_schedules": int(c.execute("SELECT count(*) FROM expiring_access WHERE server_id = ? AND status IN ('pending','running')", (server_id,)).fetchone()[0]),
        "snapshots": int(c.execute("SELECT count(*) FROM snapshots WHERE server_id = ?", (server_id,)).fetchone()[0]),
    }


def db_delete(c: sqlite3.Connection, server_id: str) -> None:
    """Remove a profile. Its pending schedules are cancelled (they could not run any more) and its snapshots deleted."""
    c.execute(
        "UPDATE expiring_access SET status = 'cancelled', finished_at = ?, error = 'server removed' WHERE server_id = ? AND status IN ('pending','running','failed')",
        (_now(), server_id),
    )
    c.execute("DELETE FROM snapshots WHERE server_id = ?", (server_id,))
    c.execute("DELETE FROM servers WHERE id = ?", (server_id,))


# ---------------------------------------------------------------------------
# Probing a connection
# ---------------------------------------------------------------------------
_HINTS = (
    ("password authentication failed", "Check the user name and password."),
    ("no pg_hba.conf entry", "The server's pg_hba.conf does not allow this console's address, user or SSL setting. Ask the database administrator to add an entry."),
    ("timeout", "The host did not answer. Check the address, the port and any firewall between this console and the server."),
    ("timed out", "The host did not answer. Check the address, the port and any firewall between this console and the server."),
    ("could not translate host name", "The host name does not resolve. Check the spelling and DNS."),
    ("name or service not known", "The host name does not resolve. Check the spelling and DNS."),
    ("connection refused", "Nothing is listening on that host and port. Check the port and that PostgreSQL is running."),
    ("certificate", "The server's certificate was not accepted. Check the SSL mode and the CA certificate."),
    ("ssl", "A secure connection could not be set up. Check the SSL mode (and CA certificate for verify-ca / verify-full)."),
    ("does not exist", "The database does not exist. Check the maintenance database name."),
)


def explain(exc: BaseException) -> tuple[str, str | None]:
    text = " ".join(str(exc).split())[:400] or type(exc).__name__
    low = text.lower()
    return text, next((h for k, h in _HINTS if k in low), None)


async def probe(conn_profile: ConnectionProfile) -> dict[str, Any]:
    """Try to connect and report basic facts. Never raises."""
    started = time.monotonic()
    try:
        conn = await asyncio.wait_for(
            psycopg.AsyncConnection.connect(**build_conninfo(conn_profile, conn_profile.database), autocommit=True),
            timeout=conn_profile.connect_timeout + 3,
        )
    except Exception as exc:  # noqa: BLE001
        error, hint = explain(exc)
        return {"ok": False, "error": error, "hint": hint}
    try:
        async with conn:
            cur = await conn.execute(
                """SELECT current_setting('server_version') AS version, current_user AS user, r.rolsuper, r.rolcreaterole,
                          COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) AS ssl
                     FROM pg_roles r WHERE r.rolname = current_user"""
            )
            row = await cur.fetchone()
        return {
            "ok": True, "latency_ms": round((time.monotonic() - started) * 1000), "server_version": row["version"],
            "connected_as": row["user"], "is_superuser": row["rolsuper"],
            "can_create_roles": bool(row["rolsuper"] or row["rolcreaterole"]), "ssl": bool(row["ssl"]),
        }
    except Exception as exc:  # noqa: BLE001
        error, hint = explain(exc)
        return {"ok": False, "error": error, "hint": hint}


# ---------------------------------------------------------------------------
# Registry: profiles + one PoolManager per server
# ---------------------------------------------------------------------------
@dataclass
class _Managed:
    fingerprint: str
    manager: PoolManager
    last_used: float


class ServerRegistry:
    _TTL = 3.0  # seconds profile changes made by another worker take to be noticed

    def __init__(self, settings: Settings, store: AppStore, box: SecretBox | None) -> None:
        self.s, self.store, self.box = settings, store, box
        self.env = env_profile(settings)
        self._cache: tuple[float, list[ServerProfile]] | None = None
        self._managers: OrderedDict[str, _Managed] = OrderedDict()
        self._lock = asyncio.Lock()
        self._ca_dir = Path(tempfile.gettempdir()) / "pgac-ca"

    # -- profiles -------------------------------------------------------
    async def all(self) -> list[ServerProfile]:
        if self._cache and time.monotonic() - self._cache[0] < self._TTL:
            return self._cache[1]
        rows = await self.store.run(db_list)
        profiles = [self.env, *rows]
        self._cache = (time.monotonic(), profiles)
        return profiles

    async def get(self, server_id: str) -> ServerProfile | None:
        return next((p for p in await self.all() if p.id == server_id), None)

    def invalidate(self) -> None:
        self._cache = None

    # -- connections ----------------------------------------------------
    def _ca_file(self, p: ServerProfile) -> str | None:
        if not p.ssl_ca:
            return None
        self._ca_dir.mkdir(mode=0o700, exist_ok=True)
        path = self._ca_dir / f"{p.id}-{hashlib.sha256(p.ssl_ca.encode()).hexdigest()[:10]}.crt"
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(p.ssl_ca)
        return str(path)

    def connection_profile(self, p: ServerProfile, *, password: str | None = None) -> ConnectionProfile:
        """The ConnectionProfile for a server, decrypting its saved password (or using ``password`` if given)."""
        if p.source == "env":
            return ConnectionProfile.from_settings(self.s)
        plain = password
        if plain is None and p.password_enc:
            if self.box is None:
                raise SecretsUnavailable()
            plain = self.box.decrypt(p.password_enc, f"server:{p.id}:password").plaintext
        return ConnectionProfile(
            host=p.host, port=p.port, user=p.user, password=plain or "", database=p.database, sslmode=p.sslmode,
            sslrootcert=self._ca_file(p), connect_timeout=p.connect_timeout, application_name=self.s.pg_application_name,
        )

    async def manager(self, p: ServerProfile) -> PoolManager:
        fp = p.fingerprint()
        stale: PoolManager | None = None
        evicted: list[PoolManager] = []
        async with self._lock:
            cur = self._managers.get(p.id)
            if cur and cur.fingerprint == fp:
                cur.last_used = time.monotonic()
                self._managers.move_to_end(p.id)
                return cur.manager
            if cur:  # credentials or address changed: the old pools must not be reused
                stale = cur.manager
                del self._managers[p.id]
            mgr = PoolManager(self.s, self.connection_profile(p))
            self._managers[p.id] = _Managed(fp, mgr, time.monotonic())
            while len(self._managers) > max(2, self.s.max_open_servers):
                victim = next((k for k, v in self._managers.items() if k not in (DEFAULT_SERVER, p.id) and not v.manager.busy), None)
                if victim is None:
                    break
                evicted.append(self._managers.pop(victim).manager)
        for m in ([stale] if stale else []) + evicted:
            await m.close()
        return mgr

    async def drop(self, server_id: str) -> None:
        async with self._lock:
            cur = self._managers.pop(server_id, None)
        if cur:
            await cur.manager.close()

    async def close(self) -> None:
        async with self._lock:
            managers, self._managers = [m.manager for m in self._managers.values()], OrderedDict()
        await asyncio.gather(*(m.close() for m in managers), return_exceptions=True)

    # -- credentials housekeeping --------------------------------------
    async def reencrypt(self) -> int:
        """Re-encrypt passwords that still use a previous key (after a key rotation)."""
        if self.box is None:
            return 0
        done = 0
        for p in await self.store.run(db_list):
            if not p.password_enc:
                continue
            try:
                res = self.box.decrypt(p.password_enc, f"server:{p.id}:password")
            except AppError as exc:
                log.error("Server %r: %s", p.name, exc.message)
                continue
            if not res.current_key:
                await self.store.run(db_set_password, p.id, self.box.encrypt(res.plaintext, f"server:{p.id}:password"))
                done += 1
        if done:
            self.invalidate()
            log.info("Re-encrypted %d saved server password(s) with the current key", done)
        return done


# ---------------------------------------------------------------------------
# Request scoping
# ---------------------------------------------------------------------------
async def resolve_server(request: Request) -> ServerProfile:
    """The server this request is about. Unknown, disabled and hidden servers all look the same (404)."""
    cached = getattr(request.state, "server", None)
    if cached is not None:
        return cached
    server_id = request.query_params.get("server") or request.headers.get("x-pgac-server") or DEFAULT_SERVER
    profile = await request.app.state.servers.get(server_id)
    if profile is None or profile.disabled:
        raise HTTPException(404, "Unknown server")
    request.state.server = profile
    return profile


async def scoped_principal(request: Request) -> Principal:
    """Signed-in principal, adjusted for the selected server: hidden servers are refused and read-only
    servers cap everyone to viewer. Sets ``request.state.principal`` so role checks see the capped role."""
    principal = await require_auth(request)
    profile = await resolve_server(request)
    if ROLE_ORDER[principal.role] < ROLE_ORDER[profile.min_role]:
        raise HTTPException(404, "Unknown server")
    if profile.read_only and principal.role != "viewer":
        principal = replace(principal, role="viewer", capped=True)
    request.state.principal = principal
    return principal


# Throttle for "test connection" so the console cannot be used as a port scanner.
_tests: dict[str, deque[float]] = defaultdict(deque)


def check_test_rate(user: str, limit: int = 15, window: float = 60.0) -> None:
    now = time.monotonic()
    q = _tests[user]
    while q and now - q[0] > window:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many connection tests. Try again in a minute.")
    q.append(now)


def new_id(name: str) -> str:
    return f"{slugify(name)}-{secrets.token_hex(2)}"

