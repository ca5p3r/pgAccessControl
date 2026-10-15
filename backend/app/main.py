from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse

from .accounts import Accounts
from .crypto import SecretBox
from .audit import AuditStore
from .oidc import OIDCClient
from .store import AppStore
from .config import get_settings
from .db import PoolManager
from .errors import install_error_handlers
from .routers import app_users, audit, auth, meta, permissions, reports, roles, snapshots, temporary
from .routers import servers as servers_router
from .servers import ServerRegistry, scoped_principal
from .scheduler import scheduler_loop
from .security import require_auth

log = logging.getLogger("pgac")


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pools = await app.state.servers.manager(app.state.servers.env)  # the PG_* server
        purge_task = None
        app.state.store.init()
        box = app.state.servers.box
        if box is None:
            log.info("No ENCRYPTION_KEY (and no explicit SECRET_KEY): servers can be added, but only without a saved password.")
        elif box.from_secret_key:
            log.warning("ENCRYPTION_KEY is not set: saved server passwords are encrypted with a key derived from SECRET_KEY. "
                        "Set a dedicated ENCRYPTION_KEY so rotating SECRET_KEY does not lock you out of them.")
        try:
            await app.state.servers.reencrypt()
        except Exception as exc:  # noqa: BLE001
            log.error("Could not re-encrypt saved server passwords: %s", exc)
        try:
            app.state.audit.init()
            purge_task = asyncio.create_task(app.state.audit.purge_loop())
        except Exception as exc:  # e.g. unwritable path: keep the app usable, entries still go to the log
            log.error("Audit history disabled, cannot use %s: %s", settings.audit_db_path, exc)
            app.state.audit.enabled = False
        sched_task = asyncio.create_task(scheduler_loop(app, settings.scheduler_interval_seconds))
        try:
            await app.state.pools.warm_up()
            log.info("Connected to PostgreSQL at %s:%s", settings.pg_host, settings.pg_port)
        except Exception as exc:  # the API keeps running and reports 503s until the server is reachable
            log.warning("PostgreSQL is not reachable yet: %s", exc)
        yield
        sched_task.cancel()
        if purge_task:
            purge_task.cancel()
        await app.state.servers.close()

    app = FastAPI(
        title="pgAccessControl",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.audit = AuditStore(settings)
    app.state.store = AppStore(settings.data_db_path)
    app.state.accounts = Accounts(app.state.store, settings.admin_username)
    app.state.servers = ServerRegistry(settings, app.state.store, SecretBox.from_settings(settings))
    app.state.oidc = OIDCClient(settings) if settings.oidc_enabled else None
    install_error_handlers(app)
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    if settings.cors_origin_list:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    api = APIRouter(prefix="/api")

    @api.get("/health")
    async def health() -> dict:
        ok = await app.state.pools.ping()
        return {"status": "ok", "database": "up" if ok else "down"}

    api.include_router(auth.router)
    protected = [Depends(require_auth)]
    # Everything that talks to a PostgreSQL server is scoped to the selected one: the dependency validates the
    # choice, hides servers the user may not see and caps read-only servers to viewer.
    scoped = [Depends(scoped_principal)]
    api.include_router(meta.router, dependencies=scoped)
    api.include_router(roles.router, dependencies=scoped)
    api.include_router(permissions.router, dependencies=scoped)
    api.include_router(reports.router, dependencies=scoped)
    api.include_router(temporary.router, dependencies=scoped)
    api.include_router(snapshots.router, dependencies=scoped)
    api.include_router(audit.router, dependencies=protected)  # filters by the servers you may see itself
    api.include_router(servers_router.router, dependencies=protected)
    api.include_router(app_users.router)  # admin-only; checks its own dependency

    @api.api_route("/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def api_not_found(rest: str) -> JSONResponse:
        return JSONResponse({"detail": "Not found"}, status_code=404)

    app.include_router(api)
    _mount_frontend(app, Path(settings.static_dir))
    return app


def _mount_frontend(app: FastAPI, root: Path) -> None:
    """Serve the built SPA (if present) with long-lived caching for hashed assets."""
    index = root / "index.html"
    if not index.is_file():
        return
    root = root.resolve()

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str) -> FileResponse:
        candidate = (root / path).resolve()
        if path and candidate.is_file() and root in candidate.parents:
            immutable = "assets" in candidate.relative_to(root).parts[:1]
            cache = "public, max-age=31536000, immutable" if immutable else "no-cache"
            return FileResponse(candidate, headers={"Cache-Control": cache})
        return FileResponse(index, headers={"Cache-Control": "no-cache"})


app = create_app()
