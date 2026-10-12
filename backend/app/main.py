from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse

from .config import get_settings
from .db import PoolManager
from .errors import install_error_handlers
from .routers import auth, meta, permissions, roles
from .security import require_auth

log = logging.getLogger("pgac")


def create_app() -> FastAPI:
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.pools = PoolManager(settings)
        try:
            await app.state.pools.warm_up()
            log.info("Connected to PostgreSQL at %s:%s", settings.pg_host, settings.pg_port)
        except Exception as exc:  # the API keeps running and reports 503s until the server is reachable
            log.warning("PostgreSQL is not reachable yet: %s", exc)
        yield
        await app.state.pools.close()

    app = FastAPI(
        title="pgAccessControl",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
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
    api.include_router(meta.router, dependencies=protected)
    api.include_router(roles.router, dependencies=protected)
    api.include_router(permissions.router, dependencies=protected)

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
