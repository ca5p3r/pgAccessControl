from __future__ import annotations

from fastapi import Request

from .db import PoolManager
from .servers import resolve_server, scoped_principal


async def get_pools(request: Request) -> PoolManager:
    """The connection pools of the server this request is about (``?server=`` or ``X-PGAC-Server``)."""
    if getattr(request.state, "principal", None) is None:
        await scoped_principal(request)  # defence in depth: visibility and read-only caps are always applied
    profile = await resolve_server(request)
    return await request.app.state.servers.manager(profile)
