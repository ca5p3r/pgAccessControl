from __future__ import annotations

from fastapi import Request

from .db import PoolManager


def get_pools(request: Request) -> PoolManager:
    return request.app.state.pools
