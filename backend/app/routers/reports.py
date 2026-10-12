from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from ..audit import log_event
from ..csvutil import to_csv
from ..db import PoolManager
from ..deps import get_pools
from ..security import Principal, require_auth
from ..services import reports as svc

router = APIRouter(tags=["reports"])

ObjectKind = Literal["database", "schema", "table", "sequence", "function"]


@router.get("/objects")
async def objects(
    database: str,
    type: ObjectKind = "table",
    schema: str | None = None,
    q: str | None = Query(None, max_length=100),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    pools: PoolManager = Depends(get_pools),
) -> dict:
    """Role-independent object search, used by the report object picker."""
    async with pools.connection(database) as conn:
        return await svc.search_objects(conn, type, schema=schema, q=q, limit=limit, offset=offset)


@router.get("/access-report")
async def access_report(database: str, type: ObjectKind, oid: int, pools: PoolManager = Depends(get_pools)) -> dict:
    """Every user and role that can access one object, and why (direct / PUBLIC / inherited role)."""
    async with pools.connection(database) as conn:
        return await svc.access_report(conn, type, oid)


def _filename(base: str, ext: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_") or "export"
    return f"pgac-{safe}-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{ext}"


@router.get("/export")
async def export(
    request: Request,
    format: Literal["sql", "csv", "json"] = "sql",
    database: str | None = None,
    role: str | None = Query(None, description='Limit to one role (or "PUBLIC")'),
    dataset: Literal["privileges", "roles", "memberships", "defaults"] = "privileges",
    pools: PoolManager = Depends(get_pools),
    me: Principal = Depends(require_auth),
) -> StreamingResponse:
    """Download permissions as a SQL script, CSV (one dataset) or JSON, for a database or a single role."""
    async with pools.connection(database) as conn:
        data = await svc.export_data(conn, role)
        scope = role or "all"
        if format == "sql":
            body = "".join(svc.render_sql(conn, data))
            media, name = "application/sql; charset=utf-8", _filename(f"{data['database']}-{scope}", "sql")
            chunks = iter([body])
        elif format == "json":
            body = json.dumps(data, indent=2, default=str)
            media, name = "application/json", _filename(f"{data['database']}-{scope}", "json")
            chunks = iter([body])
        else:
            header, rows = svc.csv_rows(data, dataset)
            media, name = "text/csv; charset=utf-8", _filename(f"{data['database']}-{scope}-{dataset}", "csv")
            chunks = to_csv(header, rows)
    await log_event(request, me.username, "export.permissions", f"Exported {format.upper()} {scope} from {data['database']}")
    return StreamingResponse(chunks, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})
