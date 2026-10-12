from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from ..audit import EXPORT_LIMIT, AuditStore
from ..csvutil import to_csv

router = APIRouter(prefix="/audit", tags=["audit"])

_DATE = r"^\d{4}-\d{2}-\d{2}$"


def _store(request: Request) -> AuditStore:
    return request.app.state.audit


def _filters(
    actor: str | None = None,
    action: str | None = Query(None, description='Prefix match: "role." or "permission.apply"'),
    target: str | None = None,
    database: str | None = None,
    status: Literal["success", "failed"] | None = None,
    q: str | None = Query(None, max_length=200),
    date_from: str | None = Query(None, pattern=_DATE),
    date_to: str | None = Query(None, pattern=_DATE),
) -> dict[str, Any]:
    return {k: v for k, v in locals().items() if v}


@router.get("")
async def list_audit(
    request: Request,
    f: dict[str, Any] = Depends(_filters),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> dict:
    store = _store(request)
    items, total = await store.query(f, limit, offset)
    return {"items": items, "total": total, "enabled": store.enabled, "retention_days": store.retention_days}


@router.get("/facets")
async def facets(request: Request) -> dict:
    return await _store(request).facets()


@router.get("/export")
async def export(
    request: Request, f: dict[str, Any] = Depends(_filters), format: Literal["csv", "json"] = "csv"
) -> StreamingResponse:
    items, total = await _store(request).query(f, EXPORT_LIMIT, 0)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    headers = {"Content-Disposition": f'attachment; filename="pgac-audit-{stamp}.{format}"', "X-Total-Count": str(total)}
    if format == "json":
        body = json.dumps({"exported_at": stamp, "total": total, "truncated": total > len(items), "entries": items}, indent=2)
        return StreamingResponse(iter([body]), media_type="application/json", headers=headers)
    header = ["time_utc", "actor", "ip", "action", "target", "database", "status", "summary", "error", "sql"]
    rows = (
        [e["ts"], e["actor"], e["ip"], e["action"], e["target"], e["database"], e["status"], e["summary"], e["error"], "\n".join(e["statements"])]
        for e in items
    )
    return StreamingResponse(to_csv(header, rows), media_type="text/csv; charset=utf-8", headers=headers)
