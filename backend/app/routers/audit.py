from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from ..audit import EXPORT_LIMIT, AuditStore
from ..csvutil import to_csv
from ..security import Principal, require_auth

router = APIRouter(prefix="/audit", tags=["audit"])

_DATE = r"^\d{4}-\d{2}-\d{2}$"


def _store(request: Request) -> AuditStore:
    return request.app.state.audit


async def _filters(
    request: Request,
    me: Principal = Depends(require_auth),
    actor: str | None = None,
    action: str | None = Query(None, description='Prefix match: "role." or "permission.apply"'),
    target: str | None = None,
    database: str | None = None,
    server: str | None = Query(None, description='Server id, or "*" for every server you may see'),
    status: Literal["success", "failed"] | None = None,
    q: str | None = Query(None, max_length=200),
    date_from: str | None = Query(None, pattern=_DATE),
    date_to: str | None = Query(None, pattern=_DATE),
) -> dict[str, Any]:
    f: dict[str, Any] = {
        k: v for k, v in dict(actor=actor, action=action, target=target, database=database, status=status, q=q,
                              date_from=date_from, date_to=date_to).items() if v
    }
    # Only servers this user may see: the audit trail of a hidden server is as hidden as the server itself.
    allowed = [p.id for p in await request.app.state.servers.all() if me.can(p.min_role) and (not p.disabled or me.can("admin"))]
    if server and server != "*":
        # Admins may look at any server's history, including servers that have since been removed.
        f["server"] = server if (server in allowed or me.can("admin")) else "\0none"  # matches nothing
    elif not me.can("admin"):
        f["servers_in"] = allowed
    return f


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
async def facets(request: Request, me: Principal = Depends(require_auth)) -> dict:
    data = await _store(request).facets()
    visible = {p.id for p in await request.app.state.servers.all() if me.can(p.min_role)}
    data["servers"] = [s for s in data["servers"] if s["id"] in visible]
    return data


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
