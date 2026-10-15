"""Permission snapshots and drift detection."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field

from ..audit import audited
from ..db import PoolManager
from ..deps import get_pools
from ..errors import AppError, NotFound
from ..security import Principal, require_operator
from ..services import drift

router = APIRouter(prefix="/snapshots", tags=["snapshots"])


class SnapshotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    note: str | None = Field(None, max_length=500)
    database: str
    baseline: bool = False  # the reference the scheduled drift check compares against


async def _load(request: Request, snapshot_id: int):
    """Load a snapshot, but only if it belongs to the selected server (otherwise it does not exist)."""
    meta, data = await drift.load(request.app, snapshot_id)
    if meta["server_id"] != request.state.server.id:
        raise NotFound(f"Snapshot {snapshot_id} does not exist")
    return meta, data


@router.get("")
async def list_snapshots(request: Request) -> dict:
    return {"items": await request.app.state.store.run(drift.db_list, request.state.server.id), "check_interval_minutes": _interval(request)}


def _interval(request: Request) -> int:
    from ..config import get_settings

    return get_settings().drift_check_interval_minutes


@router.post("", status_code=201)
async def create_snapshot(
    body: SnapshotCreate, request: Request, pools: PoolManager = Depends(get_pools), me: Principal = Depends(require_operator)
) -> dict:
    async with audited(request, me.username, "snapshot.create", target=body.name, target_type="snapshot", database=body.database) as a:
        a.summary = f"Saved snapshot “{body.name}” of {body.database}" + (" as baseline" if body.baseline else "")
        async with pools.connection(body.database) as conn:
            data = await drift.capture(conn)
        a.details = {"counts": drift.counts(data)}
        try:
            sid = await request.app.state.store.run(
                drift.db_insert, request.state.server.id, body.name.strip(), body.note, body.database, me.username, body.baseline, data
            )
        except sqlite3.IntegrityError:
            raise AppError(f"A snapshot named “{body.name}” already exists for {body.database}.", 409) from None
    meta, _ = await _load(request, sid)
    return meta


@router.delete("/{snapshot_id}", status_code=204)
async def delete_snapshot(snapshot_id: int, request: Request, me: Principal = Depends(require_operator)) -> None:
    meta, _ = await _load(request, snapshot_id)
    async with audited(request, me.username, "snapshot.delete", target=meta["name"], target_type="snapshot", database=meta["database"]) as a:
        a.summary = f"Deleted snapshot “{meta['name']}”"
        await request.app.state.store.run(drift.db_delete, snapshot_id)


class BaselineBody(BaseModel):
    baseline: bool = True


@router.post("/{snapshot_id}/baseline")
async def set_baseline(snapshot_id: int, body: BaselineBody, request: Request, me: Principal = Depends(require_operator)) -> dict:
    meta, _ = await _load(request, snapshot_id)
    async with audited(request, me.username, "snapshot.baseline", target=meta["name"], target_type="snapshot", database=meta["database"]) as a:
        a.summary = f"{'Marked' if body.baseline else 'Unmarked'} snapshot “{meta['name']}” as the baseline for {meta['database']}"
        await request.app.state.store.run(drift.db_set_baseline, snapshot_id, body.baseline)
    return (await _load(request, snapshot_id))[0]


@router.get("/{snapshot_id}/download")
async def download(snapshot_id: int, request: Request) -> Response:
    meta, data = await _load(request, snapshot_id)
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", meta["name"]).strip("_") or "snapshot"
    return Response(
        json.dumps({"snapshot": meta, "data": data}, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="pgac-snapshot-{safe}.json"'},
    )


async def _diff(request: Request, pools: PoolManager, snapshot_id: int, against: int | None):
    meta, old = await _load(request, snapshot_id)
    if against is not None:
        other, new = await _load(request, against)
        target = {"kind": "snapshot", "id": other["id"], "name": other["name"], "at": other["created_at"]}
    else:
        async with pools.connection(meta["database"]) as conn:
            new = await drift.capture(conn)
        target = {"kind": "live", "name": "live server", "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    return meta, drift.compare(old, new), target


@router.get("/{snapshot_id}/drift")
async def drift_report(
    snapshot_id: int, request: Request, against: int | None = None, limit: int = Query(500, ge=1, le=5000), pools: PoolManager = Depends(get_pools)
) -> dict:
    """What changed between the snapshot and the live server (or another snapshot via ``against``)."""
    meta, diff, target = await _diff(request, pools, snapshot_id, against)
    return {"snapshot": meta, "compared_with": target, **drift.capped(diff, limit)}


@router.get("/{snapshot_id}/remediation")
async def remediation_script(
    snapshot_id: int, request: Request, against: int | None = None, pools: PoolManager = Depends(get_pools)
) -> Response:
    """SQL that would bring the live server back to the snapshot. Never executed by the app."""
    meta, diff, target = await _diff(request, pools, snapshot_id, against)
    if target["kind"] != "live":
        raise AppError("Remediation SQL is only generated against the live server.", 400)
    async with pools.connection(meta["database"]) as conn:
        script = "".join(drift.remediation(conn, diff, meta["database"]))
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", meta["name"]).strip("_") or "snapshot"
    return Response(script, media_type="application/sql; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="pgac-remediate-{safe}.sql"'})

