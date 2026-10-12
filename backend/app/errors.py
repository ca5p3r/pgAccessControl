"""Translate database / domain errors into clean JSON HTTP responses."""

from __future__ import annotations

import logging

import psycopg
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from psycopg_pool import PoolTimeout

log = logging.getLogger("pgac")


class AppError(Exception):
    def __init__(self, message: str, status: int = 400, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.hint = hint


class NotFound(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(message, 404)


_STATE_STATUS = {
    "42501": 403,  # insufficient_privilege
    "42710": 409,  # duplicate_object
    "42P04": 409,  # duplicate_database
    "42P07": 409,  # duplicate_table
    "2BP01": 409,  # dependent_objects_still_exist
    "55006": 409,  # object_in_use
    "42704": 404,  # undefined_object
    "42P01": 404,  # undefined_table
    "42883": 404,  # undefined_function
    "3F000": 404,  # invalid_schema_name
    "3D000": 404,  # invalid_catalog_name
}


def _pg_status(exc: psycopg.Error) -> int:
    state = exc.sqlstate or ""
    if state in _STATE_STATUS:
        return _STATE_STATUS[state]
    if state.startswith(("08", "28", "57")):  # connection / auth / operator intervention
        return 503
    return 400


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse({"detail": exc.message, "hint": exc.hint}, status_code=exc.status)

    @app.exception_handler(PoolTimeout)
    async def _pool_timeout(_: Request, exc: PoolTimeout) -> JSONResponse:
        log.warning("Pool timeout: %s", exc)
        return JSONResponse(
            {"detail": "Could not connect to the PostgreSQL server (timed out).", "hint": "Check PG_* settings."},
            status_code=503,
        )

    @app.exception_handler(psycopg.OperationalError)
    async def _operational(_: Request, exc: psycopg.OperationalError) -> JSONResponse:
        log.warning("Database connection error: %s", exc)
        return JSONResponse({"detail": "PostgreSQL connection failed: " + str(exc).strip()}, status_code=503)

    @app.exception_handler(psycopg.Error)
    async def _pg_error(_: Request, exc: psycopg.Error) -> JSONResponse:
        diag = exc.diag
        message = diag.message_primary or str(exc)
        hint = diag.message_hint or diag.message_detail
        status = _pg_status(exc)
        if status >= 500:
            log.error("Database error: %s", exc)
        return JSONResponse({"detail": message, "hint": hint, "sqlstate": exc.sqlstate}, status_code=status)
