"""Application settings, loaded from environment variables (and an optional .env file)."""

from __future__ import annotations

import logging
import secrets
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger("pgac.config")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- PostgreSQL server being administered -------------------------------
    pg_host: str = "localhost"
    pg_port: int = 5432
    pg_user: str = "postgres"
    pg_password: str = ""
    pg_database: str = "postgres"  # maintenance database used for cluster-wide queries
    pg_sslmode: str = "prefer"
    pg_connect_timeout: int = 5
    pg_application_name: str = "pgAccessControl"

    # --- Connection pooling (one pool per database that is inspected) -------
    pool_min_size: int = 1
    pool_max_size: int = 5
    pool_max_idle_seconds: int = 300
    pool_acquire_timeout: float = 10.0
    pool_max_databases: int = 8  # least-recently-used pools beyond this are closed

    # --- Authentication for this web app ------------------------------------
    auth_enabled: bool = True
    admin_username: str = "admin"
    admin_password: str = ""
    secret_key: str = ""
    session_ttl_minutes: int = 480
    cookie_secure: bool = False  # set true when served over HTTPS

    # --- Audit history (SQLite file; mount a volume on its directory in Docker) ---
    audit_enabled: bool = True
    audit_db_path: str = "data/audit.db"
    audit_retention_days: int = 365  # 0 keeps everything

    # --- HTTP server --------------------------------------------------------
    host: str = "0.0.0.0"
    port: int = 8000
    log_level: str = "info"
    workers: int = 1
    cors_origins: str = ""  # comma separated; only needed when UI is served from another origin
    static_dir: str = "static"  # built frontend, served by the API when present

    @model_validator(mode="after")
    def _check(self) -> "Settings":
        if self.auth_enabled and not self.admin_password:
            raise ValueError(
                "ADMIN_PASSWORD must be set (or set AUTH_ENABLED=false to disable the login screen)"
            )
        if not self.secret_key:
            self.secret_key = secrets.token_urlsafe(48)
            if self.auth_enabled:
                log.warning(
                    "SECRET_KEY is not set: using a random key. Sessions will be invalidated on "
                    "restart and will not work across multiple workers/replicas."
                )
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
