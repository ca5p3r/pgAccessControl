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

    local_login_enabled: bool = True  # username/password sign-in (the env admin and app accounts)

    # --- Single sign-on (OpenID Connect, authorization code flow with PKCE) ---
    oidc_issuer: str = ""  # e.g. https://login.example.com/realms/corp ; empty disables SSO
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_redirect_uri: str = ""  # default: <request base url>/api/auth/oidc/callback
    oidc_scopes: str = "openid email profile"
    oidc_username_claim: str = "preferred_username"
    oidc_groups_claim: str = "groups"
    oidc_admin_groups: str = ""  # comma separated group names that map to each app role
    oidc_operator_groups: str = ""
    oidc_viewer_groups: str = ""
    oidc_default_role: str = ""  # role for signed-in users matching no group; empty = deny
    oidc_button_label: str = "Sign in with SSO"

    # --- App data (accounts, temporary access schedules, snapshots): SQLite, separate from the audit file ---
    data_db_path: str = "data/app.db"
    scheduler_interval_seconds: int = 30
    drift_check_interval_minutes: int = 0  # 0 = off; otherwise compare snapshots marked "baseline" this often

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
        if self.auth_enabled and self.local_login_enabled and not self.admin_password:
            raise ValueError(
                "ADMIN_PASSWORD must be set (or set AUTH_ENABLED=false to disable the login screen, "
                "or LOCAL_LOGIN_ENABLED=false when using SSO only)"
            )
        if self.auth_enabled and not self.local_login_enabled and not self.oidc_enabled:
            raise ValueError("LOCAL_LOGIN_ENABLED=false needs SSO: set OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET")
        if self.oidc_default_role and self.oidc_default_role not in ("viewer", "operator", "admin"):
            raise ValueError("OIDC_DEFAULT_ROLE must be viewer, operator, admin or empty")
        if not self.secret_key:
            self.secret_key = secrets.token_urlsafe(48)
            if self.auth_enabled:
                log.warning(
                    "SECRET_KEY is not set: using a random key. Sessions will be invalidated on "
                    "restart and will not work across multiple workers/replicas."
                )
        return self

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    @staticmethod
    def split_groups(value: str) -> set[str]:
        return {g.strip() for g in value.split(",") if g.strip()}

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
