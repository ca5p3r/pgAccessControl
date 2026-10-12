"""Request / response models."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

RoleName = Field(min_length=1, max_length=63)


def _clean_name(v: str) -> str:
    v = v.strip()
    if not v or "\x00" in v:
        raise ValueError("name must not be empty")
    if len(v.encode()) > 63:
        raise ValueError("name must be at most 63 bytes")
    return v


# ---------------------------------------------------------------------------
# Roles / users
# ---------------------------------------------------------------------------
class RoleAttributes(BaseModel):
    login: bool | None = None
    superuser: bool | None = None
    createdb: bool | None = None
    createrole: bool | None = None
    inherit: bool | None = None
    replication: bool | None = None
    bypassrls: bool | None = None
    connection_limit: int | None = Field(None, ge=-1)
    valid_until: datetime | None = None
    comment: str | None = Field(None, max_length=2000)


class RoleCreate(RoleAttributes):
    name: str
    password: str | None = Field(None, max_length=1024)
    member_of: list[str] = []
    members: list[str] = []

    _v_name = field_validator("name")(_clean_name)

    @field_validator("name")
    @classmethod
    def _not_reserved(cls, v: str) -> str:
        if v.lower().startswith("pg_"):
            raise ValueError('role names starting with "pg_" are reserved by PostgreSQL')
        if v.lower() in {"public", "none", "current_user", "session_user", "current_role"}:
            raise ValueError(f'"{v}" is a reserved role name')
        return v


class RoleUpdate(RoleAttributes):
    """Only fields present in the request body are changed. ``valid_until: null`` clears the expiry."""

    rename_to: str | None = None
    password: str | None = Field(None, max_length=1024)
    remove_password: bool = False

    @field_validator("rename_to")
    @classmethod
    def _v_rename(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = _clean_name(v)
        if v.lower().startswith("pg_"):
            raise ValueError('role names starting with "pg_" are reserved by PostgreSQL')
        return v


class MembershipSpec(BaseModel):
    """One membership. Options left as None keep their current value (or the server default for new ones).

    inherit_option and set_option exist only on PostgreSQL 16+; they are ignored on older servers.
    """

    role: str
    admin_option: bool | None = None
    inherit_option: bool | None = None
    set_option: bool | None = None


class MembershipUpdate(BaseModel):
    """The complete desired membership list. Send roles (names only) or memberships (with options)."""

    roles: list[str] | None = None
    memberships: list[MembershipSpec] | None = None

    def specs(self) -> list[MembershipSpec]:
        if self.memberships is not None:
            return self.memberships
        return [MembershipSpec(role=r) for r in (self.roles or [])]


class Membership(BaseModel):
    role: str
    admin_option: bool = False
    inherit_option: bool | None = None  # None on servers older than PostgreSQL 16
    set_option: bool | None = None


class RoleSummary(BaseModel):
    name: str
    oid: int
    kind: Literal["user", "role"]
    is_system: bool
    superuser: bool
    inherit: bool
    createrole: bool
    createdb: bool
    login: bool
    replication: bool
    bypassrls: bool
    connection_limit: int
    valid_until: datetime | None
    comment: str | None
    member_of: list[str]
    member_count: int


class RoleDetail(RoleSummary):
    memberships: list[Membership]
    members: list[Membership]
    is_current_user: bool


class RoleList(BaseModel):
    items: list[RoleSummary]
    total: int


class Dependency(BaseModel):
    database: str
    owned_objects: int
    privileges: int


class DependencyReport(BaseModel):
    dependencies: list[Dependency]
    owns_objects: bool


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
ObjectType = Literal[
    "database",
    "schema",
    "table",
    "sequence",
    "function",
    "all_tables",
    "all_sequences",
    "all_functions",
    "default_tables",
    "default_sequences",
    "default_functions",
    "default_schemas",
    "column",
]


class PermissionChange(BaseModel):
    action: Literal["grant", "revoke"]
    object_type: ObjectType
    privileges: list[str] = Field(min_length=1)
    schema_name: str | None = Field(None, alias="schema")
    name: str | None = None
    oid: int | None = None  # functions are addressed by oid
    with_grant_option: bool = False
    for_role: str | None = None  # default privileges: objects created by this role
    columns: list[str] | None = None  # object_type "column": the table's columns to (un)grant on
    revoke_grant_option: bool = False  # revoke only the right to pass the privilege on (REVOKE GRANT OPTION FOR)
    cascade: bool = False  # revoke: also remove privileges the grantee passed on to others

    model_config = {"populate_by_name": True}


class ApplyRequest(BaseModel):
    database: str
    changes: list[PermissionChange] = Field(min_length=1, max_length=1000)
    dry_run: bool = False
    grantor: str | None = None  # run the statements as this role (SET LOCAL ROLE) so it is recorded as grantor
    expires_at: datetime | None = None  # make the grants temporary: revoked automatically at this time


class ApplyResult(BaseModel):
    statements: list[str]
    applied: bool
    temporary: dict | None = None  # {expires_at, expiring: [...], skipped: [...], schedule_id}
