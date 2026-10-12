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


class MembershipUpdate(BaseModel):
    roles: list[str]


class Membership(BaseModel):
    role: str
    admin_option: bool = False


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

    model_config = {"populate_by_name": True}


class ApplyRequest(BaseModel):
    database: str
    changes: list[PermissionChange] = Field(min_length=1, max_length=1000)
    dry_run: bool = False


class ApplyResult(BaseModel):
    statements: list[str]
    applied: bool
