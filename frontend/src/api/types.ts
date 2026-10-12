export type ObjType = "database" | "schema" | "table" | "sequence" | "function";

export interface RoleSummary {
  name: string;
  oid: number;
  kind: "user" | "role";
  is_system: boolean;
  superuser: boolean;
  inherit: boolean;
  createrole: boolean;
  createdb: boolean;
  login: boolean;
  replication: boolean;
  bypassrls: boolean;
  connection_limit: number;
  valid_until: string | null;
  comment: string | null;
  member_of: string[];
  member_count: number;
}

export interface Membership {
  role: string;
  admin_option: boolean;
  inherit_option: boolean | null; // null on servers older than PostgreSQL 16
  set_option: boolean | null;
}

/** One membership to save; options left null keep their current value or the server default. */
export interface MembershipSpec {
  role: string;
  admin_option?: boolean | null;
  inherit_option?: boolean | null;
  set_option?: boolean | null;
}

export interface RoleDetail extends RoleSummary {
  memberships: Membership[];
  members: Membership[];
  is_current_user: boolean;
}

export interface RoleList {
  items: RoleSummary[];
  total: number;
}

export interface RoleInput {
  name?: string;
  login?: boolean;
  password?: string | null;
  superuser?: boolean;
  createdb?: boolean;
  createrole?: boolean;
  inherit?: boolean;
  replication?: boolean;
  bypassrls?: boolean;
  connection_limit?: number;
  valid_until?: string | null;
  comment?: string | null;
  member_of?: string[];
  members?: string[];
  rename_to?: string;
  remove_password?: boolean;
}

export interface Dependency {
  database: string;
  owned_objects: number;
  privileges: number;
}

export interface DependencyReport {
  dependencies: Dependency[];
  owns_objects: boolean;
}

export interface Meta {
  server_version: string;
  connected_as: string;
  is_superuser: boolean;
  can_create_roles: boolean;
  host: string;
  port: number;
  database: string;
  audit_enabled: boolean;
  membership_options: boolean;
  privileges: Record<ObjType, string[]>;
}

export interface Stats {
  users: number;
  roles: number;
  superusers: number;
  expired: number;
  databases: number;
}

export interface DatabaseInfo {
  name: string;
  owner: string;
  connectable: boolean;
}

export interface PermObject {
  oid: number;
  schema: string;
  name: string;
  kind: string;
  owner: string;
  args: string;
  direct: string[];
  grantable: string[];
  inherited: Record<string, string[]>;
}

export interface PermPage {
  items: PermObject[];
  total: number;
  role_superuser: boolean;
  privileges: string[];
}

export interface DefaultPrivilege {
  for_role: string;
  schema: string | null;
  object_type: "table" | "sequence" | "function" | "schema" | "type";
  privileges: string[];
}

export type ChangeObjectType =
  | ObjType
  | "all_tables"
  | "all_sequences"
  | "all_functions"
  | "default_tables"
  | "default_sequences"
  | "default_functions"
  | "default_schemas"
  | "column";

export interface ColumnPrivileges {
  table: { schema: string; name: string; oid: number };
  privileges: string[];
  table_level: Record<string, string[]>;
  columns: { name: string; type: string; direct: string[]; grantable: string[]; inherited: Record<string, string[]> }[];
  role_superuser: boolean;
}

export interface PermissionChange {
  action: "grant" | "revoke";
  object_type: ChangeObjectType;
  privileges: string[];
  schema?: string | null;
  name?: string | null;
  oid?: number | null;
  with_grant_option?: boolean;
  for_role?: string | null;
  columns?: string[] | null;
  revoke_grant_option?: boolean;
  cascade?: boolean;
}

export interface ApplyResult {
  statements: string[];
  applied: boolean;
  temporary?: TemporaryPlan | null;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor: string;
  ip: string | null;
  action: string;
  target_type: string | null;
  target: string | null;
  database: string | null;
  status: "success" | "failed";
  summary: string;
  statements: string[];
  details: Record<string, unknown>;
  error: string | null;
}

export interface AuditList {
  items: AuditEntry[];
  total: number;
  enabled: boolean;
  retention_days: number;
}

export interface AuditFilters {
  actor?: string;
  action?: string;
  target?: string;
  database?: string;
  status?: string;
  q?: string;
  date_from?: string;
  date_to?: string;
}

export interface ObjectItem {
  oid: number;
  schema: string;
  name: string;
  kind: string;
  owner: string;
  args: string;
}

export interface AccessPrincipal {
  name: string;
  kind: "user" | "role";
  superuser: boolean;
  is_owner: boolean;
  privileges: Record<string, string[]>;
}

export interface AccessReport {
  object: ObjectItem & { type: ObjType };
  privilege_names: string[];
  grants: { grantee: string; privilege: string; grantable: boolean; grantor: string }[];
  principals: AccessPrincipal[];
  truncated: boolean;
}

export interface AuthState {
  role?: "viewer" | "operator" | "admin";
  oidc_enabled?: boolean;
  oidc_label?: string;
  local_login?: boolean;
  source?: string;
  auth_enabled: boolean;
  authenticated: boolean;
  username: string | null;
}

export interface AppUser {
  id: number;
  username: string;
  role: "viewer" | "operator" | "admin";
  disabled: boolean;
  created_at: string;
  created_by: string | null;
  last_login: string | null;
}

export interface TemporaryItem {
  id: number;
  kind: "grant" | "membership";
  grantee: string;
  database: string | null;
  description: string;
  created_at: string;
  created_by: string;
  expires_at: string;
  status: "pending" | "running" | "expired" | "cancelled" | "failed";
  finished_at: string | null;
  error: string | null;
  spec: { role?: string; changes?: unknown[] };
}

export interface TemporaryPlan {
  expires_at: string;
  expiring: string[];
  skipped: string[];
  schedule_id?: number | null;
}

export interface Snapshot {
  id: number;
  name: string;
  note: string | null;
  database: string;
  created_at: string;
  created_by: string;
  baseline: boolean;
  counts: { roles: number; memberships: number; privileges: number; defaults: number };
  last_check: { at: string; total: number; digest: string } | null;
}

export interface DriftSection<T> {
  added: T[];
  removed: T[];
  changed: { item: T; changes: Record<string, [unknown, unknown]> }[];
}

export interface DriftReport {
  snapshot: Snapshot;
  compared_with: { kind: "live" | "snapshot"; name: string; at: string; id?: number };
  total: number;
  truncated: boolean;
  summary: Record<"roles" | "memberships" | "privileges" | "defaults", { added: number; removed: number; changed: number }>;
  roles: DriftSection<{ name: string; login: boolean; superuser: boolean }>;
  memberships: DriftSection<{ role: string; member: string; admin_option: boolean }>;
  privileges: DriftSection<{ object_type: string; schema: string; name: string; args: string; col: string; grantee: string; privilege: string; grantable: boolean }>;
  defaults: DriftSection<{ for_role: string; schema: string | null; object_type: string; grantee: string; privilege: string; grantable: boolean }>;
}

export interface HeldObject {
  kind: string;
  description: string;
}

export interface HoldingsSummary {
  role: string;
  is_superuser: boolean;
  owns_objects: boolean;
  databases: Dependency[];
  cluster: {
    owned: HeldObject[];
    privileges: { kind: string; name: string; privilege: string; grantable: boolean; grantor: string }[];
    granted_to_others: { kind: string; name: string; privilege: string; grantable: boolean; grantee: string }[];
  };
}

export interface HoldingsDetail {
  database: string;
  owned: HeldObject[];
  policies: HeldObject[];
  privileges: { object_type: string; schema: string; name: string; args: string; col: string; owner: string; grantee: string; privilege: string; grantable: boolean; grantor: string }[];
  default_privileges: { for_role: string; schema: string | null; object_type: string; grantee: string; privilege: string; grantable: boolean }[];
  granted_to_others: { object_type: string; schema: string; name: string; col: string; grantee: string; privilege: string; grantable: boolean }[];
}
