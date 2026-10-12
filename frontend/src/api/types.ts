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
  | "default_schemas";

export interface PermissionChange {
  action: "grant" | "revoke";
  object_type: ChangeObjectType;
  privileges: string[];
  schema?: string | null;
  name?: string | null;
  oid?: number | null;
  with_grant_option?: boolean;
  for_role?: string | null;
}

export interface ApplyResult {
  statements: string[];
  applied: boolean;
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
  auth_enabled: boolean;
  authenticated: boolean;
  username: string | null;
}
