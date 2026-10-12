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

export interface AuthState {
  auth_enabled: boolean;
  authenticated: boolean;
  username: string | null;
}
