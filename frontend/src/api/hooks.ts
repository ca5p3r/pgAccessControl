import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, enc, qs } from "./client";
import type {
  AccessReport,
  AppUser,
  ApplyResult,
  AuditFilters,
  AuditList,
  AuthState,
  ObjectItem,
  DatabaseInfo,
  DefaultPrivilege,
  DependencyReport,
  ColumnPrivileges,
  MembershipSpec,
  Meta,
  ObjType,
  PermPage,
  PermissionChange,
  RoleDetail,
  RoleInput,
  RoleList,
  DriftReport,
  Snapshot,
  Stats,
  TemporaryItem,
} from "./types";

export const useAuth = () =>
  useQuery({ queryKey: ["auth"], queryFn: () => api.get<AuthState>("/auth/me"), staleTime: Infinity, retry: false });

export type AppRole = "viewer" | "operator" | "admin";
const RANK: Record<AppRole, number> = { viewer: 1, operator: 2, admin: 3 };

/** What the signed-in app user may do. The server enforces it; this only hides controls that would be refused. */
export function useCan() {
  const auth = useAuth();
  const role: AppRole = auth.data?.role ?? "admin";
  return { role, can: (min: AppRole) => RANK[role] >= RANK[min] };
}

export const useMeta = () => useQuery({ queryKey: ["meta"], queryFn: () => api.get<Meta>("/meta"), staleTime: 5 * 60_000 });

export const useStats = () => useQuery({ queryKey: ["stats"], queryFn: () => api.get<Stats>("/stats"), staleTime: 15_000 });

export const useDatabases = () =>
  useQuery({ queryKey: ["databases"], queryFn: () => api.get<DatabaseInfo[]>("/databases"), staleTime: 60_000 });

export const useSchemas = (database: string | undefined) =>
  useQuery({
    queryKey: ["schemas", database],
    queryFn: () => api.get<string[]>("/schemas", { database }),
    enabled: !!database,
    staleTime: 30_000,
  });

export type RoleSort = "name" | "member_of" | "members" | "expires" | "conn_limit" | "privilege";
export type RoleAttr = "all" | "superuser" | "createrole" | "createdb" | "replication" | "bypassrls" | "expired" | "no_memberships";

export interface RoleListParams {
  kind?: "all" | "user" | "role";
  q?: string;
  include_system?: boolean;
  sort?: RoleSort;
  order?: "asc" | "desc";
  attr?: RoleAttr;
  limit?: number;
  offset?: number;
}

export const useRoles = (params: RoleListParams, enabled = true) =>
  useQuery({
    queryKey: ["roles", params],
    queryFn: ({ signal }) => api.get<RoleList>("/roles", { ...params }, signal),
    placeholderData: keepPreviousData,
    enabled,
    staleTime: 10_000,
  });

export const useRole = (name: string | undefined) =>
  useQuery({
    queryKey: ["role", name],
    queryFn: () => api.get<RoleDetail>(`/roles/${enc(name!)}`),
    enabled: !!name,
  });

export const useDependencies = (name: string | undefined, enabled: boolean) =>
  useQuery({
    queryKey: ["role-deps", name],
    queryFn: () => api.get<DependencyReport>(`/roles/${enc(name!)}/dependencies`),
    enabled: enabled && !!name,
    gcTime: 0,
  });

function useInvalidateRoles() {
  const qc = useQueryClient();
  return (name?: string) => {
    qc.invalidateQueries({ queryKey: ["roles"] });
    qc.invalidateQueries({ queryKey: ["stats"] });
    if (name) qc.invalidateQueries({ queryKey: ["role", name] });
  };
}

export function useCreateRole() {
  const invalidate = useInvalidateRoles();
  return useMutation({
    mutationFn: (body: RoleInput) => api.post<RoleDetail>("/roles", body),
    onSuccess: (r) => invalidate(r.name),
  });
}

export function useUpdateRole(name: string) {
  const invalidate = useInvalidateRoles();
  return useMutation({
    mutationFn: (body: RoleInput) => api.patch<RoleDetail>(`/roles/${enc(name)}`, body),
    onSuccess: (r) => {
      invalidate(name);
      invalidate(r.name);
    },
  });
}

export function useDeleteRole() {
  const invalidate = useInvalidateRoles();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, reassign_to }: { name: string; reassign_to?: string }) =>
      api.del(`/roles/${enc(name)}`, { reassign_to }),
    onSuccess: (_, { name }) => {
      qc.removeQueries({ queryKey: ["role", name] });
      invalidate();
    },
  });
}

export function useSetMembership(name: string, direction: "member-of" | "members") {
  const invalidate = useInvalidateRoles();
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (memberships: MembershipSpec[]) => api.put<RoleDetail>(`/roles/${enc(name)}/${direction}`, { memberships }),
    onSuccess: (r) => {
      qc.setQueryData(["role", name], r);
      invalidate();
      qc.invalidateQueries({ queryKey: ["perm"] }); // inherited privileges change with membership
    },
  });
}

export interface PermParams {
  database: string;
  type: ObjType;
  schema?: string;
  q?: string;
  granted_only?: boolean;
  limit: number;
  offset: number;
}

export const usePermObjects = (role: string, params: PermParams, enabled: boolean) =>
  useQuery({
    queryKey: ["perm", role, "objects", params],
    queryFn: ({ signal }) => api.get<PermPage>(`/permissions/${enc(role)}/objects`, { ...params }, signal),
    placeholderData: keepPreviousData,
    enabled,
  });

export const useDefaultPrivileges = (role: string, database: string | undefined) =>
  useQuery({
    queryKey: ["perm", role, "defaults", database],
    queryFn: () => api.get<DefaultPrivilege[]>(`/permissions/${enc(role)}/default-privileges`, { database }),
    enabled: !!database,
  });

export const useAudit = (filters: AuditFilters, page: number, size: number, live = false) =>
  useQuery({
    queryKey: ["audit", filters, page, size],
    queryFn: ({ signal }) => api.get<AuditList>("/audit", { ...filters, limit: size, offset: page * size }, signal),
    placeholderData: keepPreviousData,
    refetchInterval: live ? 5_000 : false,
  });

export const useAuditFacets = () =>
  useQuery({ queryKey: ["audit-facets"], queryFn: () => api.get<{ actors: string[]; databases: string[] }>("/audit/facets"), staleTime: 30_000 });

export const useObjects = (params: { database?: string; type: ObjType; schema?: string; q?: string }, enabled = true) =>
  useQuery({
    queryKey: ["objects", params],
    queryFn: ({ signal }) => api.get<{ items: ObjectItem[]; total: number }>("/objects", { ...params, limit: 30 }, signal),
    placeholderData: keepPreviousData,
    enabled: enabled && !!params.database,
  });

export const useAccessReport = (database: string | undefined, type: ObjType, oid: number | undefined) =>
  useQuery({
    queryKey: ["access-report", database, type, oid],
    queryFn: () => api.get<AccessReport>("/access-report", { database, type, oid }),
    enabled: !!database && oid !== undefined,
  });

/** URL for a file download served by the API (same-origin, so the session cookie is sent). */
export const downloadUrl = (path: string, params: Record<string, string | number | boolean | null | undefined>) => `/api${path}${qs(params)}`;

export const useColumnPrivileges = (role: string, database: string | undefined, schema: string, table: string) =>
  useQuery({
    queryKey: ["perm", role, "columns", database, schema, table],
    queryFn: () => api.get<ColumnPrivileges>(`/permissions/${enc(role)}/columns`, { database, schema, table }),
    enabled: !!database,
    gcTime: 0,
  });

export function useApplyPermissions(role: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { database: string; changes: PermissionChange[]; dry_run?: boolean; grantor?: string; expires_at?: string }) =>
      api.post<ApplyResult>(`/permissions/${enc(role)}/apply`, v),
    onSuccess: (r) => {
      if (r.applied) {
        qc.invalidateQueries({ queryKey: ["perm"] });
        qc.invalidateQueries({ queryKey: ["temporary"] });
      }
    },
  });
}

/* ------------------------------------------------------------- app accounts */
export const useAppUsers = (enabled = true) =>
  useQuery({ queryKey: ["app-users"], queryFn: () => api.get<{ items: AppUser[]; me: string }>("/app-users"), enabled });

export function useAppUserMutations() {
  const qc = useQueryClient();
  const done = () => qc.invalidateQueries({ queryKey: ["app-users"] });
  return {
    create: useMutation({ mutationFn: (b: { username: string; password: string; role: string }) => api.post<AppUser>("/app-users", b), onSuccess: done }),
    update: useMutation({
      mutationFn: ({ username, ...b }: { username: string; role?: string; disabled?: boolean; password?: string }) => api.patch<AppUser>(`/app-users/${enc(username)}`, b),
      onSuccess: done,
    }),
    remove: useMutation({ mutationFn: (username: string) => api.del(`/app-users/${enc(username)}`), onSuccess: done }),
  };
}

export const useChangePassword = () =>
  useMutation({ mutationFn: (b: { current_password: string; new_password: string }) => api.post("/auth/password", b) });

/* --------------------------------------------------------- temporary access */
export const useTemporary = (params: { status?: "pending" | "history" | "all"; involving?: string } = {}, live = false) =>
  useQuery({
    queryKey: ["temporary", params],
    queryFn: () => api.get<{ items: TemporaryItem[] }>("/temporary", params),
    refetchInterval: live ? 15_000 : false,
  });

export function useTemporaryMutations() {
  const qc = useQueryClient();
  const done = () => {
    qc.invalidateQueries({ queryKey: ["temporary"] });
    qc.invalidateQueries({ queryKey: ["perm"] });
    qc.invalidateQueries({ queryKey: ["role"] });
  };
  return {
    cancel: useMutation({ mutationFn: (id: number) => api.post<TemporaryItem>(`/temporary/${id}/cancel`), onSuccess: done }),
    revokeNow: useMutation({ mutationFn: (id: number) => api.post<TemporaryItem>(`/temporary/${id}/revoke-now`), onSuccess: done }),
    extend: useMutation({ mutationFn: ({ id, expires_at }: { id: number; expires_at: string }) => api.post<TemporaryItem>(`/temporary/${id}/extend`, { expires_at }), onSuccess: done }),
    membership: useMutation({
      mutationFn: (b: { role: string; member: string; expires_at: string | null }) => api.put<{ schedule: TemporaryItem | null }>("/temporary/membership", b),
      onSuccess: done,
    }),
  };
}

/* ------------------------------------------------------- snapshots and drift */
export const useSnapshots = () =>
  useQuery({ queryKey: ["snapshots"], queryFn: () => api.get<{ items: Snapshot[]; check_interval_minutes: number }>("/snapshots") });

export function useSnapshotMutations() {
  const qc = useQueryClient();
  const done = () => { qc.invalidateQueries({ queryKey: ["snapshots"] }); qc.invalidateQueries({ queryKey: ["drift"] }); };
  return {
    create: useMutation({ mutationFn: (b: { name: string; note?: string; database: string; baseline: boolean }) => api.post<Snapshot>("/snapshots", b), onSuccess: done }),
    remove: useMutation({ mutationFn: (id: number) => api.del(`/snapshots/${id}`), onSuccess: done }),
    baseline: useMutation({ mutationFn: ({ id, baseline }: { id: number; baseline: boolean }) => api.post<Snapshot>(`/snapshots/${id}/baseline`, { baseline }), onSuccess: done }),
  };
}

export const useDrift = (id: number | undefined, against?: number) =>
  useQuery({
    queryKey: ["drift", id, against],
    queryFn: () => api.get<DriftReport>(`/snapshots/${id}/drift`, { against }),
    enabled: id !== undefined,
    gcTime: 0,
  });
