import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, enc } from "./client";
import type {
  ApplyResult,
  AuthState,
  DatabaseInfo,
  DefaultPrivilege,
  DependencyReport,
  Meta,
  ObjType,
  PermPage,
  PermissionChange,
  RoleDetail,
  RoleInput,
  RoleList,
  Stats,
} from "./types";

export const useAuth = () =>
  useQuery({ queryKey: ["auth"], queryFn: () => api.get<AuthState>("/auth/me"), staleTime: Infinity, retry: false });

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

export interface RoleListParams {
  kind?: "all" | "user" | "role";
  q?: string;
  include_system?: boolean;
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
    mutationFn: (roles: string[]) => api.put<RoleDetail>(`/roles/${enc(name)}/${direction}`, { roles }),
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

export function useApplyPermissions(role: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: { database: string; changes: PermissionChange[]; dry_run?: boolean }) =>
      api.post<ApplyResult>(`/permissions/${enc(role)}/apply`, v),
    onSuccess: (r) => {
      if (r.applied) qc.invalidateQueries({ queryKey: ["perm"] });
    },
  });
}
