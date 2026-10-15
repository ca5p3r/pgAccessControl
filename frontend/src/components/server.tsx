import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { QueryClientProvider, useQueryClient, type QueryClient } from "@tanstack/react-query";
import { useLocation, useNavigate } from "react-router-dom";
import { setCurrentServer } from "../api/client";
import { useServerStatus, useServers } from "../api/hooks";
import { makeQueryClient } from "../api/queryClient";
import type { Environment, ServerInfo, ServerStatus, ServersResponse } from "../api/types";
import { Badge, ErrorNote, Spinner } from "./ui";

const KEY = "pgac-server";
const read = () => { try { return localStorage.getItem(KEY); } catch { return null; } };
const write = (id: string) => { try { localStorage.setItem(KEY, id); } catch { /* storage unavailable */ } };

interface Ctx {
  servers: ServerInfo[];
  response: ServersResponse;
  current: ServerInfo;
  setCurrent: (id: string) => void;
  status: Record<string, ServerStatus>;
  statusLoading: boolean;
  /** Reload the server list and health after a change on the Servers page. */
  refresh: () => void;
  /** The cache above the per-server ones: it holds who is signed in. */
  outerClient: QueryClient;
}

const ServerCtx = createContext<Ctx | null>(null);

export function useServerContext(): Ctx {
  const c = useContext(ServerCtx);
  if (!c) throw new Error("useServerContext must be used inside <ServerProvider>");
  return c;
}

/** After switching servers, pages about a specific object of the old server make no sense: go to their list. */
export function pathAfterSwitch(pathname: string): string {
  const m = pathname.match(/^\/(users|roles|permissions)\/.+/);
  if (m) return `/${m[1]}`;
  return pathname;
}

export const ENV_META: Record<Environment, { label: string; short: string }> = {
  production: { label: "Production", short: "PROD" },
  staging: { label: "Staging", short: "STAGING" },
  development: { label: "Development", short: "DEV" },
  other: { label: "Other", short: "" },
};

export function EnvBadge({ env, compact }: { env: Environment; compact?: boolean }) {
  if (env === "other" && compact) return null;
  return <span className={`env-chip env-${env}`}>{compact ? ENV_META[env].short : ENV_META[env].label}</span>;
}

/**
 * Knows which PostgreSQL server the console is working with. Lives above the data cache: it fetches the
 * server list (and health) itself, and everything below is remounted with a fresh cache on every switch.
 */
export function ServerProvider({ children }: { children: ReactNode }) {
  const outer = useQueryClient();
  const list = useServers();
  const health = useServerStatus(!!list.data);
  const navigate = useNavigate();
  const location = useLocation();
  const [stored, setStored] = useState<string | null>(read);

  const servers = list.data?.items ?? [];
  const usable = servers.filter((s) => !s.disabled);
  const current = usable.find((s) => s.id === stored) ?? usable.find((s) => s.is_default) ?? usable[0];

  // Set synchronously, during render, so the very first requests of the new screens already carry the right
  // server (an effect would run after the children have started fetching).
  setCurrentServer(current ? { id: current.id, readOnly: current.read_only } : null);

  useEffect(() => { if (current) document.title = `${current.name} · pgAccessControl`; return () => { document.title = "pgAccessControl"; }; }, [current]);

  const setCurrent = useCallback((id: string) => {
    if (id === current?.id) return;
    write(id);
    setStored(id);
    navigate(pathAfterSwitch(location.pathname), { replace: true });
  }, [current?.id, navigate, location.pathname]);

  const refresh = useCallback(() => {
    outer.invalidateQueries({ queryKey: ["servers"] });
    outer.invalidateQueries({ queryKey: ["server-status"] });
  }, [outer]);

  const value = useMemo<Ctx | null>(
    () => current && list.data ? { servers, response: list.data, current, setCurrent, status: health.data?.items ?? {}, statusLoading: health.isLoading, refresh, outerClient: outer } : null,
    [servers, list.data, current, setCurrent, health.data, health.isLoading, refresh, outer],
  );

  if (list.isLoading) return <Spinner label="Loading servers…" />;
  if (list.error) return <div className="page"><ErrorNote error={list.error} retry={() => list.refetch()} /></div>;
  if (!value) return <div className="page"><ErrorNote error={new Error("No server is available to you. Ask an administrator.")} /></div>;
  return <ServerCtx.Provider value={value}>{children}</ServerCtx.Provider>;
}

/**
 * A separate query cache per server. Switching discards the old one completely, so a slow answer from the
 * previous server can never end up on a screen that now belongs to another.
 */
export function ServerScope({ children }: { children: ReactNode }) {
  const { current } = useServerContext();
  const key = `${current.id}:${current.read_only ? "ro" : "rw"}`;
  const client = useMemo(() => makeQueryClient(), [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return <QueryClientProvider client={client} key={key}>{children}</QueryClientProvider>;
}

export function StatusDot({ status, loading }: { status?: ServerStatus; loading?: boolean }) {
  const state = status ? (status.ok ? "up" : "down") : loading ? "wait" : "unknown";
  const title = status ? (status.ok ? `Reachable${status.latency_ms !== undefined ? ` · ${status.latency_ms} ms` : ""}` : "Not reachable") : "Checking…";
  return <span className={`status-dot ${state}`} title={title} role="img" aria-label={title} />;
}

export function ServerFlags({ s }: { s: ServerInfo }) {
  return (
    <span className="badge-row">
      <EnvBadge env={s.environment} compact />
      {s.read_only && <Badge tone="info">read-only</Badge>}
      {s.disabled && <Badge tone="danger">disabled</Badge>}
    </span>
  );
}
