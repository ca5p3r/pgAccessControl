import { useEffect, useId, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { Check, ChevronsUpDown, Lock, Plus, Server, Settings2 } from "lucide-react";
import { useAuth } from "../api/hooks";
import type { ServerInfo } from "../api/types";
import { EnvBadge, StatusDot, useServerContext } from "./server";
import { cx } from "./ui";

/** The sidebar control that shows which PostgreSQL server you are working on, and switches it. */
export function ServerSwitcher({ onNavigate }: { onNavigate?: () => void }) {
  const { servers, current, setCurrent, status, statusLoading, response } = useServerContext();
  const auth = useAuth();
  const isAdmin = (auth.data?.role ?? "admin") === "admin";
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const [active, setActive] = useState(0);
  const box = useRef<HTMLDivElement>(null);
  const search = useRef<HTMLInputElement>(null);
  const listId = useId();

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return servers.filter((s) => !needle || `${s.name} ${s.environment} ${s.host ?? ""} ${s.description ?? ""}`.toLowerCase().includes(needle));
  }, [servers, q]);

  // Alt+S opens the switcher from anywhere.
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.altKey && e.key.toLowerCase() === "s") { e.preventDefault(); setOpen(true); } };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  useEffect(() => {
    if (!open) return;
    setQ("");
    setActive(Math.max(0, servers.findIndex((s) => s.id === current.id)));
    setTimeout(() => search.current?.focus(), 0);
    const h = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps

  const pick = (s: ServerInfo) => {
    if (s.disabled) return;
    setOpen(false);
    setCurrent(s.id);
    onNavigate?.();
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") { setOpen(false); (box.current?.querySelector(".switcher-btn") as HTMLElement | null)?.focus(); }
    else if (e.key === "ArrowDown") { e.preventDefault(); setActive((i) => Math.min(visible.length - 1, i + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((i) => Math.max(0, i - 1)); }
    else if (e.key === "Enter" && visible[active]) { e.preventDefault(); pick(visible[active]); }
  };

  const alone = servers.length <= 1 && !isAdmin; // nothing to switch to
  const cur = status[current.id];
  const hostLine = current.host ? `${current.host}${current.port && current.port !== 5432 ? `:${current.port}` : ""}` : current.description;

  return (
    <div className="switcher" ref={box} onKeyDown={open ? onKey : undefined}>
      <button
        className={cx("switcher-btn", `env-border-${current.environment}`, alone && "static")}
        onClick={() => !alone && setOpen((o) => !o)}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={`Server: ${current.name}. ${alone ? "" : "Press to switch."}`}
        title={alone ? undefined : "Switch server (Alt+S)"}
      >
        <span className="switcher-icon"><Server size={16} /><StatusDot status={cur} loading={statusLoading} /></span>
        <span className="switcher-text">
          <span className="switcher-name">{current.name}</span>
          <span className="switcher-sub">
            <EnvBadge env={current.environment} compact />
            {current.read_only && <span className="ro-tag"><Lock size={10} /> read-only</span>}
            {hostLine && <span className="switcher-host">{hostLine}</span>}
          </span>
        </span>
        {!alone && <ChevronsUpDown size={15} className="switcher-chev" />}
      </button>

      {open && (
        <div className="switcher-menu" role="dialog" aria-label="Switch server">
          {servers.length > 5 && (
            <input ref={search} className="switcher-search" value={q} onChange={(e) => { setQ(e.target.value); setActive(0); }} placeholder="Find a server…" aria-controls={listId} aria-label="Find a server" />
          )}
          {servers.length <= 5 && <input ref={search} className="sr-only" aria-hidden tabIndex={-1} readOnly />}
          <ul id={listId} role="listbox" className="switcher-list" aria-label="Servers">
            {visible.map((s, i) => (
              <li key={s.id} role="option" aria-selected={s.id === current.id} aria-disabled={s.disabled} id={`${listId}-${i}`}
                className={cx("switcher-opt", i === active && "active", s.id === current.id && "current", s.disabled && "disabled")}
                onMouseEnter={() => setActive(i)} onClick={() => pick(s)}>
                <StatusDot status={status[s.id]} loading={statusLoading} />
                <span className="switcher-opt-text">
                  <span className="switcher-opt-name">{s.name}</span>
                  <span className="switcher-opt-sub">
                    {s.host ? `${s.host}${s.port !== 5432 ? `:${s.port}` : ""}` : s.is_default ? "configured by the server" : s.description ?? ""}
                    {status[s.id] && !status[s.id].ok ? " · unreachable" : status[s.id]?.server_version ? ` · PostgreSQL ${status[s.id].server_version}` : ""}
                  </span>
                </span>
                <span className="switcher-opt-flags">
                  {s.read_only && <Lock size={12} aria-label="read-only" />}
                  <EnvBadge env={s.environment} compact />
                  {s.disabled && <span className="ro-tag">disabled</span>}
                </span>
                {s.id === current.id && <Check size={14} className="switcher-check" />}
              </li>
            ))}
            {visible.length === 0 && <li className="switcher-empty">No server matches “{q}”.</li>}
          </ul>
          {isAdmin && (
            <div className="switcher-foot">
              <Link to="/servers" onClick={() => { setOpen(false); onNavigate?.(); }}><Settings2 size={14} /> Manage servers</Link>
              {response.management_enabled && <Link to="/servers?add=1" onClick={() => { setOpen(false); onNavigate?.(); }}><Plus size={14} /> Add server</Link>}
            </div>
          )}
          <div className="switcher-hint">↑↓ to move · Enter to switch · Esc to close</div>
        </div>
      )}
    </div>
  );
}
