import { useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { ClipboardList, History, Hourglass, KeyRound, LayoutDashboard, Lock, LockKeyhole, LogOut, Menu, Moon, Server, ShieldCheck, Sun, UserCog, UserRound, Users } from "lucide-react";
import { api } from "../api/client";
import type { AuthState } from "../api/types";
import { useAuth, useIsAdmin, useMeta } from "../api/hooks";
import { ChangePasswordDialog } from "./ChangePassword";
import { ServerSwitcher } from "./ServerSwitcher";
import { EnvBadge, useServerContext } from "./server";
import { Avatar, cx } from "./ui";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/users", label: "Users", icon: UserRound },
  { to: "/roles", label: "Roles", icon: Users },
  { to: "/permissions", label: "Permissions", icon: KeyRound },
  { to: "/reports", label: "Reports", icon: ClipboardList },
  { to: "/temporary", label: "Temporary access", icon: Hourglass },
  { to: "/activity", label: "Activity", icon: History },
  { to: "/accounts", label: "Accounts", icon: UserCog, admin: true },
  { to: "/servers", label: "Servers", icon: Server, admin: true },
];

function useTheme() {
  const [theme, setTheme] = useState<"light" | "dark">(() => (document.documentElement.dataset.theme as "light" | "dark") || "light");
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("pgac-theme", theme); } catch { /* private mode */ }
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))] as const;
}

export function Layout() {
  const [theme, toggleTheme] = useTheme();
  const [open, setOpen] = useState(false);
  const auth = useAuth();
  const meta = useMeta();
  const isAdmin = useIsAdmin();
  const { current, outerClient } = useServerContext();
  const [changingPw, setChangingPw] = useState(false);
  const navigate = useNavigate();

  const logout = async () => {
    try {
      await api.post("/auth/logout");
    } catch {
      /* already signed out, or the server is unreachable: leave the app either way */
    }
    // Drop everything cached for this user, but keep the auth entry and mark it signed out so the app
    // switches to the login screen at once. (qc.clear() would also delete the auth entry, leaving the
    // mounted UI with stale "signed in" data and nothing to refetch.)
    // The login gate reads the cache above the per-server ones, so that is the one to update.
    outerClient.removeQueries({ predicate: (q) => q.queryKey[0] !== "auth" });
    outerClient.setQueryData<AuthState>(["auth"], (prev) => prev && { ...prev, authenticated: false, username: null, role: undefined, source: undefined });
    navigate("/", { replace: true });
  };

  return (
    <div className="shell">
      <aside className={cx("sidebar", open && "open")}>
        <div className="brand">
          <span className="brand-mark"><ShieldCheck size={20} /></span>
          <div>
            <div className="brand-name">pgAccessControl</div>
            <div className="brand-sub">PostgreSQL permissions</div>
          </div>
        </div>
        <ServerSwitcher onNavigate={() => setOpen(false)} />
        <nav className="nav" onClick={() => setOpen(false)}>
          {NAV.filter((n) => !n.admin || isAdmin).map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => cx("nav-item", isActive && "active")}>
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          {meta.data && (
            <div className="server-card" title={meta.data.host ? `${meta.data.host}:${meta.data.port}` : current.name}>
              <span className="dot" />
              <div>
                <div className="server-line">PostgreSQL {meta.data.server_version.split(" ")[0]}</div>
                <div className="server-sub">as {meta.data.connected_as}{meta.data.is_superuser ? " · superuser" : ""}</div>
              </div>
            </div>
          )}
          {auth.data?.auth_enabled && auth.data.username && (
            <div className="user-card">
              <Avatar name={auth.data.username} size={30} />
              <div className="grow"><div className="server-line">{auth.data.username}</div><div className="server-sub">{auth.data.role}{auth.data.source === "oidc" ? " · SSO" : ""}</div></div>
              {auth.data.source === "local" && <button className="foot-btn icon" onClick={() => setChangingPw(true)} aria-label="Change password" title="Change password"><LockKeyhole size={15} /></button>}
            </div>
          )}
          <div className="foot-actions">
            <button className="foot-btn" onClick={toggleTheme} aria-label="Toggle theme" title="Toggle theme">
              {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            {auth.data?.auth_enabled && (
              <button className="foot-btn grow" onClick={logout}>
                <LogOut size={16} /> Sign out
              </button>
            )}
          </div>
        </div>
      </aside>
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
      {changingPw && <ChangePasswordDialog onClose={() => setChangingPw(false)} />}
      <div className="main">
        <header className="topbar">
          <button className="icon-btn" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={20} /></button>
          <span className="brand-name">pgAccessControl</span>
        </header>
        {(current.environment === "production" || current.read_only) && (
          <div className={`server-banner ${current.environment === "production" ? "prod" : "ro"}`} role="status">
            {current.environment === "production" && <><EnvBadge env="production" compact /> <strong>{current.name}</strong></>}
            {current.environment !== "production" && <><Lock size={14} /> <strong>{current.name}</strong></>}
            <span>{current.environment === "production" ? "You are working on a production server." : ""}{current.read_only ? " Read-only: changes are disabled on this server." : ""}</span>
          </div>
        )}
        {meta.error && (
          <div className="page unreachable">
            <div className="notice notice-danger" role="alert">
              <div className="grow"><strong>{current.name} is not reachable.</strong> {(meta.error as Error).message}</div>
              <button className="btn btn-secondary btn-sm" onClick={() => meta.refetch()}>Retry</button>
            </div>
          </div>
        )}
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
