import { useEffect, useState } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { ClipboardList, History, KeyRound, LayoutDashboard, LogOut, Menu, Moon, ShieldCheck, Sun, UserRound, Users } from "lucide-react";
import { api } from "../api/client";
import { useAuth, useMeta } from "../api/hooks";
import { cx } from "./ui";

const NAV = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/users", label: "Users", icon: UserRound },
  { to: "/roles", label: "Roles", icon: Users },
  { to: "/permissions", label: "Permissions", icon: KeyRound },
  { to: "/reports", label: "Reports", icon: ClipboardList },
  { to: "/activity", label: "Activity", icon: History },
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
  const qc = useQueryClient();

  const logout = async () => {
    await api.post("/auth/logout");
    qc.clear();
    qc.invalidateQueries({ queryKey: ["auth"] });
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
        <nav className="nav" onClick={() => setOpen(false)}>
          {NAV.map(({ to, label, icon: Icon, end }) => (
            <NavLink key={to} to={to} end={end} className={({ isActive }) => cx("nav-item", isActive && "active")}>
              <Icon size={18} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          {meta.data && (
            <div className="server-card" title={`${meta.data.host}:${meta.data.port}`}>
              <span className="dot" />
              <div>
                <div className="server-line">PostgreSQL {meta.data.server_version.split(" ")[0]}</div>
                <div className="server-sub">as {meta.data.connected_as}{meta.data.is_superuser ? " · superuser" : ""}</div>
              </div>
            </div>
          )}
          <div className="foot-actions">
            <button className="foot-btn" onClick={toggleTheme} aria-label="Toggle theme" title="Toggle theme">
              {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            {auth.data?.auth_enabled && (
              <button className="foot-btn grow" onClick={logout}>
                <LogOut size={16} /> Sign out{auth.data.username ? ` (${auth.data.username})` : ""}
              </button>
            )}
          </div>
        </div>
      </aside>
      {open && <div className="scrim" onClick={() => setOpen(false)} />}
      <div className="main">
        <header className="topbar">
          <button className="icon-btn" onClick={() => setOpen(true)} aria-label="Open menu"><Menu size={20} /></button>
          <span className="brand-name">pgAccessControl</span>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
