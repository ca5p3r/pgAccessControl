import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { ArrowDown, ArrowUp, ChevronsUpDown, KeyRound, Pencil, Plus, Trash2, UserRound, Users, X } from "lucide-react";
import { useCan, useCreateRole, useRoles, type RoleAttr, type RoleSort } from "../api/hooks";
import type { RoleSummary } from "../api/types";
import { Avatar, Badge, Button, Drawer, Empty, ErrorNote, IconButton, Pagination, SearchInput, Spinner, Switch, cx, useDebounced, useToast } from "../components/ui";
import { DeleteRoleDialog, RoleBadges, RoleForm } from "../components/roles";

const SIZES = [25, 50, 100];
/** First click on a column sorts in the direction people usually want for it. */
const DEFAULT_DIR: Record<RoleSort, "asc" | "desc"> = { name: "asc", member_of: "desc", members: "desc", expires: "asc", conn_limit: "desc", privilege: "desc" };
const SORT_KEYS = Object.keys(DEFAULT_DIR) as RoleSort[];

const ATTR_OPTIONS: { value: RoleAttr; label: string; users?: boolean }[] = [
  { value: "all", label: "All attributes" },
  { value: "superuser", label: "Superusers" },
  { value: "createrole", label: "Can create roles" },
  { value: "createdb", label: "Can create databases" },
  { value: "replication", label: "Replication" },
  { value: "bypassrls", label: "Bypass RLS" },
  { value: "no_memberships", label: "Not in any role" },
  { value: "expired", label: "Expired", users: true },
];

function expiry(iso: string | null): { text: string; tone: "danger" | "warn" | "muted" } {
  if (!iso) return { text: "Never", tone: "muted" };
  const ms = new Date(iso).getTime() - Date.now();
  const days = Math.round(ms / 86_400_000);
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const text = Math.abs(days) >= 60 ? rtf.format(Math.round(days / 30), "month") : Math.abs(days) >= 1 ? rtf.format(days, "day") : rtf.format(Math.round(ms / 3_600_000), "hour");
  return { text: ms < 0 ? `Expired ${text}` : `Expires ${text}`, tone: ms < 0 ? "danger" : days <= 14 ? "warn" : "muted" };
}

function SortHeader({ label, field, sort, order, onSort, className }: { label: string; field: RoleSort; sort: RoleSort; order: "asc" | "desc"; onSort: (f: RoleSort) => void; className?: string }) {
  const active = sort === field;
  return (
    <th className={className} aria-sort={active ? (order === "asc" ? "ascending" : "descending") : "none"}>
      <button className={cx("sort-btn", active && "active")} onClick={() => onSort(field)} title={`Sort by ${label.toLowerCase()}`}>
        {label}
        {active ? order === "asc" ? <ArrowUp size={13} /> : <ArrowDown size={13} /> : <ChevronsUpDown size={13} className="sort-idle" />}
      </button>
    </th>
  );
}

export function RolesPage({ kind }: { kind: "user" | "role" }) {
  const [sp, setSp] = useSearchParams();
  const nav = useNavigate();
  const toast = useToast();
  const create = useCreateRole();
  const { can } = useCan();
  const searchRef = useRef<HTMLInputElement>(null);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);

  const base = kind === "user" ? "users" : "roles";
  const noun = kind === "user" ? "user" : "role";

  // All list state lives in the URL, so views survive a refresh and can be shared or bookmarked.
  const sortParam = sp.get("sort") as RoleSort | null;
  const sort: RoleSort = sortParam && SORT_KEYS.includes(sortParam) ? sortParam : "name";
  const order = (sp.get("order") as "asc" | "desc" | null) ?? DEFAULT_DIR[sort];
  const attr = (ATTR_OPTIONS.find((o) => o.value === sp.get("attr"))?.value ?? "all") as RoleAttr;
  const system = sp.get("system") === "1";
  const page = Math.max(0, Number(sp.get("page") ?? 0) || 0);
  const size = SIZES.includes(Number(sp.get("size"))) ? Number(sp.get("size")) : 25;
  const q = sp.get("q") ?? "";

  const update = useCallback((changes: Record<string, string | null>, resetPage = true) => {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(changes)) (v === null || v === "" ? next.delete(k) : next.set(k, v));
      if (resetPage) next.delete("page");
      return next;
    }, { replace: true });
  }, [setSp]);

  // The search box keeps its own text for snappy typing and writes to the URL after a pause.
  const [qInput, setQInput] = useState(q);
  const dq = useDebounced(qInput, 250);
  useEffect(() => { if (dq !== q) update({ q: dq }); }, [dq]); // eslint-disable-line react-hooks/exhaustive-deps

  const onSort = (f: RoleSort) => {
    const nextOrder = f === sort ? (order === "asc" ? "desc" : "asc") : DEFAULT_DIR[f];
    update({ sort: f === "name" && nextOrder === "asc" ? null : f, order: nextOrder === DEFAULT_DIR[f] && f !== sort ? null : nextOrder });
  };

  const { data, error, isLoading, isFetching, refetch } = useRoles({ kind, q: q || undefined, include_system: system, sort, order, attr, limit: size, offset: page * size });

  // Keyboard: "/" focuses search, "n" starts a new item (ignored while typing in a field).
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const el = e.target as HTMLElement;
      if (e.metaKey || e.ctrlKey || e.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName) || el.isContentEditable) return;
      if (e.key === "/") { e.preventDefault(); searchRef.current?.focus(); }
      if (e.key === "n" && can("operator") && !creating && !deleting) { e.preventDefault(); setCreating(true); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [creating, deleting, can]);

  const filtered = !!(q || attr !== "all" || system);
  const clearFilters = () => { setQInput(""); update({ q: null, attr: null, system: null }); };
  const open = (r: RoleSummary, tab?: string) => nav(`/${base}/${encodeURIComponent(r.name)}${tab ? `?tab=${tab}` : ""}`);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>{kind === "user" ? "Users" : "Roles"}</h1>
          <p className="muted">
            {kind === "user"
              ? "Roles that can log in. Assign roles to grant them privileges."
              : "Reusable permission sets (group roles). Grant privileges to a role, then assign it to users."}
          </p>
        </div>
        {can("operator") && <Button variant="primary" icon={<Plus size={16} />} onClick={() => setCreating(true)} title="Shortcut: n">New {noun}</Button>}
      </div>

      <div className="toolbar">
        <SearchInput inputRef={searchRef} value={qInput} onChange={setQInput} placeholder={`Search ${base}…  ( / )`} />
        <select className="select" value={attr} onChange={(e) => update({ attr: e.target.value === "all" ? null : e.target.value })} aria-label="Filter by attribute">
          {ATTR_OPTIONS.filter((o) => !o.users || kind === "user").map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        {kind === "role" && <Switch label="Show system roles" checked={system} onChange={(v) => update({ system: v ? "1" : null })} />}
        {filtered && <Button size="sm" variant="ghost" icon={<X size={14} />} onClick={clearFilters}>Clear filters</Button>}
        <span className="grow" />
        <span className="muted">{data ? `${data.total.toLocaleString()} ${data.total === 1 ? noun : base}` : ""}</span>
        <select className="select" value={size} onChange={(e) => update({ size: e.target.value === "25" ? null : e.target.value })} aria-label="Rows per page">
          {SIZES.map((s) => <option key={s} value={s}>{s} / page</option>)}
        </select>
      </div>

      {error ? (
        <ErrorNote error={error} retry={() => refetch()} />
      ) : isLoading ? (
        <Spinner label={`Loading ${base}…`} />
      ) : data!.items.length === 0 ? (
        <Empty icon={kind === "user" ? <UserRound size={30} /> : <Users size={30} />} title={filtered ? "No matches" : `No ${base} yet`}>
          {filtered ? <Button onClick={clearFilters}>Clear filters</Button> : can("operator") ? <Button variant="primary" onClick={() => setCreating(true)}>Create the first {noun}</Button> : "Nothing to show."}
        </Empty>
      ) : (
        <div className={cx("card flush", isFetching && "fetching")}>
          <table className="table clickable">
            <thead>
              <tr>
                <SortHeader label="Name" field="name" sort={sort} order={order} onSort={onSort} />
                <SortHeader label="Attributes" field="privilege" sort={sort} order={order} onSort={onSort} />
                <SortHeader label="Member of" field="member_of" sort={sort} order={order} onSort={onSort} />
                {kind === "role" && <SortHeader label="Members" field="members" sort={sort} order={order} onSort={onSort} className="num" />}
                {kind === "user" && <SortHeader label="Expires" field="expires" sort={sort} order={order} onSort={onSort} />}
                <th />
              </tr>
            </thead>
            <tbody>
              {data!.items.map((r) => {
                const ex = expiry(r.valid_until);
                return (
                  <tr key={r.name} onClick={() => open(r)}>
                    <td>
                      <div className="name-cell">
                        <Avatar name={r.name} kind={r.kind} />
                        <div>
                          <div className="name">{r.name}</div>
                          {r.comment && <div className="muted small">{r.comment}</div>}
                        </div>
                      </div>
                    </td>
                    <td><RoleBadges role={r} max={3} /></td>
                    <td>
                      <span className="badge-row">
                        {r.member_of.slice(0, 3).map((m) => <Badge key={m} tone="primary">{m}</Badge>)}
                        {r.member_of.length > 3 && <Badge title={r.member_of.slice(3).join(", ")}>+{r.member_of.length - 3}</Badge>}
                        {r.member_of.length === 0 && <span className="muted">—</span>}
                      </span>
                    </td>
                    {kind === "role" && <td className="num">{r.member_count}</td>}
                    {kind === "user" && <td><span className={cx("expiry", ex.tone)} title={r.valid_until ?? "No expiry set"}>{ex.text}</span></td>}
                    <td className="actions" onClick={(e) => e.stopPropagation()}>
                      <IconButton label="Permissions" onClick={() => open(r, "permissions")}><KeyRound size={16} /></IconButton>
                      {!r.is_system && can("operator") && <IconButton label="Edit" onClick={() => open(r)}><Pencil size={16} /></IconButton>}
                      {!r.is_system && can("admin") && <IconButton label="Delete" className="danger" onClick={() => setDeleting(r.name)}><Trash2 size={16} /></IconButton>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <Pagination page={page} pageSize={size} total={data!.total} onPage={(p) => update({ page: p ? String(p) : null }, false)} />
        </div>
      )}

      {creating && (
        <Drawer
          title={`New ${noun}`}
          subtitle={kind === "user" ? "A role with LOGIN that can connect to the database." : "A group role without LOGIN. Grant it privileges, then add members."}
          onClose={() => setCreating(false)}
        >
          <RoleForm
            mode="create"
            kind={kind}
            saving={create.isPending}
            onCancel={() => setCreating(false)}
            onSubmit={(v) =>
              create.mutate(v, {
                onSuccess: (r) => { toast.success(`Created ${r.name}`); setCreating(false); nav(`/${base}/${encodeURIComponent(r.name)}`); },
                onError: toast.error,
              })
            }
          />
        </Drawer>
      )}
      {deleting && <DeleteRoleDialog name={deleting} onClose={() => setDeleting(null)} onDeleted={() => setDeleting(null)} />}
    </div>
  );
}
