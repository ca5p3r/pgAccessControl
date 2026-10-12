import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Camera, Check, Database, Download, FileCode2, FileJson, FileSpreadsheet, FolderTree, Hash, Search, ShieldQuestion, SquareFunction, Table2 } from "lucide-react";
import { downloadUrl, useAccessReport, useDatabases, useMeta, useObjects } from "../api/hooks";
import type { AccessPrincipal, ObjType, ObjectItem } from "../api/types";
import { Avatar, Badge, Button, Empty, ErrorNote, Notice, SearchInput, Spinner, Tabs, cx, useDebounced } from "../components/ui";
import { RolePicker } from "../components/roles";
import { SnapshotsTab } from "../components/SnapshotsTab";

const DB_KEY = "pgac-database";
const savedDb = () => { try { return localStorage.getItem(DB_KEY); } catch { return null; } };

const TYPES: { id: ObjType; label: string; icon: JSX.Element }[] = [
  { id: "table", label: "Table / view", icon: <Table2 size={15} /> },
  { id: "sequence", label: "Sequence", icon: <Hash size={15} /> },
  { id: "function", label: "Function", icon: <SquareFunction size={15} /> },
  { id: "schema", label: "Schema", icon: <FolderTree size={15} /> },
  { id: "database", label: "Database", icon: <Database size={15} /> },
];

/** Same protection as the server: stop spreadsheet apps from evaluating names that start with = + - @. */
const csvCell = (v: unknown) => {
  let s = String(v ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

function useDatabaseChoice() {
  const dbs = useDatabases();
  const meta = useMeta();
  const [database, setDatabase] = useState<string>();
  useEffect(() => {
    if (database || !dbs.data) return;
    const ok = dbs.data.filter((d) => d.connectable);
    const saved = savedDb();
    setDatabase((ok.find((d) => d.name === saved) ?? ok.find((d) => d.name !== meta.data?.database) ?? ok[0])?.name);
  }, [dbs.data, meta.data, database]);
  return { dbs, database, setDatabase };
}

const objLabel = (o: Pick<ObjectItem, "schema" | "name" | "args">, type: ObjType) =>
  type === "database" || type === "schema" ? o.name : `${o.schema}.${o.name}${o.args ? `(${o.args})` : ""}`;

/* ----------------------------------------------------------------- picker */
function ObjectPicker({ database, type, schema, value, onPick }: { database?: string; type: ObjType; schema?: string; value?: string; onPick: (o: ObjectItem) => void }) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q, 200);
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const { data, isFetching } = useObjects({ database, type, schema: schema || undefined, q: dq || undefined }, open);
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);
  return (
    <div className="picker" ref={box}>
      <div className="picker-box" onClick={() => setOpen(true)}>
        <Search size={15} className="muted" />
        <input value={q} onFocus={() => setOpen(true)} onChange={(e) => { setQ(e.target.value); setOpen(true); }} placeholder={value ?? `Search ${type}s by name…`} aria-label="Object" />
      </div>
      {open && (
        <div className="picker-menu">
          {!data && isFetching ? <div className="picker-empty">Searching…</div> : !data?.items.length ? <div className="picker-empty">Nothing found</div> : (
            <>
              {data.items.map((o) => (
                <button type="button" key={o.oid} className="picker-opt" onClick={() => { onPick(o); setOpen(false); setQ(""); }}>
                  <span className="grow mono">{objLabel(o, type)}</span>
                  {["view", "matview", "foreign", "partitioned", "procedure"].includes(o.kind) && <Badge>{o.kind}</Badge>}
                  <span className="muted small">owner {o.owner}</span>
                </button>
              ))}
              {data.total > data.items.length && <div className="picker-empty">Showing {data.items.length} of {data.total.toLocaleString()} — type to narrow down</div>}
            </>
          )}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------ access tab */
function AccessTab() {
  const [sp, setSp] = useSearchParams();
  const { dbs, database: defaultDb, setDatabase } = useDatabaseChoice();
  const database = sp.get("db") ?? defaultDb;
  const type = (TYPES.find((t) => t.id === sp.get("type"))?.id ?? "table") as ObjType;
  const oid = sp.get("oid") ? Number(sp.get("oid")) : undefined;
  const [schema, setSchema] = useState("");
  const [filter, setFilter] = useState("");
  const [only, setOnly] = useState<"all" | "user" | "role">("all");
  const report = useAccessReport(database, type, oid);

  const set = (changes: Record<string, string | null>) =>
    setSp((prev) => { const n = new URLSearchParams(prev); n.set("tab", "access"); for (const [k, v] of Object.entries(changes)) (v ? n.set(k, v) : n.delete(k)); return n; }, { replace: true });

  const principals = useMemo(
    () => (report.data?.principals ?? []).filter((p) => (only === "all" || p.kind === only) && p.name.toLowerCase().includes(filter.toLowerCase())),
    [report.data, filter, only],
  );

  const exportCsv = () => {
    const r = report.data!;
    const lines = [["principal", "kind", "superuser", "owner", "privilege", "via"].join(",")];
    for (const p of r.principals) for (const [priv, via] of Object.entries(p.privileges)) lines.push([p.name, p.kind, p.superuser, p.is_owner, priv, via.join("; ")].map(csvCell).join(","));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv" }));
    a.download = `access-${r.object.name}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="stack">
      <section className="card chooser-col">
        <div className="grid-3">
          <label className="field"><span className="field-label">Database</span>
            <select className="select" value={database ?? ""} onChange={(e) => { setDatabase(e.target.value); set({ db: e.target.value, oid: null }); }}>
              {dbs.data?.map((d) => <option key={d.name} value={d.name} disabled={!d.connectable}>{d.name}{d.connectable ? "" : " (no access)"}</option>)}
            </select>
          </label>
          <label className="field"><span className="field-label">Object type</span>
            <select className="select" value={type} onChange={(e) => set({ type: e.target.value, oid: null })}>
              {TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}
            </select>
          </label>
          {["table", "sequence", "function"].includes(type) && (
            <label className="field"><span className="field-label">Schema (optional)</span>
              <input className="input" value={schema} onChange={(e) => setSchema(e.target.value)} placeholder="any" />
            </label>
          )}
        </div>
        <div className="field">
          <span className="field-label">Object</span>
          <ObjectPicker database={database} type={type} schema={schema} value={report.data ? objLabel(report.data.object, type) : undefined} onPick={(o) => set({ oid: String(o.oid), db: database ?? null })} />
        </div>
      </section>

      {oid === undefined ? (
        <Empty icon={<ShieldQuestion size={30} />} title="Who can access this?">
          Pick a table, view, sequence, function, schema or database to see every user and role that can use it, and exactly why — a direct grant, PUBLIC, or inherited from another role.
        </Empty>
      ) : report.isLoading ? <Spinner label="Working out who has access…" /> : report.error ? <ErrorNote error={report.error} retry={() => report.refetch()} /> : report.data && (
        <>
          <section className="card report-head">
            <div className="card-icon">{TYPES.find((t) => t.id === type)?.icon}</div>
            <div className="grow">
              <h3 className="mono">{objLabel(report.data.object, type)}</h3>
              <p className="muted">{report.data.object.kind} · owner <strong>{report.data.object.owner}</strong> · {report.data.principals.length} {report.data.principals.length === 1 ? "principal has" : "principals have"} access</p>
            </div>
            <Button icon={<Download size={15} />} onClick={exportCsv}>Export CSV</Button>
          </section>
          {report.data.truncated && <Notice tone="warn">Very large result: only the first rows are shown. Narrow the search or use the SQL/CSV export.</Notice>}
          <div className="toolbar">
            <SearchInput value={filter} onChange={setFilter} placeholder="Filter users and roles…" />
            <div className="seg" role="group" aria-label="Show">
              {(["all", "user", "role"] as const).map((k) => <button key={k} className={cx(only === k && "on")} onClick={() => setOnly(k)}>{k === "all" ? "All" : k === "user" ? "Users" : "Roles"}</button>)}
            </div>
            <span className="grow" />
            <span className="muted">{principals.length} shown</span>
          </div>
          <div className="grid-wrap">
            <table className="grid access">
              <thead>
                <tr>
                  <th className="obj-col">Principal</th>
                  {report.data.privilege_names.map((p) => <th key={p}>{p}</th>)}
                  <th className="left">Access via</th>
                </tr>
              </thead>
              <tbody>
                {principals.length === 0 ? <tr><td colSpan={report.data.privilege_names.length + 2}><Empty title="No matching principals" /></td></tr> : principals.map((p) => <PrincipalRow key={p.name} p={p} names={report.data!.privilege_names} />)}
              </tbody>
            </table>
          </div>
          {report.data.grants.length > 0 && (
            <details className="raw-acl">
              <summary>Raw grants on this object ({report.data.grants.length})</summary>
              <table className="table"><thead><tr><th>Grantee</th><th>Privilege</th><th>Grantor</th><th>Grant option</th></tr></thead>
                <tbody>{report.data.grants.map((g, i) => <tr key={i}><td className="mono">{g.grantee}</td><td>{g.privilege}</td><td className="mono">{g.grantor}</td><td>{g.grantable ? "yes" : "—"}</td></tr>)}</tbody></table>
            </details>
          )}
        </>
      )}
    </div>
  );
}

function PrincipalRow({ p, names }: { p: AccessPrincipal; names: string[] }) {
  const via = [...new Set(Object.values(p.privileges).flat())];
  return (
    <tr>
      <td className="obj-col">
        <div className="name-cell">
          <Avatar name={p.name} kind={p.kind} size={28} />
          <div>
            <div className="name">{p.name}</div>
            <div className="obj-sub">{p.kind}{p.superuser ? " · superuser" : ""}{p.is_owner ? " · owner" : ""}</div>
          </div>
        </div>
      </td>
      {names.map((n) => {
        const src = p.privileges[n];
        const direct = src?.includes("direct");
        return (
          <td key={n}>
            {src ? <span className={cx("pip", direct ? "direct" : "inherited")} title={`${n}: ${src.join(", ")}`}><Check size={14} strokeWidth={3} /></span> : <span className="pip-empty" aria-label={`no ${n}`} />}
          </td>
        );
      })}
      <td className="left">
        <span className="badge-row">
          {via.map((v) => <Badge key={v} tone={v === "direct" ? "primary" : v === "PUBLIC" ? "warn" : v === "superuser" ? "danger" : "neutral"}>{v}</Badge>)}
        </span>
      </td>
    </tr>
  );
}

/* ------------------------------------------------------------ export tab */
type Format = "sql" | "csv" | "json";
const FORMATS: { id: Format; title: string; icon: JSX.Element; text: string }[] = [
  { id: "sql", title: "SQL script", icon: <FileCode2 size={22} />, text: "CREATE ROLE, GRANT and ALTER DEFAULT PRIVILEGES statements you can replay on another server or keep as a backup." },
  { id: "csv", title: "CSV", icon: <FileSpreadsheet size={22} />, text: "One flat table for spreadsheets and access reviews. Pick which dataset to export." },
  { id: "json", title: "JSON", icon: <FileJson size={22} />, text: "Everything in one structured document for scripts, diffing or other tools." },
];

function ExportTab() {
  const [sp] = useSearchParams();
  const { dbs, database, setDatabase } = useDatabaseChoice();
  const [role, setRole] = useState<string[]>(sp.get("role") ? [sp.get("role")!] : []);
  const [format, setFormat] = useState<Format>("sql");
  const [dataset, setDataset] = useState("privileges");
  const url = downloadUrl("/export", { format, database, role: role[0], dataset: format === "csv" ? dataset : undefined });

  return (
    <div className="stack">
      <section className="card">
        <div className="grid-2">
          <label className="field"><span className="field-label">Database</span>
            <select className="select" value={database ?? ""} onChange={(e) => setDatabase(e.target.value)}>
              {dbs.data?.map((d) => <option key={d.name} value={d.name} disabled={!d.connectable}>{d.name}{d.connectable ? "" : " (no access)"}</option>)}
            </select>
            <span className="field-hint">Object privileges are per database; role definitions and memberships are cluster-wide.</span>
          </label>
          <div className="field"><span className="field-label">Limit to one user or role</span>
            <RolePicker single value={role} onChange={setRole} placeholder="Everyone (all roles)" />
            <span className="field-hint">Leave empty to export everything. <button className="link-btn" onClick={() => setRole(["PUBLIC"])}>Use PUBLIC</button></span>
          </div>
        </div>
      </section>

      <div className="format-grid">
        {FORMATS.map((f) => (
          <button key={f.id} className={cx("format-card", format === f.id && "on")} onClick={() => setFormat(f.id)} aria-pressed={format === f.id}>
            {f.icon}<strong>{f.title}</strong><span className="muted">{f.text}</span>
          </button>
        ))}
      </div>

      {format === "csv" && (
        <label className="field narrow-field"><span className="field-label">Dataset</span>
          <select className="select" value={dataset} onChange={(e) => setDataset(e.target.value)}>
            <option value="privileges">Object privileges (who can do what on which object)</option>
            <option value="roles">Roles and users (attributes)</option>
            <option value="memberships">Role memberships</option>
            <option value="defaults">Default privileges</option>
          </select>
        </label>
      )}

      <Notice tone="info">
        Passwords are never exported. Only <em>explicit</em> grants are listed (the implicit owner privileges are skipped), and revokes of PostgreSQL's default PUBLIC privileges are not reproduced. Exports are recorded in Activity.
      </Notice>
      <div><Button variant="primary" icon={<Download size={16} />} disabled={!database} onClick={() => (window.location.href = url)}>Download {format.toUpperCase()}</Button></div>
    </div>
  );
}

/* ------------------------------------------------------------------- page */
export function ReportsPage() {
  const [sp, setSp] = useSearchParams();
  const tab = (["export", "snapshots"].includes(sp.get("tab") ?? "") ? sp.get("tab") : "access") as "access" | "export" | "snapshots";
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Reports</h1>
          <p className="muted">Review access across the server, export permissions, and compare snapshots to catch drift.</p>
        </div>
      </div>
      <Tabs<"access" | "export" | "snapshots"> value={tab} onChange={(t) => setSp(t === "access" ? {} : { tab: t }, { replace: true })}
        tabs={[{ id: "access", label: "Who has access?", icon: <ShieldQuestion size={15} /> }, { id: "export", label: "Export", icon: <Download size={15} /> }, { id: "snapshots", label: "Snapshots & drift", icon: <Camera size={15} /> }]} />
      <div className="tab-body">{tab === "access" ? <AccessTab /> : tab === "export" ? <ExportTab /> : <SnapshotsTab />}</div>
    </div>
  );
}
