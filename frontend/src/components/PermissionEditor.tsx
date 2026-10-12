import { useEffect, useState } from "react";
import { Check, Copy, Database, FolderTree, Func, Hash, Layers, Minus, Plus, Table2, Undo2, X, Zap } from "./icons";
import { useApplyPermissions, useDatabases, useDefaultPrivileges, useMeta, usePermObjects, useSchemas } from "../api/hooks";
import type { ChangeObjectType, ObjType, PermObject, PermissionChange } from "../api/types";
import { Badge, Button, Empty, ErrorNote, IconButton, Modal, Notice, Pagination, SearchInput, Spinner, Tabs, Switch, cx, useDebounced, useToast } from "./ui";

type TabId = ObjType | "defaults";
const PAGE_SIZE = 100;
const DB_KEY = "pgac-database";
const readSaved = () => {
  try { return localStorage.getItem(DB_KEY); } catch { return null; }
};

interface Target {
  type: ObjType;
  schema?: string;
  name: string;
  oid?: number;
}
interface PendingEntry {
  target: Target;
  grant: Set<string>;
  revoke: Set<string>;
}
interface Extra {
  id: string;
  label: string;
  change: PermissionChange;
}
type CellState = "direct" | "inherited" | "grant" | "revoke" | "none";

const targetKey = (t: Target) => `${t.type}|${t.schema ?? ""}|${t.name}|${t.oid ?? ""}`;
const toTarget = (type: ObjType, o: PermObject): Target =>
  type === "database" ? { type, name: o.name } : type === "schema" ? { type, name: o.name } : type === "function" ? { type, schema: o.schema, name: o.name, oid: o.oid } : { type, schema: o.schema, name: o.name };

/** Mutates ``m`` so the *effective direct* state of one privilege on one object becomes ``on``. */
function applyCell(m: Map<string, PendingEntry>, target: Target, direct: boolean, priv: string, on: boolean) {
  const key = targetKey(target);
  const cur = m.get(key);
  const e: PendingEntry = { target, grant: new Set(cur?.grant), revoke: new Set(cur?.revoke) };
  if (on) (direct ? e.revoke.delete(priv) : e.grant.add(priv));
  else (direct ? e.revoke.add(priv) : e.grant.delete(priv));
  if (e.grant.size || e.revoke.size) m.set(key, e);
  else m.delete(key);
}

function cellState(o: PermObject, priv: string, e?: PendingEntry): CellState {
  if (e?.revoke.has(priv)) return "revoke";
  if (e?.grant.has(priv)) return "grant";
  if (o.direct.includes(priv)) return "direct";
  if (o.inherited[priv]?.length) return "inherited";
  return "none";
}
const effectiveDirect = (o: PermObject, priv: string, e?: PendingEntry) => (o.direct.includes(priv) && !e?.revoke.has(priv)) || !!e?.grant.has(priv);

function buildChanges(pending: Map<string, PendingEntry>, extras: Extra[]): PermissionChange[] {
  const out: PermissionChange[] = extras.map((x) => x.change);
  const base = (t: Target) => ({ object_type: t.type as ChangeObjectType, schema: t.schema ?? null, name: t.name, oid: t.oid ?? null });
  for (const e of pending.values()) if (e.revoke.size) out.push({ action: "revoke", ...base(e.target), privileges: [...e.revoke] });
  for (const e of pending.values()) if (e.grant.size) out.push({ action: "grant", ...base(e.target), privileges: [...e.grant] });
  return out;
}

const TAB_META: { id: TabId; label: string; icon: JSX.Element }[] = [
  { id: "database", label: "Databases", icon: <Database size={15} /> },
  { id: "schema", label: "Schemas", icon: <FolderTree size={15} /> },
  { id: "table", label: "Tables & views", icon: <Table2 size={15} /> },
  { id: "sequence", label: "Sequences", icon: <Hash size={15} /> },
  { id: "function", label: "Functions", icon: <Func size={15} /> },
  { id: "defaults", label: "Default privileges", icon: <Layers size={15} /> },
];

/* =========================================================================
   Main editor
   ========================================================================= */
export function PermissionEditor({ role }: { role: string }) {
  const meta = useMeta();
  const dbs = useDatabases();
  const toast = useToast();
  const [database, setDatabase] = useState<string>();
  const [tab, setTab] = useState<TabId>("table");
  const [schema, setSchema] = useState("");
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [grantedOnly, setGrantedOnly] = useState(false);
  const [page, setPage] = useState(0);
  const [pending, setPending] = useState<Map<string, PendingEntry>>(new Map());
  const [extras, setExtras] = useState<Extra[]>([]);
  const [reviewing, setReviewing] = useState(false);
  const schemas = useSchemas(database);

  // Pick a sensible initial database once the list is known.
  useEffect(() => {
    if (database || !dbs.data) return;
    const ok = dbs.data.filter((d) => d.connectable);
    // Remembered choice first, then any database other than the maintenance one (which usually holds no app data).
    const saved = readSaved();
    setDatabase((ok.find((d) => d.name === saved) ?? ok.find((d) => d.name !== meta.data?.database) ?? ok[0])?.name);
  }, [dbs.data, meta.data, database]);

  useEffect(() => setSchema(""), [database]);

  useEffect(() => setPage(0), [tab, schema, dq, grantedOnly, database]);

  const objectTab = tab !== "defaults";
  const perms = usePermObjects(
    role,
    { database: database ?? "", type: (objectTab ? tab : "table") as ObjType, schema: schema || undefined, q: dq || undefined, granted_only: grantedOnly, limit: PAGE_SIZE, offset: page * PAGE_SIZE },
    !!database && objectTab,
  );

  const pendingCount = [...pending.values()].reduce((n, e) => n + e.grant.size + e.revoke.size, 0) + extras.length;

  const changeDatabase = (name: string) => {
    if (pendingCount && !window.confirm("Switching database discards your pending changes. Continue?")) return;
    setPending(new Map());
    setExtras([]);
    setDatabase(name);
    try { localStorage.setItem(DB_KEY, name); } catch { /* storage unavailable */ }
  };

  const privs = (objectTab ? meta.data?.privileges[tab as ObjType] : undefined) ?? perms.data?.privileges ?? [];
  const schemaFiltered = tab === "table" || tab === "sequence" || tab === "function";
  const items = perms.data?.items ?? [];

  const toggleCell = (o: PermObject, priv: string) => {
    const t = toTarget(tab as ObjType, o);
    setPending((prev) => {
      const m = new Map(prev);
      applyCell(m, t, o.direct.includes(priv), priv, !effectiveDirect(o, priv, prev.get(targetKey(t))));
      return m;
    });
  };
  const setMany = (cells: { o: PermObject; priv: string }[], on: boolean) =>
    setPending((prev) => {
      const m = new Map(prev);
      for (const { o, priv } of cells) applyCell(m, toTarget(tab as ObjType, o), o.direct.includes(priv), priv, on);
      return m;
    });
  const entryOf = (o: PermObject) => pending.get(targetKey(toTarget(tab as ObjType, o)));
  const rowAllOn = (o: PermObject) => privs.every((p) => effectiveDirect(o, p, entryOf(o)));
  const colAllOn = (p: string) => items.length > 0 && items.every((o) => effectiveDirect(o, p, entryOf(o)));

  if (dbs.isLoading || meta.isLoading) return <Spinner label="Loading…" />;
  if (dbs.error) return <ErrorNote error={dbs.error} retry={() => dbs.refetch()} />;

  return (
    <div className="perm">
      <div className="perm-toolbar">
        <div className="perm-db">
          <Database size={16} />
          <select className="select" value={database ?? ""} onChange={(e) => changeDatabase(e.target.value)} aria-label="Database">
            {dbs.data?.map((d) => (
              <option key={d.name} value={d.name} disabled={!d.connectable}>
                {d.name}
                {d.connectable ? "" : " (no access)"}
              </option>
            ))}
          </select>
        </div>
        <Tabs tabs={TAB_META} value={tab} onChange={setTab} />
      </div>

      {perms.data?.role_superuser && (
        <Notice tone="warn">
          <strong>{role} is a superuser</strong> and bypasses all permission checks. Grants shown here have no effect while the superuser attribute is set.
        </Notice>
      )}
      {role.toUpperCase() === "PUBLIC" && <Notice tone="info">PUBLIC is a built-in pseudo-role that stands for <strong>every</strong> role. Privileges granted here apply to all users.</Notice>}

      {objectTab && (
        <>
          <div className="perm-filters">
            {schemaFiltered && (
              <select className="select" value={schema} onChange={(e) => setSchema(e.target.value)} aria-label="Schema">
                <option value="">All schemas</option>
                {schemas.data?.map((s) => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            )}
            <SearchInput value={q} onChange={setQ} placeholder={`Filter ${TAB_META.find((t) => t.id === tab)?.label.toLowerCase()}…`} />
            <label className="check-inline">
              <input type="checkbox" checked={grantedOnly} onChange={(e) => setGrantedOnly(e.target.checked)} /> Only with access
            </label>
            <Legend />
          </div>

          {perms.error ? (
            <ErrorNote error={perms.error} retry={() => perms.refetch()} />
          ) : !perms.data ? (
            <Spinner label="Loading permissions…" />
          ) : items.length === 0 ? (
            <Empty icon={<Table2 size={28} />} title="Nothing to show">
              {grantedOnly ? "This role has no access to any matching object." : "No matching objects in this scope."}
            </Empty>
          ) : (
            <div className={cx("grid-wrap", perms.isFetching && "fetching")}>
              <table className="grid">
                <thead>
                  <tr>
                    <th className="obj-col">{TAB_META.find((t) => t.id === tab)?.label.replace(" & views", "")}</th>
                    {privs.map((p) => (
                      <th key={p}>
                        <button className="th-btn" title={`Toggle ${p} for all rows on this page`} onClick={() => setMany(items.map((o) => ({ o, priv: p })), !colAllOn(p))}>
                          {p}
                        </button>
                      </th>
                    ))}
                    <th>All</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((o) => {
                    const e = entryOf(o);
                    return (
                      <tr key={`${o.oid}`} className={cx(e && "row-pending")}>
                        <td className="obj-col">
                          <div className="obj-name">
                            {schemaFiltered && !schema && <span className="muted">{o.schema}.</span>}
                            <span className="mono">{o.name}</span>
                            {o.args !== "" && <span className="muted mono">({o.args})</span>}
                            {["view", "matview", "foreign", "partitioned", "procedure"].includes(o.kind) && <Badge>{o.kind === "matview" ? "mat. view" : o.kind}</Badge>}
                          </div>
                          <div className="obj-sub">owner {o.owner}</div>
                        </td>
                        {privs.map((p) => {
                          const st = cellState(o, p, e);
                          const src = o.inherited[p]?.join(", ");
                          return (
                            <td key={p}>
                              <button
                                className={cx("pip", st)}
                                onClick={() => toggleCell(o, p)}
                                aria-label={`${p} on ${o.name}: ${st}`}
                                aria-pressed={st === "direct" || st === "grant"}
                                title={
                                  st === "direct" ? `${p}: granted directly${o.grantable.includes(p) ? " (with grant option)" : ""} — click to revoke`
                                  : st === "inherited" ? `${p}: inherited from ${src} — click to also grant directly`
                                  : st === "grant" ? `${p}: will be granted — click to cancel`
                                  : st === "revoke" ? `${p}: will be revoked — click to cancel`
                                  : `${p}: not granted — click to grant`
                                }
                              >
                                {st === "direct" || st === "inherited" ? <Check size={14} strokeWidth={3} /> : st === "grant" ? <Plus size={14} strokeWidth={3} /> : st === "revoke" ? <Minus size={14} strokeWidth={3} /> : null}
                                {st === "direct" && o.grantable.includes(p) && <span className="pip-dot" />}
                              </button>
                            </td>
                          );
                        })}
                        <td>
                          <IconButton label={rowAllOn(o) ? "Clear all" : "Select all"} onClick={() => setMany(privs.map((priv) => ({ o, priv })), !rowAllOn(o))}>
                            {rowAllOn(o) ? <X size={14} /> : <Zap size={14} />}
                          </IconButton>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {perms.data && <Pagination page={page} pageSize={PAGE_SIZE} total={perms.data.total} onPage={setPage} />}
        </>
      )}

      {(tab === "table" || tab === "sequence" || tab === "function") && (
        <BulkPanel
          key={tab}
          mode="all"
          lockedType={tab}
          schema={schema}
          schemas={schemas.data ?? []}
          onAdd={(x) => setExtras((l) => [...l, x])}
          catalog={meta.data?.privileges}
        />
      )}

      {tab === "defaults" && database && (
        <DefaultsTab role={role} database={database} schemas={schemas.data ?? []} catalog={meta.data?.privileges} onAdd={(x) => setExtras((l) => [...l, x])} />
      )}

      {pendingCount > 0 && (
        <div className="pending-bar" role="region" aria-label="Pending changes">
          <div className="pending-info">
            <strong>{pendingCount}</strong> pending change{pendingCount === 1 ? "" : "s"}
            <span className="pending-chips">
              {extras.map((x) => (
                <span key={x.id} className={cx("chip", x.change.action === "revoke" ? "chip-danger" : "chip-success")}>
                  {x.label}
                  <button aria-label="Remove" onClick={() => setExtras((l) => l.filter((y) => y.id !== x.id))}><X size={12} /></button>
                </span>
              ))}
            </span>
          </div>
          <Button variant="ghost" icon={<Undo2 size={15} />} onClick={() => { setPending(new Map()); setExtras([]); }}>Discard</Button>
          <Button variant="primary" onClick={() => setReviewing(true)}>Review &amp; apply</Button>
        </div>
      )}

      {reviewing && database && (
        <ReviewDialog
          role={role}
          database={database}
          changes={buildChanges(pending, extras)}
          onClose={() => setReviewing(false)}
          onApplied={(n) => {
            setReviewing(false);
            setPending(new Map());
            setExtras([]);
            toast.success(`${n} statement${n === 1 ? "" : "s"} applied to ${database}`);
          }}
        />
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ Legend */
function Legend() {
  return (
    <span className="legend">
      <span><i className="pip mini direct"><Check size={10} strokeWidth={3} /></i> direct</span>
      <span><i className="pip mini inherited"><Check size={10} strokeWidth={3} /></i> inherited</span>
      <span><i className="pip mini grant"><Plus size={10} strokeWidth={3} /></i> to grant</span>
      <span><i className="pip mini revoke"><Minus size={10} strokeWidth={3} /></i> to revoke</span>
    </span>
  );
}

/* ------------------------------------------------------------ Review dialog */
function ReviewDialog({ role, database, changes, onClose, onApplied }: { role: string; database: string; changes: PermissionChange[]; onClose: () => void; onApplied: (n: number) => void }) {
  const apply = useApplyPermissions(role);
  const [preview, setPreview] = useState<string[] | null>(null);
  const [copied, setCopied] = useState(false);
  const { mutate: dry } = apply;

  useEffect(() => {
    dry({ database, changes, dry_run: true }, { onSuccess: (r) => setPreview(r.statements) });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const error = apply.error;
  return (
    <Modal
      wide
      title="Review changes"
      subtitle={`These statements run in one transaction on database “${database}”. If any fails, nothing is changed.`}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!preview} loading={apply.isPending && !apply.variables?.dry_run}
            onClick={() => apply.mutate({ database, changes }, { onSuccess: (r) => onApplied(r.statements.length) })}>
            Apply {preview?.length ?? ""} statement{preview?.length === 1 ? "" : "s"}
          </Button>
        </>
      }
    >
      {error && <ErrorNote error={error} />}
      {!preview && !error ? (
        <Spinner label="Generating SQL…" />
      ) : preview ? (
        <div className="code-wrap">
          <button className="code-copy" onClick={async () => { await navigator.clipboard?.writeText(preview.join("\n")); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
            {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "Copied" : "Copy"}
          </button>
          <pre className="code">{preview.join("\n")}</pre>
        </div>
      ) : null}
    </Modal>
  );
}

/* --------------------------------------------------------------- Bulk panel */
const TYPE_LABEL: Record<string, string> = { table: "tables", sequence: "sequences", function: "functions", schema: "schemas" };

function BulkPanel({ mode, lockedType, schema, schemas, onAdd, catalog }: { mode: "all" | "default"; lockedType?: ObjType; schema: string; schemas: string[]; onAdd: (x: Extra) => void; catalog?: Record<ObjType, string[]> }) {
  const [type, setType] = useState<ObjType>(lockedType ?? "table");
  const [chosen, setChosen] = useState<string[]>([]);
  const [defSchema, setDefSchema] = useState("");
  const [forRole, setForRole] = useState("");
  const [grantOpt, setGrantOpt] = useState(false);
  const [open, setOpen] = useState(mode === "default");
  const t = lockedType ?? type;
  const available = catalog?.[t] ?? [];
  const scope = mode === "all" ? schema : defSchema;

  useEffect(() => setChosen([]), [t]);

  const submit = (action: "grant" | "revoke") => {
    const privileges = chosen.length ? chosen : [];
    if (!privileges.length) return;
    const objectType = (mode === "all" ? `all_${TYPE_LABEL[t]}` : `default_${TYPE_LABEL[t]}`) as ChangeObjectType;
    const where = mode === "all" ? `in ${scope}` : `${scope ? `in ${scope}` : "everywhere"}${forRole ? `, created by ${forRole}` : ""}`;
    const label = `${action === "grant" ? "Grant" : "Revoke"} ${privileges.join("/")} on ${mode === "all" ? "all" : "future"} ${TYPE_LABEL[t]} ${where}`;
    onAdd({
      id: crypto.randomUUID(),
      label,
      change: {
        action, object_type: objectType, privileges,
        schema: scope || null,
        for_role: mode === "default" ? forRole || null : null,
        with_grant_option: action === "grant" && grantOpt,
      },
    });
    setChosen([]);
  };

  const needsSchema = mode === "all" && !schema;
  return (
    <section className="card bulk">
      <button className="card-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
        <Zap size={16} />
        <span className="grow">
          <strong>{mode === "all" ? "Bulk grant / revoke" : "Add default privileges"}</strong>
          <span className="muted">
            {mode === "all" ? ` — change all existing ${TYPE_LABEL[t]} in a schema at once` : " — automatically applied to objects created in the future"}
          </span>
        </span>
        <span className="muted">{open ? "Hide" : "Show"}</span>
      </button>
      {open && (
        <div className="bulk-body">
          {mode === "default" && (
            <div className="grid-3">
              <label className="field"><span className="field-label">Object type</span>
                <select className="select" value={type} onChange={(e) => setType(e.target.value as ObjType)}>
                  {(["table", "sequence", "function", "schema"] as ObjType[]).map((x) => <option key={x} value={x}>{TYPE_LABEL[x]}</option>)}
                </select>
              </label>
              <label className="field"><span className="field-label">Schema</span>
                <select className="select" value={t === "schema" ? "" : defSchema} disabled={t === "schema"} onChange={(e) => setDefSchema(e.target.value)}>
                  <option value="">All schemas</option>
                  {schemas.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </label>
              <label className="field"><span className="field-label">Created by role</span>
                <input className="input" value={forRole} onChange={(e) => setForRole(e.target.value)} placeholder="(the app's connection user)" />
              </label>
            </div>
          )}
          {mode === "all" && (
            <p className="muted">
              {needsSchema ? "Select a schema above to enable bulk actions." : <>Target: all <strong>{TYPE_LABEL[t]}</strong> in schema <span className="mono">{schema}</span>.</>}
            </p>
          )}
          <div className="chip-toggles">
            {available.map((p) => (
              <button key={p} type="button" className={cx("chip-toggle", chosen.includes(p) && "on")} onClick={() => setChosen((c) => (c.includes(p) ? c.filter((x) => x !== p) : [...c, p]))}>
                {chosen.includes(p) && <Check size={12} strokeWidth={3} />} {p}
              </button>
            ))}
            <button type="button" className="chip-toggle ghost" onClick={() => setChosen(chosen.length === available.length ? [] : [...available])}>
              {chosen.length === available.length ? "None" : "All"}
            </button>
          </div>
          <div className="bulk-actions">
            <Switch label="With grant option" checked={grantOpt} onChange={setGrantOpt} />
            <div className="row gap">
              <Button variant="danger" disabled={!chosen.length || needsSchema} onClick={() => submit("revoke")}>Revoke</Button>
              <Button variant="primary" disabled={!chosen.length || needsSchema} onClick={() => submit("grant")}>Grant</Button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}

/* -------------------------------------------------------------- Defaults tab */
function DefaultsTab({ role, database, schemas, catalog, onAdd }: { role: string; database: string; schemas: string[]; catalog?: Record<ObjType, string[]>; onAdd: (x: Extra) => void }) {
  const defaults = useDefaultPrivileges(role, database);
  return (
    <div className="stack">
      <Notice tone="info">
        Default privileges only affect objects created <em>after</em> they are set, and only those created by the chosen role. Use “Bulk grant / revoke” on the table, sequence and function tabs for objects that already exist.
      </Notice>
      <section className="card flush">
        <div className="card-head pad"><div className="grow"><h3>Current default privileges for {role}</h3></div></div>
        {defaults.isLoading ? <Spinner /> : defaults.error ? <ErrorNote error={defaults.error} /> : !defaults.data?.length ? (
          <Empty icon={<Layers size={26} />} title="No default privileges">Add one below to grant access to future objects automatically.</Empty>
        ) : (
          <table className="table">
            <thead><tr><th>Object type</th><th>Schema</th><th>When created by</th><th>Privileges</th><th /></tr></thead>
            <tbody>
              {defaults.data.map((d, i) => (
                <tr key={i}>
                  <td className="cap">{TYPE_LABEL[d.object_type] ?? d.object_type}</td>
                  <td>{d.schema ?? <span className="muted">all schemas</span>}</td>
                  <td className="mono">{d.for_role}</td>
                  <td><span className="badge-row">{d.privileges.map((p) => <Badge key={p} tone="primary">{p}</Badge>)}</span></td>
                  <td className="right">
                    <Button size="sm" variant="ghost" disabled={d.object_type === "type"} onClick={() =>
                      onAdd({
                        id: crypto.randomUUID(),
                        label: `Revoke ${d.privileges.join("/")} on future ${TYPE_LABEL[d.object_type]}${d.schema ? ` in ${d.schema}` : ""} (by ${d.for_role})`,
                        change: { action: "revoke", object_type: `default_${TYPE_LABEL[d.object_type]}` as ChangeObjectType, privileges: d.privileges, schema: d.schema, for_role: d.for_role },
                      })}>
                      Revoke
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
      <BulkPanel mode="default" schema="" schemas={schemas} onAdd={onAdd} catalog={catalog} />
    </div>
  );
}
