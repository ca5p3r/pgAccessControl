import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Check, Copy, Database, Download, FolderTree, Func, Hash, Key, Layers, Minus, Plus, Table2, Undo2, X, Zap } from "./icons";
import { RolePicker } from "./roles";
import { useApplyPermissions, useCan, useColumnPrivileges, useDatabases, useDefaultPrivileges, useMeta, usePermObjects, useSchemas } from "../api/hooks";
import type { ChangeObjectType, ObjType, PermObject, PermissionChange, TemporaryPlan } from "../api/types";
import { ExpiryPicker, toLocalInput } from "./expiry";
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
  optOn: Set<string>; // privileges that should gain WITH GRANT OPTION
  optOff: Set<string>; // privileges that should lose the grant option (REVOKE GRANT OPTION FOR)
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

const copyEntry = (target: Target, cur?: PendingEntry): PendingEntry => ({
  target,
  grant: new Set(cur?.grant),
  revoke: new Set(cur?.revoke),
  optOn: new Set(cur?.optOn),
  optOff: new Set(cur?.optOff),
});
const isEmpty = (e: PendingEntry) => !(e.grant.size || e.revoke.size || e.optOn.size || e.optOff.size);
const commit = (m: Map<string, PendingEntry>, key: string, e: PendingEntry) => (isEmpty(e) ? m.delete(key) : m.set(key, e));

/** Mutates ``m`` so the *effective direct* state of one privilege on one object becomes ``on``. */
function applyCell(m: Map<string, PendingEntry>, target: Target, direct: boolean, priv: string, on: boolean) {
  const key = targetKey(target);
  const e = copyEntry(target, m.get(key));
  if (on) (direct ? e.revoke.delete(priv) : e.grant.add(priv));
  else (direct ? e.revoke.add(priv) : e.grant.delete(priv));
  if (!on) { e.optOn.delete(priv); e.optOff.delete(priv); } // no privilege left to carry the option
  commit(m, key, e);
}

/** Toggle WITH GRANT OPTION on a privilege that is (or is about to be) held directly. */
function applyOption(m: Map<string, PendingEntry>, target: Target, hadOption: boolean, priv: string) {
  const key = targetKey(target);
  const e = copyEntry(target, m.get(key));
  const set = hadOption ? e.optOff : e.optOn;
  if (set.has(priv)) set.delete(priv);
  else set.add(priv);
  commit(m, key, e);
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
  for (const e of pending.values()) {
    if (e.revoke.size) out.push({ action: "revoke", ...base(e.target), privileges: [...e.revoke] });
    if (e.optOff.size) out.push({ action: "revoke", revoke_grant_option: true, ...base(e.target), privileges: [...e.optOff] });
  }
  for (const e of pending.values()) {
    const plain = [...e.grant].filter((p) => !e.optOn.has(p));
    const withOpt = [...e.optOn]; // new grants that carry the option, and existing grants gaining it
    if (plain.length) out.push({ action: "grant", ...base(e.target), privileges: plain });
    if (withOpt.length) out.push({ action: "grant", with_grant_option: true, ...base(e.target), privileges: withOpt });
  }
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
  const nav = useNavigate();
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
  const [mode, setMode] = useState<"priv" | "option">("priv");
  const [columnsFor, setColumnsFor] = useState<PermObject | null>(null);
  const { can } = useCan();
  const ro = !can("operator");
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

  const pendingCount = [...pending.values()].reduce((n, e) => n + e.grant.size + e.revoke.size + e.optOn.size + e.optOff.size, 0) + extras.length;

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
    if (ro) return;
    const t = toTarget(tab as ObjType, o);
    setPending((prev) => {
      const m = new Map(prev);
      const e = prev.get(targetKey(t));
      if (mode === "option") {
        if (!effectiveDirect(o, priv, e)) return prev; // the privilege must be held directly first
        applyOption(m, t, o.grantable.includes(priv), priv);
      } else {
        applyCell(m, t, o.direct.includes(priv), priv, !effectiveDirect(o, priv, e));
      }
      return m;
    });
  };
  const setMany = (cells: { o: PermObject; priv: string }[], on: boolean) =>
    !ro &&
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
        <Button size="sm" variant="ghost" icon={<Download size={14} />} onClick={() => nav(`/reports?tab=export&role=${encodeURIComponent(role)}`)} title="Export this principal's permissions as SQL, CSV or JSON">Export</Button>
      </div>

      {ro && <Notice tone="info">You are signed in as a <strong>viewer</strong>: permissions are shown read-only.</Notice>}
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
            {!ro && (
              <div className="seg" role="group" aria-label="What a click changes">
                <button className={cx(mode === "priv" && "on")} onClick={() => setMode("priv")} title="Click cells to grant or revoke privileges">Privileges</button>
                <button className={cx(mode === "option" && "on")} onClick={() => setMode("option")} title="Click granted cells to add or remove WITH GRANT OPTION (the right to pass the privilege on)"><Key size={13} /> Grant option</button>
              </div>
            )}
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
                          <div className="obj-sub">owner {o.owner} · <button className="link-btn" onClick={() => nav(`/reports?tab=access&db=${encodeURIComponent(database ?? "")}&type=${tab}&oid=${o.oid}`)} title="See every user and role that can access this object">who has access?</button>{tab === "table" && !["foreign"].includes(o.kind) && <> · <button className="link-btn" onClick={() => setColumnsFor(o)} title="Grant or revoke SELECT, INSERT, UPDATE and REFERENCES on individual columns">columns</button></>}</div>
                        </td>
                        {privs.map((p) => {
                          const st = cellState(o, p, e);
                          const src = o.inherited[p]?.join(", ");
                          const held = effectiveDirect(o, p, e);
                          const optNow = (o.grantable.includes(p) && !e?.optOff.has(p)) || !!e?.optOn.has(p);
                          return (
                            <td key={p}>
                              <button
                                className={cx("pip", st, mode === "option" && !held && "dim")}
                                disabled={ro}
                                onClick={() => toggleCell(o, p)}
                                aria-label={`${p} on ${o.name}: ${st}`}
                                aria-pressed={st === "direct" || st === "grant"}
                                title={
                                  mode === "option" ? (held ? `${p}: ${optNow ? "can be passed on (grant option) — click to remove" : "click to allow passing it on (WITH GRANT OPTION)"}` : `${p}: grant the privilege first`)
                                  : st === "direct" ? `${p}: granted directly${o.grantable.includes(p) ? " (with grant option)" : ""} — click to revoke`
                                  : st === "inherited" ? `${p}: inherited from ${src} — click to also grant directly`
                                  : st === "grant" ? `${p}: will be granted — click to cancel`
                                  : st === "revoke" ? `${p}: will be revoked — click to cancel`
                                  : `${p}: not granted — click to grant`
                                }
                              >
                                {st === "direct" || st === "inherited" ? <Check size={14} strokeWidth={3} /> : st === "grant" ? <Plus size={14} strokeWidth={3} /> : st === "revoke" ? <Minus size={14} strokeWidth={3} /> : null}
                                {(st === "direct" || st === "grant") && (optNow || e?.optOff.has(p)) && <span className={cx("pip-dot", e?.optOn.has(p) && "add", e?.optOff.has(p) && "off")} />}
                              </button>
                            </td>
                          );
                        })}
                        <td>
                          {!ro && mode === "priv" && (
                            <IconButton label={rowAllOn(o) ? "Clear all" : "Select all"} onClick={() => setMany(privs.map((priv) => ({ o, priv })), !rowAllOn(o))}>
                              {rowAllOn(o) ? <X size={14} /> : <Zap size={14} />}
                            </IconButton>
                          )}
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

      {!ro && (tab === "table" || tab === "sequence" || tab === "function") && (
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
        <DefaultsTab role={role} database={database} schemas={schemas.data ?? []} catalog={meta.data?.privileges} onAdd={(x) => setExtras((l) => [...l, x])} readOnly={ro} />
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

      {columnsFor && database && (
        <ColumnsDialog
          role={role}
          database={database}
          schema={columnsFor.schema}
          table={columnsFor.name}
          readOnly={ro}
          onClose={() => setColumnsFor(null)}
          onAdd={(xs) => { setExtras((l) => [...l, ...xs]); setColumnsFor(null); }}
        />
      )}

      {reviewing && database && (
        <ReviewDialog
          role={role}
          database={database}
          changes={buildChanges(pending, extras)}
          onClose={() => setReviewing(false)}
          onApplied={(n, temporary) => {
            setReviewing(false);
            setPending(new Map());
            setExtras([]);
            toast.success(`${n} statement${n === 1 ? "" : "s"} applied to ${database}${temporary ? `; ends ${new Date(temporary).toLocaleString()}` : ""}`);
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
      <span><i className="pip-dot inline" /> grant option</span>
    </span>
  );
}

/* ------------------------------------------------------------ Review dialog */
const NOT_EXPIRABLE = /^(all_|default_)/;

function ReviewDialog({ role, database, changes, onClose, onApplied }: { role: string; database: string; changes: PermissionChange[]; onClose: () => void; onApplied: (n: number, temporary?: string) => void }) {
  const apply = useApplyPermissions(role);
  const [preview, setPreview] = useState<string[] | null>(null);
  const [plan, setPlan] = useState<TemporaryPlan | null>(null);
  const [copied, setCopied] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [grantor, setGrantor] = useState<string[]>([]);
  const [cascade, setCascade] = useState(false);
  const [temp, setTemp] = useState(false);
  const [when, setWhen] = useState(toLocalInput(new Date(Date.now() + 24 * 3_600_000)));
  const { mutate: dry } = apply;
  const hasRevoke = changes.some((c) => c.action === "revoke");
  const canExpire = changes.length > 0 && changes.every((c) => c.action === "grant" && !NOT_EXPIRABLE.test(c.object_type));
  const finalChanges = cascade ? changes.map((c) => (c.action === "revoke" ? { ...c, cascade: true } : c)) : changes;
  const expires_at = temp && canExpire && when ? new Date(when).toISOString() : undefined;
  const key = JSON.stringify([finalChanges, grantor, expires_at]);

  useEffect(() => {
    setPreview(null);
    dry({ database, changes: finalChanges, dry_run: true, grantor: grantor[0], expires_at }, {
      onSuccess: (r) => { setPreview(r.statements); setPlan(r.temporary ?? null); },
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const error = apply.error;
  const needsCascade = /dependent privileges/i.test(error?.message ?? "");
  const shown = (preview ?? []).filter((x) => !x.startsWith("SET LOCAL ROLE")).length;
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
            onClick={() => apply.mutate({ database, changes: finalChanges, grantor: grantor[0], expires_at }, { onSuccess: (r) => onApplied(r.statements.filter((x) => !x.startsWith("SET LOCAL ROLE")).length, r.temporary?.expires_at) })}>
            Apply {preview ? shown : ""} statement{shown === 1 ? "" : "s"}{expires_at ? " (temporary)" : ""}
          </Button>
        </>
      }
    >
      {error && <ErrorNote error={error} />}
      {needsCascade && <Notice tone="warn">Other roles received these privileges from the one you are changing. Open “Advanced” and tick <strong>cascade</strong> to remove those as well.</Notice>}
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

      {canExpire ? (
        <div className={cx("temp-box", temp && "on")}>
          <label className="check-inline"><input type="checkbox" checked={temp} onChange={(e) => setTemp(e.target.checked)} /> <strong>Make this temporary</strong> — revoke it automatically later</label>
          {temp && (
            <>
              <ExpiryPicker value={when} onChange={setWhen} />
              {plan && (
                <>
                  {plan.expiring.length > 0 && <div><div className="detail-title">Will be revoked on {new Date(plan.expires_at).toLocaleString()}</div><ul className="temp-plan">{plan.expiring.map((x) => <li key={x}>{x}</li>)}</ul></div>}
                  {plan.skipped.length > 0 && <Notice tone="info">Already granted permanently, so these stay after expiry: {plan.skipped.join("; ")}.</Notice>}
                  {plan.expiring.length === 0 && <Notice tone="warn">Everything here is already granted, so nothing would expire.</Notice>}
                </>
              )}
            </>
          )}
        </div>
      ) : (
        changes.some((c) => c.action === "grant") && <p className="muted small temp-hint">Temporary access is available when a change only grants privileges on individual objects (not bulk or default privileges).</p>
      )}

      <button className="link-btn adv-toggle" onClick={() => setAdvanced(!advanced)}>{advanced ? "Hide" : "Show"} advanced options</button>
      {advanced && (
        <div className="adv-box">
          <div className="field">
            <span className="field-label">Grant as (grantor)</span>
            <RolePicker single value={grantor} onChange={setGrantor} placeholder="Default: the object owner" />
            <span className="field-hint">Runs the statements as this role (<code>SET LOCAL ROLE</code>), so it is recorded as the one who granted. Only roles that hold the privilege WITH GRANT OPTION (or own the object) can do this; PostgreSQL rejects anything else.</span>
          </div>
          {hasRevoke && (
            <label className="check-inline">
              <input type="checkbox" checked={cascade} onChange={(e) => setCascade(e.target.checked)} /> Cascade: also revoke privileges that role passed on to others
            </label>
          )}
        </div>
      )}
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
function DefaultsTab({ role, database, schemas, catalog, onAdd, readOnly }: { role: string; database: string; schemas: string[]; catalog?: Record<ObjType, string[]>; onAdd: (x: Extra) => void; readOnly?: boolean }) {
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
                    <Button size="sm" variant="ghost" disabled={readOnly || d.object_type === "type"} onClick={() =>
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
      {!readOnly && <BulkPanel mode="default" schema="" schemas={schemas} onAdd={onAdd} catalog={catalog} />}
    </div>
  );
}

/* ------------------------------------------------------------ Columns dialog */
interface ColPend { grant: Set<string>; revoke: Set<string> }

function ColumnsDialog({ role, database, schema, table, readOnly, onClose, onAdd }: { role: string; database: string; schema: string; table: string; readOnly: boolean; onClose: () => void; onAdd: (x: Extra[]) => void }) {
  const q = useColumnPrivileges(role, database, schema, table);
  const [pend, setPend] = useState<Record<string, ColPend>>({});
  const data = q.data;
  const held = (col: NonNullable<typeof data>["columns"][number], p: string) => {
    const pe = pend[col.name];
    return (col.direct.includes(p) && !pe?.revoke.has(p)) || !!pe?.grant.has(p);
  };
  const setCell = (colName: string, direct: boolean, p: string, on: boolean) =>
    setPend((prev) => {
      const e: ColPend = { grant: new Set(prev[colName]?.grant), revoke: new Set(prev[colName]?.revoke) };
      if (on) (direct ? e.revoke.delete(p) : e.grant.add(p));
      else (direct ? e.revoke.add(p) : e.grant.delete(p));
      const next = { ...prev };
      if (e.grant.size || e.revoke.size) next[colName] = e;
      else delete next[colName];
      return next;
    });
  const toggle = (c: NonNullable<typeof data>["columns"][number], p: string) => !readOnly && setCell(c.name, c.direct.includes(p), p, !held(c, p));
  const toggleAll = (p: string) => {
    if (readOnly || !data) return;
    const on = !data.columns.every((c) => held(c, p));
    for (const c of data.columns) setCell(c.name, c.direct.includes(p), p, on);
  };

  const count = Object.values(pend).reduce((n, e) => n + e.grant.size + e.revoke.size, 0);
  const add = () => {
    if (!data) return;
    const out: Extra[] = [];
    for (const action of ["revoke", "grant"] as const) {
      for (const p of data.privileges) {
        const cols = Object.entries(pend).filter(([, e]) => (action === "grant" ? e.grant : e.revoke).has(p)).map(([n]) => n);
        if (!cols.length) continue;
        out.push({
          id: crypto.randomUUID(),
          label: `${action === "grant" ? "Grant" : "Revoke"} ${p} (${cols.join(", ")}) on ${schema}.${table}`,
          change: { action, object_type: "column", schema, name: table, columns: cols, privileges: [p] },
        });
      }
    }
    onAdd(out);
  };

  return (
    <Modal
      wide
      title={`Columns of ${schema}.${table}`}
      subtitle={`Column-level privileges for ${role}. A table-level grant already covers every column.`}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Close</Button>
          {!readOnly && <Button variant="primary" disabled={!count} onClick={add}>Add {count || ""} change{count === 1 ? "" : "s"} to pending</Button>}
        </>
      }
    >
      {q.isLoading ? <Spinner label="Loading columns…" /> : q.error ? <ErrorNote error={q.error} /> : data && (
        <div className="grid-wrap col-grid">
          <table className="grid">
            <thead>
              <tr>
                <th className="obj-col">Column</th>
                {data.privileges.map((p) => <th key={p}><button className="th-btn" onClick={() => toggleAll(p)} title={`Toggle ${p} on every column`}>{p}</button></th>)}
              </tr>
            </thead>
            <tbody>
              {data.columns.map((c) => (
                <tr key={c.name}>
                  <td className="obj-col"><span className="mono">{c.name}</span> <span className="muted small">{c.type}</span></td>
                  {data.privileges.map((p) => {
                    const covered = !!data.table_level[p]?.length;
                    const pe = pend[c.name];
                    const st = pe?.revoke.has(p) ? "revoke" : pe?.grant.has(p) ? "grant" : c.direct.includes(p) ? "direct" : c.inherited[p]?.length ? "inherited" : covered ? "covered" : "none";
                    return (
                      <td key={p}>
                        <button
                          className={cx("pip", st)}
                          disabled={readOnly}
                          onClick={() => toggle(c, p)}
                          title={st === "covered" ? `${p} is granted on the whole table (${data.table_level[p].join(", ")}), so it already applies to this column` : st === "inherited" ? `${p}: inherited from ${c.inherited[p].join(", ")}` : st === "direct" ? `${p}: granted on this column — click to revoke` : st === "grant" ? "Will be granted — click to cancel" : st === "revoke" ? "Will be revoked — click to cancel" : `${p}: not granted — click to grant`}
                        >
                          {st === "direct" || st === "inherited" || st === "covered" ? <Check size={14} strokeWidth={3} /> : st === "grant" ? <Plus size={14} strokeWidth={3} /> : st === "revoke" ? <Minus size={14} strokeWidth={3} /> : null}
                        </button>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && Object.keys(data.table_level).length > 0 && (
        <p className="muted small col-note"><i className="pip mini covered"><Check size={10} strokeWidth={3} /></i> Dotted checks: granted on the whole table ({Object.entries(data.table_level).map(([p, via]) => `${p} via ${via.join(", ")}`).join("; ")}). Column-level grants add nothing on top of those.</p>
      )}
    </Modal>
  );
}
