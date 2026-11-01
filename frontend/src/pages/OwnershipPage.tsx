import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowRightLeft, Check, Copy, Crown, Database, FolderTree, Hash, Puzzle, Shapes, SquareFunction, Table2, X } from "lucide-react";
import { useCan, useChangeOwner, useDatabaseChoice, useOwnedObjects, useOwnerSummary, useReassignOwner } from "../api/hooks";
import type { OwnedObject, OwnedType, OwnerChangeResult, OwnerFilterBody, ReassignResult } from "../api/types";
import { Avatar, Badge, Button, Empty, ErrorNote, Modal, Notice, Pagination, SearchInput, Spinner, Tabs, cx, hueFor, useDebounced, useToast } from "../components/ui";
import { ProductionConfirm } from "../components/ProductionConfirm";
import { RoleChoice } from "../components/RoleChoice";
import { RolePicker } from "../components/roles";

const PAGE = 50;
const SHOWN_STATEMENTS = 200;

const TYPES: { id: OwnedType; label: string; icon: JSX.Element }[] = [
  { id: "table", label: "Tables & views", icon: <Table2 size={15} /> },
  { id: "sequence", label: "Sequences", icon: <Hash size={15} /> },
  { id: "function", label: "Functions", icon: <SquareFunction size={15} /> },
  { id: "type", label: "Types", icon: <Shapes size={15} /> },
  { id: "schema", label: "Schemas", icon: <FolderTree size={15} /> },
  { id: "database", label: "Databases", icon: <Database size={15} /> },
];
const TOP_OWNERS = 8;
const PLAIN_KINDS = ["table", "sequence", "function", "schema", "database"];

const label = (o: Pick<OwnedObject, "type" | "schema" | "name" | "args">) =>
  o.type === "database" || o.type === "schema" ? o.name : `${o.schema}.${o.name}${o.args ? `(${o.args})` : ""}`;

const plural = (n: number, word: string) => `${n.toLocaleString()} ${word}${n === 1 ? "" : "s"}`;

/* ------------------------------------------------------------------ SQL box */
function Sql({ lines, total }: { lines: string[]; total?: number }) {
  const [copied, setCopied] = useState(false);
  const shown = lines.slice(0, SHOWN_STATEMENTS);
  return (
    <div className="code-wrap">
      <button className="code-copy" onClick={async () => { await navigator.clipboard?.writeText(lines.join("\n")); setCopied(true); setTimeout(() => setCopied(false), 1500); }}>
        {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "Copied" : "Copy"}
      </button>
      <pre className="code">{shown.join("\n")}{lines.length > shown.length ? `\n-- … and ${(total ?? lines.length) - shown.length} more (Copy includes all)` : ""}</pre>
    </div>
  );
}

/* ------------------------------------------------------- change-owner dialog */
type Selection = { items: { object_type: OwnedType; oid: number }[] } | { filter: OwnerFilterBody };

function ChangeOwnerDialog({ database, count, selection, onClose, onDone }: { database: string; count: number; selection: Selection; onClose: () => void; onDone: (r: OwnerChangeResult, newOwner: string) => void }) {
  const change = useChangeOwner();
  const [owner, setOwner] = useState<string[]>([]);
  const [preview, setPreview] = useState<OwnerChangeResult | null>(null);
  const [prodOk, setProdOk] = useState(true);
  const { mutate: dry } = change;
  const newOwner = owner[0];

  useEffect(() => {
    setPreview(null);
    if (!newOwner) return;
    dry({ database, new_owner: newOwner, ...selection, dry_run: true }, { onSuccess: setPreview });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [newOwner]);

  const froms = useMemo(() => [...new Set(preview?.objects.map((o) => o.from))], [preview]);
  const error = change.error;
  return (
    <Modal
      wide
      title="Change owner"
      subtitle={`${plural(count, "object")} in database “${database}”. All of them change in one transaction: if one fails, nothing is changed.`}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!preview || preview.changed === 0 || !prodOk} loading={change.isPending && !change.variables?.dry_run}
            onClick={() => change.mutate({ database, new_owner: newOwner, ...selection }, { onSuccess: (r) => onDone(r, newOwner) })}>
            {preview ? `Make ${newOwner} owner of ${plural(preview.changed, "object")}` : "Change owner"}
          </Button>
        </>
      }
    >
      <ProductionConfirm onChange={setProdOk} />
      <div className="field">
        <span className="field-label">New owner</span>
        <RoleChoice value={newOwner} onChange={(v) => setOwner(v ? [v] : [])} />
        <span className="field-hint">The owner can always grant, alter and drop these objects. The previous owner loses those rights; permissions granted to other roles stay.</span>
      </div>
      {error && <ErrorNote error={error} />}
      {newOwner && !preview && !error && <Spinner label="Generating SQL…" />}
      {preview && (
        <>
          {froms.length > 0 && <p className="muted">Ownership moves from <strong>{froms.join(", ")}</strong> to <strong>{newOwner}</strong>.</p>}
          {preview.changed === 0 && <Notice tone="info">Nothing to change: every selected object is skipped (see below).</Notice>}
          {preview.statements.length > 0 && <Sql lines={preview.statements} />}
          {preview.skipped.length > 0 && (
            <Notice tone="info">
              <div><strong>{plural(preview.skipped.length, "object")} will be left as they are:</strong></div>
              <ul className="temp-plan">
                {preview.skipped.slice(0, 8).map((s) => <li key={s.object}><span className="mono">{s.object}</span> — {s.reason}</li>)}
                {preview.skipped.length > 8 && <li>… and {preview.skipped.length - 8} more</li>}
              </ul>
            </Notice>
          )}
        </>
      )}
    </Modal>
  );
}

/* ------------------------------------------------------------ transfer dialog */
function TransferDialog({ database, initialFrom, onClose, onDone }: { database: string; initialFrom?: string; onClose: () => void; onDone: (r: ReassignResult, from: string, to: string) => void }) {
  const reassign = useReassignOwner();
  const [from, setFrom] = useState<string[]>(initialFrom ? [initialFrom] : []);
  const [to, setTo] = useState<string[]>([]);
  const [scope, setScope] = useState<"all" | "db">("all");
  const [preview, setPreview] = useState<ReassignResult | null>(null);
  const [prodOk, setProdOk] = useState(true);
  const { mutate: dry } = reassign;
  const body = { from_role: from[0], to_role: to[0], database: scope === "db" ? database : undefined };
  const key = JSON.stringify(body);

  useEffect(() => {
    setPreview(null);
    if (!body.from_role || !body.to_role) return;
    dry({ ...body, dry_run: true }, { onSuccess: setPreview });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  const places = Object.entries(preview?.places ?? {});
  const total = places.reduce((n, [, c]) => n + c, 0);
  return (
    <Modal
      wide
      title="Transfer everything a role owns"
      subtitle="Hands every object one role owns to another role (REASSIGN OWNED). Typical use: before deleting a user, or when a team takes over a project."
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!preview || !prodOk || preview.statements.length === 0} loading={reassign.isPending && !reassign.variables?.dry_run}
            onClick={() => reassign.mutate(body, { onSuccess: (r) => onDone(r, body.from_role, body.to_role) })}>
            Hand over everything
          </Button>
        </>
      }
    >
      <ProductionConfirm onChange={setProdOk} />
      <div className="grid-2">
        <div className="field"><span className="field-label">From</span><RoleChoice value={from[0]} onChange={(v) => setFrom(v ? [v] : [])} exclude={to} placeholder="Search the current owner…" /></div>
        <div className="field"><span className="field-label">To</span><RoleChoice value={to[0]} onChange={(v) => setTo(v ? [v] : [])} exclude={from} placeholder="Search the new owner…" /></div>
      </div>
      <div className="seg" role="group" aria-label="Where">
        <button className={cx(scope === "all" && "on")} onClick={() => setScope("all")}>All databases</button>
        <button className={cx(scope === "db" && "on")} onClick={() => setScope("db")}>Only “{database}”</button>
      </div>
      <Notice tone="warn">
        Databases and tablespaces the role owns are handed over as well, whichever option you pick. The change runs one database at a time, so if a later database fails, the earlier ones stay handed over.
      </Notice>
      {reassign.error && <ErrorNote error={reassign.error} />}
      {from[0] && to[0] && !preview && !reassign.error && <Spinner label="Looking up what it owns…" />}
      {preview && (
        <>
          {total === 0
            ? <Notice tone="info"><strong>{from[0]}</strong> does not own anything{scope === "db" ? ` in ${database}` : ""}, so there is nothing to hand over.</Notice>
            : <p className="muted">{places.map(([db, n]) => `${db}: ${plural(n, "object")}`).join(" · ")}</p>}
          {preview.statements.length > 0 && <Sql lines={preview.statements} />}
        </>
      )}
    </Modal>
  );
}

/* ----------------------------------------------------------------------- page */
function ObjectName({ o }: { o: OwnedObject }) {
  const scoped = o.type !== "database" && o.type !== "schema";
  return (
    <span className="own-name" title={label(o)}>
      {scoped && <span className="own-schema">{o.schema}.</span>}
      <strong>{o.name}</strong>
      {o.args && <span className="own-schema">({o.args})</span>}
    </span>
  );
}

/** Who owns how much of this type: a proportional bar plus the biggest owners as one-click filters. */
function OwnerOverview({ owners, type, selected, onPick }: { owners: { owner: string; count: number }[]; type: OwnedType; selected?: string; onPick: (o: string | null) => void }) {
  const total = owners.reduce((n, o) => n + o.count, 0);
  if (total === 0) return null;
  const top = owners.slice(0, TOP_OWNERS);
  const rest = owners.slice(TOP_OWNERS);
  const restCount = rest.reduce((n, o) => n + o.count, 0);
  return (
    <section className="card own-overview" aria-label="Owners">
      <div className="own-bar" role="img" aria-label={`Share of ${type} objects per owner`}>
        {top.map((o) => <span key={o.owner} style={{ flex: o.count, background: `hsl(${hueFor(o.owner)} 60% 52%)`, opacity: selected && selected !== o.owner ? 0.25 : 1 }} title={`${o.owner}: ${o.count.toLocaleString()}`} />)}
        {restCount > 0 && <span style={{ flex: restCount, background: "var(--border-strong)", opacity: selected ? 0.25 : 1 }} title={`${rest.length} other owners: ${restCount.toLocaleString()}`} />}
      </div>
      <div className="own-legend">
        {top.map((o) => (
          <button key={o.owner} className={cx("own-chip", selected === o.owner && "on")} onClick={() => onPick(selected === o.owner ? null : o.owner)} title={`Show only what ${o.owner} owns`}>
            <i style={{ background: `hsl(${hueFor(o.owner)} 60% 52%)` }} />
            <span className="own-chip-name">{o.owner}</span>
            <b>{o.count.toLocaleString()}</b>
          </button>
        ))}
        {rest.length > 0 && <span className="own-more muted">+ {rest.length} more owner{rest.length === 1 ? "" : "s"} ({restCount.toLocaleString()}). Use the owner filter below.</span>}
      </div>
    </section>
  );
}

export function OwnershipPage() {
  const [sp, setSp] = useSearchParams();
  const toast = useToast();
  const { can } = useCan();
  const canChange = can("operator");
  const canTransfer = can("admin");
  const { dbs, database: defaultDb, setDatabase } = useDatabaseChoice();
  const database = sp.get("db") ?? defaultDb;
  const type = (TYPES.find((t) => t.id === sp.get("type"))?.id ?? "table") as OwnedType;
  const owner = sp.get("owner") ?? undefined;
  const [q, setQ] = useState("");
  const dq = useDebounced(q, 250);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [allMatching, setAllMatching] = useState(false);
  const [changing, setChanging] = useState(false);
  const [transfer, setTransfer] = useState(false);

  const set = (changes: Record<string, string | null>) =>
    setSp((prev) => { const n = new URLSearchParams(prev); for (const [k, v] of Object.entries(changes)) (v ? n.set(k, v) : n.delete(k)); return n; }, { replace: true });
  useEffect(() => { setPage(0); setSelected(new Set()); setAllMatching(false); }, [database, type, owner, dq]);

  const summary = useOwnerSummary(database);
  const list = useOwnedObjects({ database, type, owner, q: dq || undefined, limit: PAGE, offset: page * PAGE });
  const items = list.data?.items ?? [];
  const total = list.data?.total ?? 0;

  const owners = summary.data?.owners ?? [];
  const countFor = (t: OwnedType) => owners.filter((o) => !owner || o.owner === owner).reduce((n, o) => n + (o.counts[t] ?? 0), 0);
  const ranked = useMemo(
    () => owners.map((o) => ({ owner: o.owner, count: o.counts[type] ?? 0 })).filter((o) => o.count > 0).sort((a, b) => b.count - a.count || a.owner.localeCompare(b.owner)),
    [owners, type],
  );

  const selectable = (o: OwnedObject) => canChange && !o.extension && !o.linked_to;
  const pickable = items.filter(selectable);
  const pageAll = pickable.length > 0 && pickable.every((o) => selected.has(o.oid));
  const toggle = (oid: number) => { setAllMatching(false); setSelected((s) => { const n = new Set(s); n.has(oid) ? n.delete(oid) : n.add(oid); return n; }); };
  const togglePage = () => { setAllMatching(false); setSelected(pageAll ? new Set() : new Set(pickable.map((o) => o.oid))); };
  const clear = () => { setSelected(new Set()); setAllMatching(false); };

  const count = allMatching ? total : selected.size;
  const filter: OwnerFilterBody = { object_type: type, owner, q: dq || undefined };
  const selection: Selection = allMatching ? { filter } : { items: [...selected].map((oid) => ({ object_type: type, oid })) };
  const finished = (r: { applied: boolean }, message: string) => { clear(); setChanging(false); setTransfer(false); if (r.applied) toast.success(message); };
  const current = TYPES.find((t) => t.id === type)!;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Ownership</h1>
          <p className="muted">Owners can always grant, alter and drop their objects, and a role that still owns objects cannot be deleted. Select objects to give them a new owner.</p>
        </div>
        <div className="own-head-actions">
          <label className="own-db"><Database size={15} /><select className="select" value={database ?? ""} onChange={(e) => { setDatabase(e.target.value); set({ db: e.target.value }); }} aria-label="Database">
            {dbs.data?.map((d) => <option key={d.name} value={d.name} disabled={!d.connectable}>{d.name}{d.connectable ? "" : " (no access)"}</option>)}
          </select></label>
          {canTransfer && database && <Button icon={<ArrowRightLeft size={15} />} onClick={() => setTransfer(true)}>Transfer everything…</Button>}
        </div>
      </div>

      <Tabs<OwnedType> value={type} onChange={(t) => set({ type: t === "table" ? null : t })}
        tabs={TYPES.map((t) => ({ id: t.id, label: t.label, icon: t.icon, count: summary.data ? countFor(t.id) : undefined }))} />

      {summary.isLoading ? <Spinner label="Counting owners…" /> : <OwnerOverview owners={ranked} type={type} selected={owner} onPick={(o) => set({ owner: o })} />}

      <div className="toolbar own-toolbar">
        <SearchInput value={q} onChange={setQ} placeholder={type === "database" || type === "schema" ? `Search ${current.label.toLowerCase()}…` : `Search ${current.label.toLowerCase()}, e.g. sales.orders…`} />
        <div className="own-owner-pick"><RolePicker single value={owner ? [owner] : []} onChange={(v) => set({ owner: v[0] ?? null })} placeholder="Any owner" /></div>
        <span className="grow" />
        <span className="muted">{plural(total, "object")}</span>
      </div>

      {type === "database" && <Notice tone="info">Databases belong to the whole server, so this list is the same whichever database is selected above.</Notice>}
      {canChange && pageAll && total > pickable.length && !allMatching && (
        <div className="select-banner">All {pickable.length} on this page are selected. <button className="link-btn" onClick={() => setAllMatching(true)}>Select all {total.toLocaleString()} matching</button></div>
      )}
      {allMatching && <div className="select-banner">All {total.toLocaleString()} matching objects are selected. <button className="link-btn" onClick={clear}>Clear selection</button></div>}

      {list.isLoading ? <Spinner label="Reading the catalog…" /> : list.error ? <ErrorNote error={list.error} retry={() => list.refetch()} /> : items.length === 0 ? (
        <Empty icon={<Crown size={28} />} title="Nothing found">{owner || dq ? "No objects match these filters." : "There are no objects of this type here."}</Empty>
      ) : (
        <div className="card flush">
          <table className="table own-table">
            <colgroup>{canChange && <col className="c-chk" />}<col /><col className="c-owner" /><col className="c-notes" /></colgroup>
            <thead>
              <tr>
                {canChange && <th className="chk"><input type="checkbox" checked={pageAll} onChange={togglePage} disabled={pickable.length === 0} aria-label="Select all on this page" /></th>}
                <th>Object</th><th>Owner</th><th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {items.map((o) => {
                const on = selected.has(o.oid) || (allMatching && selectable(o));
                return (
                  <tr key={`${o.type}${o.oid}`} className={cx(on && "row-pending")}>
                    {canChange && (
                      <td className="chk">
                        <input type="checkbox" checked={on} disabled={!selectable(o) || allMatching} onChange={() => toggle(o.oid)}
                          aria-label={`Select ${label(o)}`}
                          title={o.extension ? `Belongs to extension ${o.extension}` : o.linked_to ? `Follows its table ${o.linked_to}` : undefined} />
                      </td>
                    )}
                    <td><ObjectName o={o} /></td>
                    <td>
                      <button className="owner-link" onClick={() => set({ owner: o.owner })} title={`Show everything owned by ${o.owner}`}>
                        <Avatar name={o.owner} size={22} /><span className="own-owner-name">{o.owner}</span>
                      </button>
                    </td>
                    <td>
                      <span className="badge-row">
                        {!PLAIN_KINDS.includes(o.kind) && <Badge>{o.kind}</Badge>}
                        {o.extension && <Badge tone="info" title="Its owner stays with the extension"><Puzzle size={11} /> {o.extension}</Badge>}
                        {o.linked_to && <Badge tone="info" title={`Owned by a column of ${o.linked_to}: changes with that table`}>follows table</Badge>}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <Pagination page={page} pageSize={PAGE} total={total} onPage={setPage} />
        </div>
      )}

      {count > 0 && canChange && database && (
        <div className="pending-bar">
          <div className="pending-info"><strong>{plural(count, "object")} selected</strong></div>
          <Button variant="ghost" icon={<X size={14} />} onClick={clear}>Clear</Button>
          <Button variant="primary" icon={<Crown size={15} />} onClick={() => setChanging(true)}>Change owner…</Button>
        </div>
      )}

      {changing && database && (
        <ChangeOwnerDialog database={database} count={count} selection={selection} onClose={() => setChanging(false)}
          onDone={(r, who) => finished(r, `${who} now owns ${plural(r.changed, "object")}`)} />
      )}
      {transfer && database && (
        <TransferDialog database={database} initialFrom={owner} onClose={() => setTransfer(false)}
          onDone={(r, from, to) => finished(r, `${to} took over everything ${from} owned`)} />
      )}
    </div>
  );
}
