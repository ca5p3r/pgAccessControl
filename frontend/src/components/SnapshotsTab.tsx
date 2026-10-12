import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Camera, Download, FileCode2, GitCompare, Minus, Pin, PinOff, Plus, Trash2, Pencil } from "lucide-react";
import { downloadUrl, useCan, useDatabases, useDrift, useSnapshotMutations, useSnapshots } from "../api/hooks";
import type { DriftReport, Snapshot } from "../api/types";
import { timeAgo } from "./activity";
import { Badge, Button, ConfirmDialog, Empty, ErrorNote, Field, IconButton, Modal, Notice, Spinner, useToast } from "./ui";

function CreateSnapshot({ onClose, onCreated }: { onClose: () => void; onCreated: (s: Snapshot) => void }) {
  const dbs = useDatabases();
  const { create } = useSnapshotMutations();
  const toast = useToast();
  const [name, setName] = useState(`Snapshot ${new Date().toISOString().slice(0, 10)}`);
  const [note, setNote] = useState("");
  const [database, setDatabase] = useState<string>("");
  const [baseline, setBaseline] = useState(false);
  const db = database || dbs.data?.find((d) => d.connectable)?.name || "";
  return (
    <Modal title="Take a snapshot" subtitle="Saves the roles, memberships and permissions of one database as they are right now." onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={create.isPending} disabled={!name.trim() || !db} onClick={() => create.mutate({ name: name.trim(), note: note || undefined, database: db, baseline }, { onSuccess: (s) => { toast.success("Snapshot saved"); onCreated(s); }, onError: toast.error })}>Save snapshot</Button></>}>
      <div className="form">
        <Field label="Name"><input className="input" value={name} onChange={(e) => setName(e.target.value)} autoFocus /></Field>
        <Field label="Database"><select className="select full" value={db} onChange={(e) => setDatabase(e.target.value)}>{dbs.data?.filter((d) => d.connectable).map((d) => <option key={d.name}>{d.name}</option>)}</select></Field>
        <Field label="Note (optional)"><input className="input" value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. approved after Q3 access review" /></Field>
        <label className="check-inline"><input type="checkbox" checked={baseline} onChange={(e) => setBaseline(e.target.checked)} /> Use as the baseline (the approved state that scheduled checks compare against)</label>
      </div>
    </Modal>
  );
}

/* ----------------------------------------------------------------- drift view */
type Row = { kind: "added" | "removed" | "changed"; text: string; sub?: string };

const SECTION_TITLES = { roles: "Roles & users", memberships: "Role memberships", privileges: "Privileges", defaults: "Default privileges" } as const;

function rowsFor(d: DriftReport, sec: keyof typeof SECTION_TITLES): Row[] {
  const out: Row[] = [];
  const fmt = (v: unknown) => (typeof v === "boolean" ? (v ? "yes" : "no") : v === null || v === "" ? "none" : String(v));
  const changes = (c: Record<string, [unknown, unknown]>) => Object.entries(c).map(([k, [a, b]]) => `${k}: ${fmt(a)} → ${fmt(b)}`).join(", ");
  if (sec === "roles") {
    const s = d.roles;
    s.added.forEach((r) => out.push({ kind: "added", text: r.name, sub: `${r.login ? "user" : "role"}${r.superuser ? " · superuser" : ""} — did not exist in the snapshot` }));
    s.removed.forEach((r) => out.push({ kind: "removed", text: r.name, sub: `${r.login ? "user" : "role"} — existed in the snapshot` }));
    s.changed.forEach((c) => out.push({ kind: "changed", text: c.item.name, sub: changes(c.changes) }));
  } else if (sec === "memberships") {
    const s = d.memberships;
    s.added.forEach((m) => out.push({ kind: "added", text: `${m.member} is a member of ${m.role}`, sub: m.admin_option ? "with admin option" : undefined }));
    s.removed.forEach((m) => out.push({ kind: "removed", text: `${m.member} was a member of ${m.role}`, sub: m.admin_option ? "with admin option" : undefined }));
    s.changed.forEach((c) => out.push({ kind: "changed", text: `${c.item.member} in ${c.item.role}`, sub: changes(c.changes) }));
  } else if (sec === "privileges") {
    const obj = (p: DriftReport["privileges"]["added"][number]) => (p.object_type === "database" || p.object_type === "schema" ? `${p.object_type} ${p.name}` : `${p.object_type} ${p.schema}.${p.name}${p.args ? `(${p.args})` : ""}${p.col ? ` (${p.col})` : ""}`);
    const t = (p: DriftReport["privileges"]["added"][number]) => `${p.privilege} on ${obj(p)} → ${p.grantee}${p.grantable ? " (grant option)" : ""}`;
    d.privileges.added.forEach((p) => out.push({ kind: "added", text: t(p) }));
    d.privileges.removed.forEach((p) => out.push({ kind: "removed", text: t(p) }));
    d.privileges.changed.forEach((c) => out.push({ kind: "changed", text: t(c.item), sub: changes(c.changes) }));
  } else {
    const t = (p: DriftReport["defaults"]["added"][number]) => `${p.privilege} on future ${p.object_type}${p.schema ? ` in ${p.schema}` : ""} created by ${p.for_role} → ${p.grantee}`;
    d.defaults.added.forEach((p) => out.push({ kind: "added", text: t(p) }));
    d.defaults.removed.forEach((p) => out.push({ kind: "removed", text: t(p) }));
    d.defaults.changed.forEach((c) => out.push({ kind: "changed", text: t(c.item), sub: changes(c.changes) }));
  }
  return out;
}

function DriftView({ id, against, onAgainst, onClose }: { id: number; against?: number; onAgainst: (id?: number) => void; onClose: () => void }) {
  const q = useDrift(id, against);
  const snaps = useSnapshots();
  const d = q.data;
  const sameDb = (snaps.data?.items ?? []).filter((s) => s.id !== id && d && s.database === d.snapshot.database);
  const live = !against;

  return (
    <div className="stack">
      <div className="row gap wrap">
        <Button variant="ghost" onClick={onClose}>← All snapshots</Button>
        <span className="grow" />
        <label className="row gap muted">Compare with
          <select className="select" value={against ?? ""} onChange={(e) => onAgainst(e.target.value ? Number(e.target.value) : undefined)}>
            <option value="">the live server</option>
            {sameDb.map((s) => <option key={s.id} value={s.id}>snapshot “{s.name}”</option>)}
          </select>
        </label>
        {live && <Button icon={<FileCode2 size={15} />} onClick={() => (window.location.href = downloadUrl(`/snapshots/${id}/remediation`, {}))} title="SQL that would restore the snapshot state. Never run automatically.">Remediation SQL</Button>}
      </div>
      {q.isLoading ? <Spinner label="Comparing…" /> : q.error ? <ErrorNote error={q.error} retry={() => q.refetch()} /> : d && (
        <>
          <section className="card report-head">
            <div className="card-icon"><GitCompare size={18} /></div>
            <div className="grow">
              <h3>“{d.snapshot.name}” <span className="muted">→</span> {d.compared_with.name}</h3>
              <p className="muted">snapshot of <span className="mono">{d.snapshot.database}</span> taken {timeAgo(d.snapshot.created_at)}</p>
            </div>
            <Badge tone={d.total ? "warn" : "success"}>{d.total ? `${d.total} difference${d.total === 1 ? "" : "s"}` : "No differences"}</Badge>
          </section>
          {d.total === 0 ? <Empty icon={<GitCompare size={28} />} title="In sync">Nothing has changed since this snapshot.</Empty> : (
            <>
              {d.truncated && <Notice tone="warn">Only the first 500 items of each kind are listed here. The remediation SQL contains everything.</Notice>}
              {(Object.keys(SECTION_TITLES) as (keyof typeof SECTION_TITLES)[]).map((sec) => {
                const rows = rowsFor(d, sec);
                const s = d.summary[sec];
                if (!rows.length) return null;
                return (
                  <section key={sec} className="card flush">
                    <div className="card-head pad"><div className="grow"><h3>{SECTION_TITLES[sec]}</h3></div>
                      <span className="badge-row">{s.added > 0 && <Badge tone="success">+{s.added}</Badge>}{s.removed > 0 && <Badge tone="danger">−{s.removed}</Badge>}{s.changed > 0 && <Badge tone="warn">~{s.changed}</Badge>}</span></div>
                    <ul className="drift-list">
                      {rows.map((r, i) => (
                        <li key={i} className={r.kind}>
                          <span className="drift-mark">{r.kind === "added" ? <Plus size={14} /> : r.kind === "removed" ? <Minus size={14} /> : <Pencil size={13} />}</span>
                          <div><div className="mono">{r.text}</div>{r.sub && <div className="muted small">{r.sub}</div>}</div>
                          <span className="drift-label">{r.kind === "added" ? "added since" : r.kind === "removed" ? "removed since" : "changed"}</span>
                        </li>
                      ))}
                    </ul>
                  </section>
                );
              })}
            </>
          )}
        </>
      )}
    </div>
  );
}

/* ----------------------------------------------------------------------- tab */
export function SnapshotsTab() {
  const [sp, setSp] = useSearchParams();
  const { can } = useCan();
  const q = useSnapshots();
  const m = useSnapshotMutations();
  const toast = useToast();
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<Snapshot | null>(null);
  const open = sp.get("snapshot") ? Number(sp.get("snapshot")) : undefined;
  const against = sp.get("against") ? Number(sp.get("against")) : undefined;
  const set = (c: Record<string, string | null>) => setSp((p) => { const n = new URLSearchParams(p); n.set("tab", "snapshots"); for (const [k, v] of Object.entries(c)) (v ? n.set(k, v) : n.delete(k)); return n; }, { replace: true });

  if (open !== undefined) return <DriftView id={open} against={against} onAgainst={(a) => set({ against: a ? String(a) : null })} onClose={() => set({ snapshot: null, against: null })} />;

  const items = q.data?.items ?? [];
  return (
    <div className="stack">
      <div className="row gap wrap">
        <p className="muted grow">A snapshot records who can do what in a database. Compare it with the live server later to see every change, including ones made outside this app, and get SQL to undo them.</p>
        {can("operator") && <Button variant="primary" icon={<Camera size={16} />} onClick={() => setCreating(true)}>Take snapshot</Button>}
      </div>
      {q.data && (q.data.check_interval_minutes > 0
        ? <Notice tone="info">Scheduled check is on: baseline snapshots are compared with the live server every {q.data.check_interval_minutes} minute{q.data.check_interval_minutes === 1 ? "" : "s"}, and new drift is written to the Activity log (and the server log) as <span className="mono">drift.detected</span>.</Notice>
        : <Notice tone="info">Automatic checks are off. Set <span className="mono">DRIFT_CHECK_INTERVAL_MINUTES</span> on the server to compare baseline snapshots on a schedule and get alerted through the Activity log.</Notice>)}
      {q.error ? <ErrorNote error={q.error} retry={() => q.refetch()} /> : q.isLoading ? <Spinner /> : items.length === 0 ? (
        <Empty icon={<Camera size={30} />} title="No snapshots yet">Take one now, ideally right after an access review, and mark it as the baseline.</Empty>
      ) : (
        <div className="card flush">
          <table className="table">
            <thead><tr><th>Snapshot</th><th>Database</th><th>Contents</th><th>Status</th><th /></tr></thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id} className="row-click" onClick={() => set({ snapshot: String(s.id) })}>
                  <td><div className="name">{s.name}{s.baseline && <> <Badge tone="primary">baseline</Badge></>}</div><div className="muted small">{timeAgo(s.created_at)} by {s.created_by}{s.note ? ` · ${s.note}` : ""}</div></td>
                  <td className="mono">{s.database}</td>
                  <td className="muted small">{s.counts.roles} roles · {s.counts.memberships} memberships · {s.counts.privileges} privileges</td>
                  <td>{s.baseline ? (s.last_check ? <Badge tone={s.last_check.total ? "warn" : "success"}>{s.last_check.total ? `${s.last_check.total} drift` : "In sync"} · {timeAgo(s.last_check.at)}</Badge> : <span className="muted small">not checked yet</span>) : <span className="muted">—</span>}</td>
                  <td className="actions wide" onClick={(e) => e.stopPropagation()}>
                    <Button size="sm" variant="ghost" icon={<GitCompare size={14} />} onClick={() => set({ snapshot: String(s.id) })}>Compare</Button>
                    {can("operator") && <IconButton label={s.baseline ? "Unset baseline" : "Use as baseline"} onClick={() => m.baseline.mutate({ id: s.id, baseline: !s.baseline }, { onError: toast.error })}>{s.baseline ? <PinOff size={16} /> : <Pin size={16} />}</IconButton>}
                    <IconButton label="Download JSON" onClick={() => (window.location.href = downloadUrl(`/snapshots/${s.id}/download`, {}))}><Download size={16} /></IconButton>
                    {can("operator") && <IconButton label="Delete" className="danger" onClick={() => setDeleting(s)}><Trash2 size={16} /></IconButton>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {creating && <CreateSnapshot onClose={() => setCreating(false)} onCreated={(s) => { setCreating(false); set({ snapshot: String(s.id) }); }} />}
      {deleting && <ConfirmDialog title={`Delete “${deleting.name}”?`} danger confirmLabel="Delete snapshot" loading={m.remove.isPending} onClose={() => setDeleting(null)}
        onConfirm={() => m.remove.mutate(deleting.id, { onSuccess: () => { toast.success("Snapshot deleted"); setDeleting(null); }, onError: toast.error })}>This only removes the saved copy; it does not change any permissions.</ConfirmDialog>}
    </div>
  );
}

