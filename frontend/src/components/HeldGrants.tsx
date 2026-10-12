import { useEffect, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { Boxes, Database, Globe, KeyRound, Pencil } from "lucide-react";
import { useHoldingsDetail, useHoldingsSummary } from "../api/hooks";
import type { HeldObject, HoldingsDetail, HoldingsSummary, RoleDetail } from "../api/types";
import { Badge, Button, Empty, ErrorNote, Notice, SearchInput, Spinner, cx } from "./ui";

const CLUSTER = "";

/** Group privilege rows by object so "SELECT, UPDATE on orders" is one line. */
function groupPrivileges(rows: HoldingsDetail["privileges"]) {
  const map = new Map<string, { label: string; type: string; owner: string; privs: Map<string, boolean>; grantors: Set<string> }>();
  for (const r of rows) {
    const obj = r.object_type === "database" || r.object_type === "schema" ? r.name : `${r.schema}.${r.name}${r.args ? `(${r.args})` : ""}${r.col ? ` · column ${r.col}` : ""}`;
    const key = `${r.object_type}|${obj}`;
    const g = map.get(key) ?? { label: obj, type: r.object_type, owner: r.owner, privs: new Map(), grantors: new Set() };
    g.privs.set(r.privilege, r.grantable);
    g.grantors.add(r.grantor);
    map.set(key, g);
  }
  return [...map.values()].sort((a, b) => a.type.localeCompare(b.type) || a.label.localeCompare(b.label));
}

function Section({ title, count, hint, children }: { title: string; count?: number; hint?: string; children: ReactNode }) {
  return (
    <section className="card flush held-section">
      <div className="card-head pad">
        <div className="grow"><h3>{title}{count !== undefined && <span className="tab-count">{count}</span>}</h3>{hint && <p className="muted">{hint}</p>}</div>
      </div>
      {children}
    </section>
  );
}

const PrivBadges = ({ privs }: { privs: Map<string, boolean> }) => (
  <span className="badge-row">
    {[...privs.entries()].sort().map(([p, opt]) => (
      <Badge key={p} tone="primary" title={opt ? "with grant option: can pass it on" : undefined}>{p}{opt && <KeyRound size={11} className="opt-key" />}</Badge>
    ))}
  </span>
);

function OwnedList({ items, deleteHint }: { items: HeldObject[]; deleteHint?: boolean }) {
  if (!items.length) return <p className="muted pad-p">Owns nothing here.</p>;
  return (
    <>
      {deleteHint && <div className="pad-p"><Notice tone="warn">Owned objects must be transferred to another role before this role can be deleted (the delete dialog asks for the new owner). They are never dropped.</Notice></div>}
      <table className="table"><thead><tr><th>Type</th><th>Object</th></tr></thead>
        <tbody>{items.map((o, i) => <tr key={i}><td><Badge>{o.kind}</Badge></td><td className="mono">{o.description.replace(/^[a-z -]+? (?=\S)/, "")}</td></tr>)}</tbody></table>
    </>
  );
}

function ClusterPane({ cluster: c }: { cluster: HoldingsSummary["cluster"] }) {
  const grouped = useMemo(() => {
    const m = new Map<string, { kind: string; name: string; privs: Map<string, boolean>; grantors: Set<string> }>();
    for (const p of c.privileges) {
      const g = m.get(`${p.kind}|${p.name}`) ?? { kind: p.kind, name: p.name, privs: new Map(), grantors: new Set() };
      g.privs.set(p.privilege, p.grantable); g.grantors.add(p.grantor); m.set(`${p.kind}|${p.name}`, g);
    }
    return [...m.values()];
  }, [c.privileges]);
  return (
    <div className="stack">
      <Notice tone="info">Databases and tablespaces belong to the whole server, not to a single database, so they are listed here.</Notice>
      <Section title="Owns" count={c.owned.length}><OwnedList items={c.owned} deleteHint={c.owned.length > 0} /></Section>
      <Section title="Privileges held on databases and tablespaces" count={grouped.length}>
        {grouped.length === 0 ? <p className="muted pad-p">None.</p> : (
          <table className="table"><thead><tr><th>Object</th><th>Privileges</th><th>Granted by</th></tr></thead>
            <tbody>{grouped.map((g) => <tr key={g.kind + g.name}><td><Badge>{g.kind}</Badge> <span className="mono">{g.name}</span></td><td><PrivBadges privs={g.privs} /></td><td className="mono muted">{[...g.grantors].join(", ")}</td></tr>)}</tbody></table>
        )}
      </Section>
      {c.granted_to_others.length > 0 && (
        <Section title="Grants this role has given to others" count={c.granted_to_others.length} hint="Removed together with the role.">
          <table className="table"><thead><tr><th>Object</th><th>Privilege</th><th>Given to</th></tr></thead>
            <tbody>{c.granted_to_others.map((g, i) => <tr key={i}><td><Badge>{g.kind}</Badge> <span className="mono">{g.name}</span></td><td>{g.privilege}</td><td className="mono">{g.grantee}</td></tr>)}</tbody></table>
        </Section>
      )}
    </div>
  );
}

function DatabasePane({ role, database }: { role: string; database: string }) {
  const q = useHoldingsDetail(role, database);
  const [filter, setFilter] = useState("");
  const d = q.data;
  const privs = useMemo(() => groupPrivileges(d?.privileges ?? []), [d]);
  const shown = privs.filter((p) => p.label.toLowerCase().includes(filter.toLowerCase()));
  if (q.isLoading) return <Spinner label={`Reading ${database}…`} />;
  if (q.error) return <ErrorNote error={q.error} retry={() => q.refetch()} />;
  if (!d) return null;
  const nothing = !d.owned.length && !privs.length && !d.default_privileges.length && !d.granted_to_others.length && !d.policies.length;
  if (nothing) return <Empty icon={<Boxes size={28} />} title="Holds nothing in this database">No owned objects, privileges or default privileges.</Empty>;

  return (
    <div className="stack">
      <Section title="Owns" count={d.owned.length}><OwnedList items={d.owned} deleteHint={d.owned.length > 0} /></Section>

      <Section title="Privileges held" count={privs.length} hint="Granted directly to this role (privileges it only inherits from other roles are on the Permissions tab).">
        {privs.length === 0 ? <p className="muted pad-p">None.</p> : (
          <>
            {privs.length > 8 && <div className="pad-p"><SearchInput value={filter} onChange={setFilter} placeholder="Filter objects…" /></div>}
            <table className="table">
              <thead><tr><th>Object</th><th>Privileges</th><th>Granted by</th></tr></thead>
              <tbody>
                {shown.map((p) => (
                  <tr key={p.type + p.label}>
                    <td><Badge>{p.type}</Badge> <span className="mono">{p.label}</span></td>
                    <td><PrivBadges privs={p.privs} /></td>
                    <td className="mono muted">{[...p.grantors].join(", ")}</td>
                  </tr>
                ))}
                {shown.length === 0 && <tr><td colSpan={3} className="muted">No objects match.</td></tr>}
              </tbody>
            </table>
          </>
        )}
      </Section>

      {d.default_privileges.length > 0 && (
        <Section title="Default privileges" count={d.default_privileges.length} hint="Applied automatically to objects created later.">
          <table className="table"><thead><tr><th>On future</th><th>In schema</th><th>Created by</th><th>Privilege</th></tr></thead>
            <tbody>{d.default_privileges.map((x, i) => <tr key={i}><td className="cap">{x.object_type}</td><td>{x.schema ?? <span className="muted">all schemas</span>}</td><td className="mono">{x.for_role}</td><td><Badge tone="primary">{x.privilege}</Badge></td></tr>)}</tbody></table>
        </Section>
      )}

      {d.granted_to_others.length > 0 && (
        <Section title="Grants this role has given to others" count={d.granted_to_others.length} hint="Removed together with the role.">
          <table className="table"><thead><tr><th>Object</th><th>Privilege</th><th>Given to</th></tr></thead>
            <tbody>{d.granted_to_others.map((g, i) => <tr key={i}><td><Badge>{g.object_type}</Badge> <span className="mono">{g.object_type === "schema" || g.object_type === "database" ? g.name : `${g.schema}.${g.name}${g.col ? ` · ${g.col}` : ""}`}</span></td><td>{g.privilege}</td><td className="mono">{g.grantee}</td></tr>)}</tbody></table>
        </Section>
      )}

      {d.policies.length > 0 && (
        <Section title="Row-level security policies" count={d.policies.length} hint="Policies that name this role.">
          <table className="table"><tbody>{d.policies.map((o, i) => <tr key={i}><td className="mono">{o.description}</td></tr>)}</tbody></table>
        </Section>
      )}
    </div>
  );
}

export function HeldGrants({ role }: { role: RoleDetail }) {
  const summary = useHoldingsSummary(role.name);
  const [, setParams] = useSearchParams();
  const [sel, setSel] = useState<string | null>(null);
  const data = summary.data;

  // Start on the first place that actually holds something.
  useEffect(() => {
    if (!data || sel !== null) return;
    const busy = data.databases.find((d) => d.owned_objects + d.privileges > 0);
    const clusterBusy = data.cluster.owned.length + data.cluster.privileges.length + data.cluster.granted_to_others.length > 0;
    setSel(busy ? busy.database : clusterBusy ? CLUSTER : data.databases[0]?.database ?? CLUSTER);
  }, [data, sel]);

  if (summary.isLoading) return <Spinner label="Looking up what this role holds…" />;
  if (summary.error) return <ErrorNote error={summary.error} retry={() => summary.refetch()} />;
  if (!data) return null;

  const totalOwned = data.databases.reduce((n, d) => n + d.owned_objects, 0) + data.cluster.owned.length;
  const totalGrants = data.databases.reduce((n, d) => n + d.privileges, 0) + data.cluster.privileges.length;
  const clusterCount = data.cluster.owned.length + data.cluster.privileges.length + data.cluster.granted_to_others.length;

  return (
    <div className="stack">
      <div className="held-summary">
        <div className="stat"><span className="stat-icon tone-amber"><Boxes size={20} /></span><div><div className="stat-value">{totalOwned}</div><div className="stat-label">owned objects</div></div></div>
        <div className="stat"><span className="stat-icon tone-indigo"><KeyRound size={20} /></span><div><div className="stat-value">{totalGrants}</div><div className="stat-label" title="Objects whose permissions mention this role, plus its default privileges">grant entries</div></div></div>
        <div className="stat"><span className="stat-icon tone-teal"><Database size={20} /></span><div><div className="stat-value">{data.databases.filter((d) => d.owned_objects + d.privileges > 0).length + (clusterCount ? 1 : 0)}</div><div className="stat-label">places involved</div></div></div>
        <div className="grow" />
        <Button icon={<Pencil size={15} />} onClick={() => setParams({ tab: "permissions" }, { replace: true })}>Edit in Permissions</Button>
      </div>

      {data.is_superuser && <Notice tone="warn"><strong>{role.name} is a superuser</strong>: it bypasses permission checks, so the grants below are not what gives it access.</Notice>}
      <p className="muted">Everything this {role.kind} holds <strong>directly</strong>. These are the grants removed, and the objects that must be handed over, when the role is deleted.</p>

      {data.databases.length === 0 && clusterCount === 0 ? (
        <Empty icon={<Boxes size={30} />} title="Holds nothing">This {role.kind} owns no objects and has no direct grants, so it can be deleted without side effects.</Empty>
      ) : (
        <div className="held-layout">
          <nav className="held-nav" aria-label="Databases">
            <button className={cx("held-item", sel === CLUSTER && "on")} onClick={() => setSel(CLUSTER)}>
              <Globe size={15} /><span className="grow">Server-wide</span><span className="held-count">{clusterCount || ""}</span>
            </button>
            {data.databases.map((d) => (
              <button key={d.database} className={cx("held-item", sel === d.database && "on")} onClick={() => setSel(d.database)} title={`${d.owned_objects} owned, ${d.privileges} with grants`}>
                <Database size={15} /><span className="grow mono">{d.database}</span>
                <span className="held-count">{d.owned_objects + d.privileges || ""}</span>
              </button>
            ))}
          </nav>
          <div className="held-pane">
            {sel === null ? <Spinner /> : sel === CLUSTER ? <ClusterPane cluster={data.cluster} /> : <DatabasePane key={sel} role={role.name} database={sel} />}
          </div>
        </div>
      )}
      <p className="muted small">Databases where the role holds nothing are not listed. The number next to a database counts the objects it owns plus the objects whose permissions mention it.</p>
    </div>
  );
}
