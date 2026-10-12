import { Link } from "react-router-dom";
import { AlertTriangle, ArrowRight, Crown, Database, History, Hourglass, KeyRound, ShieldAlert, UserRound, Users } from "lucide-react";
import { useAudit, useMeta, useRoles, useStats, useTemporary } from "../api/hooks";
import { Avatar, ErrorNote, Notice, Spinner } from "../components/ui";
import { RoleBadges } from "../components/roles";
import { ActionBadge, timeAgo } from "../components/activity";
import { until } from "../components/expiry";

function Stat({ icon, label, value, tone, to }: { icon: JSX.Element; label: string; value: number | string; tone: string; to?: string }) {
  const body = (
    <>
      <span className={`stat-icon tone-${tone}`}>{icon}</span>
      <div>
        <div className="stat-value">{value}</div>
        <div className="stat-label">{label}</div>
      </div>
    </>
  );
  return to ? <Link to={to} className="stat">{body}</Link> : <div className="stat">{body}</div>;
}

export function Dashboard() {
  const stats = useStats();
  const meta = useMeta();
  const privileged = useRoles({ kind: "all", limit: 200 });
  const recent = useAudit({}, 0, 6);
  const expiring = useTemporary({ status: "pending" });
  const risky = (privileged.data?.items ?? []).filter((r) => r.superuser || r.createrole).slice(0, 6);

  if (stats.isLoading) return <Spinner label="Connecting to PostgreSQL…" />;
  if (stats.error) return <ErrorNote error={stats.error} retry={() => stats.refetch()} />;
  const s = stats.data!;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Overview</h1>
          <p className="muted">
            {meta.data ? `PostgreSQL ${meta.data.server_version} on ${meta.data.host}:${meta.data.port}` : "Connected"}
          </p>
        </div>
      </div>

      <div className="stats">
        <Stat icon={<UserRound size={20} />} label="Users" value={s.users} tone="indigo" to="/users" />
        <Stat icon={<Users size={20} />} label="Roles" value={s.roles} tone="teal" to="/roles" />
        <Stat icon={<Database size={20} />} label="Databases" value={s.databases} tone="amber" to="/permissions" />
        <Stat icon={<Crown size={20} />} label="Superusers" value={s.superusers} tone="rose" />
        {s.expired > 0 && <Stat icon={<AlertTriangle size={20} />} label="Expired users" value={s.expired} tone="rose" to="/users" />}
      </div>

      {meta.data && !meta.data.can_create_roles && (
        <Notice tone="warn">The connected PostgreSQL account (<strong>{meta.data.connected_as}</strong>) cannot create roles. Use a superuser or a CREATEROLE account to manage users.</Notice>
      )}

      {(expiring.data?.items.length ?? 0) > 0 && (
        <section className="card">
          <div className="card-head">
            <div className="card-icon"><Hourglass size={18} /></div>
            <div className="grow"><h3>Temporary access ending soon</h3><p className="muted">{expiring.data!.items.length} scheduled in total.</p></div>
            <Link to="/temporary" className="link-arrow">Manage <ArrowRight size={15} /></Link>
          </div>
          <ul className="list">
            {expiring.data!.items.slice(0, 4).map((t) => (
              <li key={t.id} className="list-row static">
                <Avatar name={t.grantee} size={26} />
                <span className="grow"><strong>{t.grantee}</strong> <span className="muted">· {t.description}</span></span>
                <span className={`expiry ${until(t.expires_at).tone}`}>{until(t.expires_at).text}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {meta.data?.audit_enabled && (
        <section className="card">
          <div className="card-head">
            <div className="card-icon"><History size={18} /></div>
            <div className="grow">
              <h3>Recent activity</h3>
              <p className="muted">The latest changes made through this app.</p>
            </div>
            <Link to="/activity" className="link-arrow">View all <ArrowRight size={15} /></Link>
          </div>
          {!recent.data?.items.length ? <p className="muted">No activity recorded yet.</p> : (
            <ul className="list">
              {recent.data.items.map((e) => (
                <li key={e.id} className="list-row static">
                  <ActionBadge action={e.action} />
                  <span className={`grow ${e.status === "failed" ? "danger-text" : ""}`}>{e.summary}</span>
                  <span className="muted small nowrap">{e.actor} · {timeAgo(e.ts)}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <div className="grid-2 gap-lg">
        <section className="card">
          <div className="card-head">
            <div className="card-icon"><ShieldAlert size={18} /></div>
            <div className="grow">
              <h3>Highly privileged roles</h3>
              <p className="muted">Superusers and roles that can create other roles.</p>
            </div>
          </div>
          {risky.length === 0 ? <p className="muted">None found.</p> : (
            <ul className="list">
              {risky.map((r) => (
                <li key={r.name}>
                  <Link to={`/${r.kind === "user" ? "users" : "roles"}/${encodeURIComponent(r.name)}`} className="list-row">
                    <Avatar name={r.name} kind={r.kind} size={30} />
                    <span className="grow">{r.name}</span>
                    <RoleBadges role={r} max={2} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card">
          <div className="card-head">
            <div className="card-icon"><KeyRound size={18} /></div>
            <div className="grow">
              <h3>How access works in PostgreSQL</h3>
            </div>
          </div>
          <ul className="tips">
            <li><strong>Users and roles are the same thing.</strong> A user is a role that can log in; a role without login acts as a group.</li>
            <li><strong>Privileges are additive.</strong> PostgreSQL has no “deny”; remove access by revoking the grant (and any grant to PUBLIC or an inherited role).</li>
            <li><strong>Objects are checked top-down:</strong> CONNECT on the database, USAGE on the schema, then the table, sequence or function privilege.</li>
          </ul>
          <Link to="/permissions" className="link-arrow">Manage permissions <ArrowRight size={15} /></Link>
        </section>
      </div>
    </div>
  );
}
