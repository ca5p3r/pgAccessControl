import { Link } from "react-router-dom";
import { AlertTriangle, ArrowRight, Crown, Database, KeyRound, ShieldAlert, UserRound, Users } from "lucide-react";
import { useMeta, useRoles, useStats } from "../api/hooks";
import { Avatar, ErrorNote, Notice, Spinner } from "../components/ui";
import { RoleBadges } from "../components/roles";

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
