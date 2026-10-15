import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowRightLeft, Lock, Pencil, Plus, RefreshCw, Server, ShieldAlert, ShieldCheck, Trash2, Zap } from "lucide-react";
import { useIsAdmin, useServerMutations, useServerUsage } from "../api/hooks";
import type { ServerInfo, ServerStatus } from "../api/types";
import { ServerFormDrawer } from "../components/ServerForm";
import { EnvBadge, ServerFlags, StatusDot, useServerContext } from "../components/server";
import { Badge, Button, Empty, Field, Modal, Notice, Spinner, cx, useToast } from "../components/ui";

const ROLE_LABEL = { viewer: "", operator: "operators+", admin: "admins only" } as const;

function HealthLine({ s, st, loading }: { s: ServerInfo; st?: ServerStatus; loading: boolean }) {
  if (s.disabled) return <span className="muted">Disabled: not used.</span>;
  if (!st) return <span className="muted">{loading ? "Checking…" : "Not checked yet"}</span>;
  if (!st.ok) return <span className="danger-text small">Unreachable{st.error ? `: ${st.error}` : ""}{st.hint ? ` — ${st.hint}` : ""}</span>;
  return (
    <span className="muted small">
      PostgreSQL {st.server_version} · {st.latency_ms} ms{st.is_superuser ? " · superuser" : st.can_create_roles === false ? " · cannot create roles" : ""}{st.ssl === false ? " · not encrypted" : st.ssl ? " · encrypted" : ""}
    </span>
  );
}

function ServerCard({ s, current, st, loading, onUse, onEdit, onRemove, canManage }: { s: ServerInfo; current: boolean; st?: ServerStatus; loading: boolean; onUse: () => void; onEdit: () => void; onRemove: () => void; canManage: boolean }) {
  const secure = s.sslmode ? s.encrypted_connection : undefined;
  return (
    <article className={cx("srv-card", `env-border-${s.environment}`, current && "current", s.disabled && "is-disabled")}>
      <header>
        <StatusDot status={st} loading={loading} />
        <h3>{s.name}</h3>
        {current && <Badge tone="primary">current</Badge>}
        <span className="grow" />
        <ServerFlags s={s} />
        {ROLE_LABEL[s.min_role] && <Badge title="Who can see this server">{ROLE_LABEL[s.min_role]}</Badge>}
      </header>
      {s.description && <p className="muted small">{s.description}</p>}
      <div className="server-meta">
        {s.is_default ? (
          <span className="muted">Configured with environment variables (<span className="mono">PG_*</span>) — edit them in the server settings</span>
        ) : (
          <>
            <span className="mono">{s.host}:{s.port}</span><span className="dotsep">·</span><span className="mono">{s.database}</span><span className="dotsep">·</span><span className="mono">{s.user}</span>
            {s.has_password === false && <Badge tone="warn" title="No password is saved for this server">no password</Badge>}
          </>
        )}
      </div>
      {secure !== undefined && (
        <div className={cx("server-sec", secure ? "good" : "bad")}>{secure ? <ShieldCheck size={13} /> : <ShieldAlert size={13} />} {s.sslmode}{secure ? "" : " — not guaranteed to be encrypted"}</div>
      )}
      <div className="server-health"><HealthLine s={s} st={st} loading={loading} /></div>
      <footer>
        {!current && !s.disabled && <Button size="sm" icon={<ArrowRightLeft size={14} />} onClick={onUse}>Use this server</Button>}
        {canManage && !s.is_default && <Button size="sm" variant="ghost" icon={<Pencil size={14} />} onClick={onEdit}>Edit</Button>}
        {canManage && !s.is_default && <Button size="sm" variant="ghost" className="danger-ghost" icon={<Trash2 size={14} />} onClick={onRemove}>Remove</Button>}
      </footer>
    </article>
  );
}

function RemoveDialog({ server, onClose, onDone }: { server: ServerInfo; onClose: () => void; onDone: () => void }) {
  const usage = useServerUsage(server.id);
  const m = useServerMutations(onDone);
  const toast = useToast();
  const [typed, setTyped] = useState("");
  const has = !!usage.data && (usage.data.pending_schedules > 0 || usage.data.snapshots > 0);
  return (
    <Modal title={`Remove “${server.name}”?`} onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="danger" loading={m.remove.isPending} disabled={typed !== server.name || usage.isLoading}
          onClick={() => m.remove.mutate(server.id, { onSuccess: () => { toast.success(`Removed ${server.name}`); onClose(); }, onError: toast.error })}>Remove server</Button></>}>
      <div className="stack-sm">
        <p>The console stops managing this server. <strong>Nothing is changed on the PostgreSQL server itself</strong>: its roles and permissions stay exactly as they are.</p>
        {usage.isLoading ? <Spinner /> : has ? (
          <Notice tone="warn">
            Removed together with it: {usage.data!.pending_schedules > 0 && <><strong>{usage.data!.pending_schedules}</strong> scheduled access expiries (they will <em>not</em> run, so that access stays)</>}
            {usage.data!.pending_schedules > 0 && usage.data!.snapshots > 0 && " and "}
            {usage.data!.snapshots > 0 && <><strong>{usage.data!.snapshots}</strong> permission snapshots</>}. The activity history is kept.
          </Notice>
        ) : <p className="muted">No scheduled expiries or snapshots belong to this server. Its activity history is kept.</p>}
        <Field label={`Type “${server.name}” to confirm`}><input className="input" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" /></Field>
      </div>
    </Modal>
  );
}

export function ServersPage() {
  const isAdmin = useIsAdmin();
  const { servers, response, current, setCurrent, status, statusLoading, refresh } = useServerContext();
  const [sp, setSp] = useSearchParams();
  const [editing, setEditing] = useState<ServerInfo | "new" | null>(null);
  const [removing, setRemoving] = useState<ServerInfo | null>(null);
  const [offerSwitch, setOfferSwitch] = useState<ServerInfo | null>(null);

  useEffect(() => { if (sp.get("add") && response.management_enabled) { setEditing("new"); setSp({}, { replace: true }); } }, [sp, response.management_enabled, setSp]);

  if (!isAdmin) return <div className="page"><Empty icon={<Server size={30} />} title="Admins only">Only administrators can manage servers. You can switch between the servers you may use from the menu at the top left.</Empty></div>;
  const canManage = response.management_enabled;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Servers</h1>
          <p className="muted">The PostgreSQL servers this console manages. Each has its own users, permissions, activity, temporary access and snapshots.</p>
        </div>
        <div className="row gap">
          <Button icon={<RefreshCw size={15} />} onClick={refresh} title="Check every server again">Recheck</Button>
          {canManage && <Button variant="primary" icon={<Plus size={16} />} disabled={servers.length - 1 >= response.max} onClick={() => setEditing("new")}>Add server</Button>}
        </div>
      </div>

      {!response.management_enabled && <Notice tone="info">Adding and changing servers is turned off on this console (<span className="mono">SERVER_MANAGEMENT_ENABLED=false</span>).</Notice>}
      {response.management_enabled && !response.encryption.ready && (
        <Notice tone="warn"><strong>Passwords cannot be saved yet.</strong> Set <span className="mono">ENCRYPTION_KEY</span> (a long random string) in the server settings. Until then servers can only be added if they need no password.</Notice>
      )}
      {response.management_enabled && response.encryption.fallback_to_secret_key && (
        <Notice tone="info">Saved passwords are encrypted with a key derived from <span className="mono">SECRET_KEY</span>. Set a dedicated <span className="mono">ENCRYPTION_KEY</span> so changing the session secret never locks you out of them.</Notice>
      )}
      {response.allowlist_active && <Notice tone="info">Only hosts on the allowed list (<span className="mono">SERVER_HOST_ALLOWLIST</span>) can be added.</Notice>}

      <div className="server-grid">
        {servers.map((s) => (
          <ServerCard key={s.id} s={s} current={s.id === current.id} st={status[s.id]} loading={statusLoading} canManage={canManage}
            onUse={() => setCurrent(s.id)} onEdit={() => setEditing(s)} onRemove={() => setRemoving(s)} />
        ))}
      </div>
      <p className="muted small"><Zap size={13} style={{ verticalAlign: "-2px" }} /> Health is checked every 30 seconds. <Lock size={13} style={{ verticalAlign: "-2px" }} /> Passwords are write-only: they are never shown again, not even to admins.</p>

      {editing && (
        <ServerFormDrawer server={editing === "new" ? undefined : editing} canStorePassword={response.encryption.ready} onClose={() => setEditing(null)} onChanged={refresh}
          onSaved={(s, created) => { setEditing(null); if (created) setOfferSwitch(s); }} />
      )}
      {removing && <RemoveDialog server={removing} onClose={() => setRemoving(null)} onDone={() => { refresh(); if (removing.id === current.id) setCurrent("default"); }} />}
      {offerSwitch && (
        <Modal title="Server added" onClose={() => setOfferSwitch(null)}
          footer={<><Button variant="ghost" onClick={() => setOfferSwitch(null)}>Stay here</Button><Button variant="primary" icon={<ArrowRightLeft size={15} />} onClick={() => { setCurrent(offerSwitch.id); setOfferSwitch(null); }}>Switch to {offerSwitch.name}</Button></>}>
          <p><EnvBadge env={offerSwitch.environment} compact /> <strong>{offerSwitch.name}</strong> is ready. Switch to it now?</p>
        </Modal>
      )}
    </div>
  );
}

