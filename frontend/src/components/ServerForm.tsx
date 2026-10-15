import { useMemo, useState } from "react";
import { CheckCircle2, Eye, EyeOff, Lock, ShieldAlert, Unlock, XCircle } from "lucide-react";
import { useServerMutations } from "../api/hooks";
import type { Environment, ServerFormValues, ServerInfo, ServerTestResult, SslMode } from "../api/types";
import { ENV_META } from "./server";
import { Button, Drawer, Field, Notice, Switch, cx, useToast } from "./ui";

const SSL_HELP: Record<SslMode, { label: string; text: string; tone: "good" | "ok" | "bad" }> = {
  "verify-full": { label: "verify-full (recommended)", text: "Encrypted, and the server's certificate and host name are checked. Protects against impersonation.", tone: "good" },
  "verify-ca": { label: "verify-ca", text: "Encrypted, and the certificate must come from a trusted CA (the host name is not checked).", tone: "good" },
  require: { label: "require", text: "Encrypted, but the server's identity is not verified.", tone: "ok" },
  prefer: { label: "prefer", text: "Uses encryption if the server offers it, otherwise sends everything in plain text.", tone: "bad" },
  allow: { label: "allow", text: "Plain text unless the server insists on encryption.", tone: "bad" },
  disable: { label: "disable", text: "Never encrypted. Only acceptable on a trusted local network.", tone: "bad" },
};

const ENV_HELP: Record<Environment, string> = {
  production: "Shows a red banner and asks for confirmation before any change.",
  staging: "Shown with an amber tag so it is not mistaken for production.",
  development: "Shown with a green tag.",
  other: "No special treatment.",
};

const ROLE_HELP = { viewer: "Everyone who can sign in", operator: "Operators and admins only", admin: "Admins only" } as const;

export const emptyForm = (): ServerFormValues => ({
  name: "", description: "", environment: "development", host: "", port: 5432, user: "postgres", password: "", database: "postgres",
  sslmode: "verify-full", ssl_ca: "", connect_timeout: 5, read_only: false, min_role: "viewer", disabled: false,
});

const fromServer = (s: ServerInfo): ServerFormValues => ({
  name: s.name, description: s.description ?? "", environment: s.environment, host: s.host ?? "", port: s.port ?? 5432, user: s.user ?? "",
  password: "", database: s.database ?? "postgres", sslmode: s.sslmode ?? "verify-full", ssl_ca: s.ssl_ca ?? "", connect_timeout: s.connect_timeout ?? 5,
  read_only: s.read_only, min_role: s.min_role, disabled: s.disabled,
});

export function ServerFormDrawer({ server, canStorePassword, onClose, onSaved, onChanged }: { server?: ServerInfo; canStorePassword: boolean; onClose: () => void; onSaved: (s: ServerInfo, created: boolean) => void; onChanged: () => void }) {
  const editing = !!server;
  const [v, setV] = useState<ServerFormValues>(server ? fromServer(server) : emptyForm());
  const [showPw, setShowPw] = useState(false);
  const [clearPw, setClearPw] = useState(false);
  const [result, setResult] = useState<ServerTestResult | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const m = useServerMutations(onChanged);
  const toast = useToast();
  const set = <K extends keyof ServerFormValues>(k: K, val: ServerFormValues[K]) => { setV((p) => ({ ...p, [k]: val })); setResult(null); };

  const initial = useMemo(() => (server ? fromServer(server) : null), [server]);
  const moved = !!initial && (initial.host !== v.host.trim() || initial.port !== v.port || initial.user !== v.user.trim());
  const needsPassword = editing && !!server?.has_password && moved && !v.password && !clearPw;
  const missing = !v.name.trim() || !v.host.trim() || !v.user.trim() || !v.database.trim() || !(v.port >= 1 && v.port <= 65535);
  const wantsCa = v.sslmode === "verify-ca" || v.sslmode === "verify-full" || v.sslmode === "require";
  const help = SSL_HELP[v.sslmode];

  const testBody = () => ({
    host: v.host.trim(), port: v.port, user: v.user.trim(), database: v.database.trim(), sslmode: v.sslmode, environment: v.environment,
    ssl_ca: v.ssl_ca.trim() || null, connect_timeout: v.connect_timeout,
    ...(v.password ? { password: v.password } : editing && !moved && !clearPw ? { server_id: server!.id } : {}),
  });

  const test = () => { setErr(null); m.test.mutate(testBody(), { onSuccess: setResult, onError: (e) => { setResult(null); setErr((e as Error).message); } }); };

  const save = () => {
    setErr(null);
    const common = {
      name: v.name.trim(), description: v.description.trim() || null, environment: v.environment, host: v.host.trim(), port: v.port,
      user: v.user.trim(), database: v.database.trim(), sslmode: v.sslmode, ssl_ca: v.ssl_ca.trim() || null,
      connect_timeout: v.connect_timeout, read_only: v.read_only, min_role: v.min_role,
    };
    const fail = (e: unknown) => setErr((e as Error).message);
    if (editing) {
      m.update.mutate({ id: server!.id, ...common, disabled: v.disabled, ...(v.password ? { password: v.password } : {}), ...(clearPw ? { clear_password: true } : {}) },
        { onSuccess: (s) => { toast.success(`Saved “${s.name}”`); onSaved(s, false); }, onError: fail });
    } else {
      m.create.mutate({ ...common, password: v.password || null, disabled: v.disabled },
        { onSuccess: (s) => { toast.success(`Added “${s.name}”`); onSaved(s, true); }, onError: fail });
    }
  };

  const busy = m.create.isPending || m.update.isPending;
  return (
    <Drawer
      title={editing ? `Edit ${server!.name}` : "Add a server"}
      subtitle={editing ? "Changes apply to everyone using this server." : "Connect another PostgreSQL server to manage from this console."}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button onClick={test} loading={m.test.isPending} disabled={missing || needsPassword}>Test connection</Button>
          <Button variant="primary" onClick={save} loading={busy} disabled={missing || needsPassword}>{editing ? "Save changes" : "Add server"}</Button>
        </>
      }
    >
      <div className="form">
        {err && <Notice tone="danger">{err}</Notice>}

        <div className="form-section first">Identity</div>
        <Field label="Name"><input className="input" value={v.name} onChange={(e) => set("name", e.target.value)} placeholder="e.g. Billing (EU production)" autoFocus={!editing} maxLength={60} /></Field>
        <Field label="Environment" hint={ENV_HELP[v.environment]}>
          <div className="env-pills" role="radiogroup" aria-label="Environment">
            {(Object.keys(ENV_META) as Environment[]).map((e) => (
              <button key={e} type="button" role="radio" aria-checked={v.environment === e} className={cx("env-pill", `env-${e}`, v.environment === e && "on")} onClick={() => set("environment", e)}>{ENV_META[e].label}</button>
            ))}
          </div>
        </Field>
        <Field label="Description (optional)"><input className="input" value={v.description} onChange={(e) => set("description", e.target.value)} maxLength={300} placeholder="What lives here, who owns it" /></Field>

        <div className="form-section">Connection</div>
        <div className="grid-host">
          <Field label="Host"><input className="input mono" value={v.host} onChange={(e) => set("host", e.target.value)} placeholder="db.example.com or 10.0.0.5" spellCheck={false} /></Field>
          <Field label="Port"><input className="input" type="number" min={1} max={65535} value={v.port} onChange={(e) => set("port", Number(e.target.value))} /></Field>
        </div>
        <div className="grid-2">
          <Field label="User" hint="A superuser works best. CREATEROLE is the minimum for managing users."><input className="input mono" value={v.user} onChange={(e) => set("user", e.target.value)} autoComplete="off" spellCheck={false} /></Field>
          <Field label="Maintenance database" hint="Used for server-wide queries."><input className="input mono" value={v.database} onChange={(e) => set("database", e.target.value)} spellCheck={false} /></Field>
        </div>
        <Field label="Password" error={needsPassword ? "Enter the password again: a saved password is only ever sent to the address it was saved for." : null}
          hint={!canStorePassword ? "Saving passwords is disabled until ENCRYPTION_KEY is set on the server. The connection will only work if no password is needed." : editing && server?.has_password ? (clearPw ? "The saved password will be removed." : "A password is saved (encrypted). Leave empty to keep it.") : "Stored encrypted (AES-256-GCM) and never shown again."}>
          <div className="input-group">
            <input className="input mono" type={showPw ? "text" : "password"} value={v.password} disabled={clearPw || !canStorePassword} onChange={(e) => { set("password", e.target.value); }} autoComplete="new-password" placeholder={editing && server?.has_password ? "•••••••• saved" : ""} />
            <button type="button" className="input-addon" onClick={() => setShowPw((s) => !s)} aria-label={showPw ? "Hide password" : "Show password"}>{showPw ? <EyeOff size={16} /> : <Eye size={16} />}</button>
          </div>
          {editing && server?.has_password && (
            <label className="check-inline"><input type="checkbox" checked={clearPw} onChange={(e) => { setClearPw(e.target.checked); setResult(null); }} /> Remove the saved password</label>
          )}
        </Field>

        <div className="form-section">Security</div>
        <Field label="SSL mode">
          <select className="select full" value={v.sslmode} onChange={(e) => set("sslmode", e.target.value as SslMode)}>
            {(Object.keys(SSL_HELP) as SslMode[]).map((k) => <option key={k} value={k}>{SSL_HELP[k].label}</option>)}
          </select>
          <div className={cx("ssl-help", help.tone)}>{help.tone === "bad" ? <Unlock size={14} /> : <Lock size={14} />} {help.text}</div>
        </Field>
        {wantsCa && (
          <Field label="CA certificate (optional)" hint="Paste the PEM text of the CA that signed the server's certificate. Public certificate only: never a private key.">
            <textarea className="input mono ta" rows={5} value={v.ssl_ca} onChange={(e) => set("ssl_ca", e.target.value)} placeholder={"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----"} spellCheck={false} />
          </Field>
        )}
        <Field label="Connection timeout (seconds)"><input className="input" type="number" min={1} max={30} value={v.connect_timeout} onChange={(e) => set("connect_timeout", Number(e.target.value))} /></Field>

        <div className="form-section">Access in this console</div>
        <Switch label="Read-only" hint="Nobody can change anything on this server through the console, whatever their role. Good for production overview." checked={v.read_only} onChange={(x) => set("read_only", x)} />
        <Field label="Visible to">
          <select className="select full" value={v.min_role} onChange={(e) => set("min_role", e.target.value as ServerFormValues["min_role"])}>
            {(Object.keys(ROLE_HELP) as (keyof typeof ROLE_HELP)[]).map((r) => <option key={r} value={r}>{ROLE_HELP[r]}</option>)}
          </select>
          <span className="field-hint">People who may not see a server cannot tell it exists, and its activity history is hidden from them too.</span>
        </Field>
        {editing && <Switch label="Disabled" hint="Hides the server and stops using it (scheduled jobs for it pause). Nothing is deleted." checked={v.disabled} onChange={(x) => set("disabled", x)} />}

        {result && (
          <div className={cx("test-result", result.ok ? "ok" : "bad")} role="status">
            {result.ok ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
            <div>
              <strong>{result.ok ? `Connected in ${result.latency_ms} ms` : "Could not connect"}</strong>
              {result.ok ? (
                <div className="muted">PostgreSQL {result.server_version} · signed in as {result.connected_as}{result.is_superuser ? " (superuser)" : result.can_create_roles ? " (can create roles)" : ""} · {result.ssl ? "encrypted" : "not encrypted"}</div>
              ) : (
                <div className="muted">{result.error}{result.hint && <><br />{result.hint}</>}</div>
              )}
              {result.warnings.length > 0 && <ul className="test-warnings">{result.warnings.map((w) => <li key={w}><ShieldAlert size={13} /> {w}</li>)}</ul>}
            </div>
          </div>
        )}
      </div>
    </Drawer>
  );
}
