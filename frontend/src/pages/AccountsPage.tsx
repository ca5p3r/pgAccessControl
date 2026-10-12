import { useState } from "react";
import { Ban, CheckCircle2, Dices, KeyRound, Plus, ShieldCheck, Trash2, UserCog } from "lucide-react";
import { useAppUserMutations, useAppUsers, useAuth, useCan } from "../api/hooks";
import type { AppUser } from "../api/types";
import { timeAgo } from "../components/activity";
import { Avatar, Badge, Button, ConfirmDialog, Empty, ErrorNote, Field, IconButton, Modal, Notice, Spinner, cx, useToast } from "../components/ui";

const ROLE_INFO: Record<string, { tone: "neutral" | "primary" | "danger"; text: string }> = {
  viewer: { tone: "neutral", text: "Can look at everything but change nothing." },
  operator: { tone: "primary", text: "Manages grants, memberships and everyday users and roles. Cannot create superusers or other powerful roles, take over privileged roles, or delete roles." },
  admin: { tone: "danger", text: "Full control, including these accounts, privileged roles and deleting roles." },
};

function randomPassword(len = 18) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_#%+=";
  const buf = new Uint32Array(len);
  crypto.getRandomValues(buf);
  return [...buf].map((n) => chars[n % chars.length]).join("");
}

function PasswordInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="input-group">
      <input className="input mono" value={value} onChange={(e) => onChange(e.target.value)} autoComplete="new-password" placeholder="At least 10 characters" />
      <button type="button" className="input-addon" onClick={() => onChange(randomPassword())} aria-label="Generate password" title="Generate a strong password"><Dices size={16} /></button>
    </div>
  );
}

function CreateDialog({ onClose }: { onClose: () => void }) {
  const { create } = useAppUserMutations();
  const toast = useToast();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const submit = () => create.mutate({ username: username.trim(), password, role }, { onSuccess: () => { toast.success(`Created ${username}. Give them the password securely.`); onClose(); }, onError: toast.error });
  return (
    <Modal title="New account" subtitle="A person who can sign in to this console." onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={create.isPending} disabled={!username.trim() || password.length < 10} onClick={submit}>Create account</Button></>}>
      <div className="form">
        <Field label="Username"><input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="off" /></Field>
        <Field label="Initial password" hint="They can change it after signing in."><PasswordInput value={password} onChange={setPassword} /></Field>
        <Field label="Role">
          <select className="select full" value={role} onChange={(e) => setRole(e.target.value)}>
            {Object.keys(ROLE_INFO).map((r) => <option key={r} value={r}>{r}</option>)}
          </select>
        </Field>
        <p className="muted small">{ROLE_INFO[role].text}</p>
      </div>
    </Modal>
  );
}

function ResetDialog({ user, onClose }: { user: AppUser; onClose: () => void }) {
  const { update } = useAppUserMutations();
  const toast = useToast();
  const [password, setPassword] = useState("");
  return (
    <Modal title={`Reset password for ${user.username}`} onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" loading={update.isPending} disabled={password.length < 10}
        onClick={() => update.mutate({ username: user.username, password }, { onSuccess: () => { toast.success("Password reset"); onClose(); }, onError: toast.error })}>Reset password</Button></>}>
      <Field label="New password"><PasswordInput value={password} onChange={setPassword} /></Field>
    </Modal>
  );
}

export function AccountsPage() {
  const { can } = useCan();
  const auth = useAuth();
  const users = useAppUsers(can("admin"));
  const { update, remove } = useAppUserMutations();
  const toast = useToast();
  const [creating, setCreating] = useState(false);
  const [reset, setReset] = useState<AppUser | null>(null);
  const [deleting, setDeleting] = useState<AppUser | null>(null);

  if (!can("admin")) return <div className="page"><Empty icon={<ShieldCheck size={30} />} title="Admins only">Only administrators can manage console accounts.</Empty></div>;
  const me = users.data?.me;

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Accounts</h1>
          <p className="muted">People who can sign in to this console and what they may do. These are not PostgreSQL users.</p>
        </div>
        <Button variant="primary" icon={<Plus size={16} />} onClick={() => setCreating(true)}>New account</Button>
      </div>

      <div className="grid-3 roles-info">
        {Object.entries(ROLE_INFO).map(([r, i]) => (
          <div key={r} className="card"><Badge tone={i.tone}>{r}</Badge><p className="muted small" style={{ marginTop: 8 }}>{i.text}</p></div>
        ))}
      </div>
      <Notice tone="info">
        The built-in administrator (<span className="mono">ADMIN_USERNAME</span> in the server settings) always works as a break-glass account and is not listed here.
        {auth.data?.oidc_enabled ? " Single sign-on is enabled: people signing in through your identity provider get a role from their groups and need no account here." : " To use single sign-on, configure OIDC_* in the server settings."}
      </Notice>

      {users.isLoading ? <Spinner /> : users.error ? <ErrorNote error={users.error} retry={() => users.refetch()} /> : !users.data!.items.length ? (
        <Empty icon={<UserCog size={30} />} title="No accounts yet">Create accounts for colleagues who should use this console with limited rights.</Empty>
      ) : (
        <div className="card flush">
          <table className="table">
            <thead><tr><th>Account</th><th>Role</th><th>Status</th><th>Last sign-in</th><th /></tr></thead>
            <tbody>
              {users.data!.items.map((u) => {
                const self = u.username === me;
                return (
                  <tr key={u.id} className={cx(u.disabled && "row-disabled")}>
                    <td><div className="name-cell"><Avatar name={u.username} size={32} /><div><div className="name">{u.username}{self && <> <Badge tone="info">you</Badge></>}</div><div className="muted small">created {timeAgo(u.created_at)}{u.created_by ? ` by ${u.created_by}` : ""}</div></div></div></td>
                    <td>
                      <select className="select" value={u.role} disabled={self} aria-label={`Role of ${u.username}`}
                        onChange={(e) => update.mutate({ username: u.username, role: e.target.value }, { onSuccess: () => toast.success(`${u.username} is now ${e.target.value}`), onError: toast.error })}>
                        {Object.keys(ROLE_INFO).map((r) => <option key={r} value={r}>{r}</option>)}
                      </select>
                    </td>
                    <td>{u.disabled ? <Badge tone="danger">Disabled</Badge> : <Badge tone="success">Active</Badge>}</td>
                    <td className="muted">{u.last_login ? timeAgo(u.last_login) : "never"}</td>
                    <td className="actions wide">
                      <IconButton label="Reset password" onClick={() => setReset(u)}><KeyRound size={16} /></IconButton>
                      {!self && <IconButton label={u.disabled ? "Enable account" : "Disable account"} onClick={() => update.mutate({ username: u.username, disabled: !u.disabled }, { onSuccess: () => toast.success(u.disabled ? "Enabled" : "Disabled and signed out"), onError: toast.error })}>{u.disabled ? <CheckCircle2 size={16} /> : <Ban size={16} />}</IconButton>}
                      {!self && <IconButton label="Delete account" className="danger" onClick={() => setDeleting(u)}><Trash2 size={16} /></IconButton>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {creating && <CreateDialog onClose={() => setCreating(false)} />}
      {reset && <ResetDialog user={reset} onClose={() => setReset(null)} />}
      {deleting && (
        <ConfirmDialog title={`Delete ${deleting.username}?`} danger confirmLabel="Delete account" loading={remove.isPending} onClose={() => setDeleting(null)}
          onConfirm={() => remove.mutate(deleting.username, { onSuccess: () => { toast.success("Account deleted"); setDeleting(null); }, onError: toast.error })}>
          They will be signed out immediately and can no longer sign in. Their past activity stays in the audit history.
        </ConfirmDialog>
      )}
    </div>
  );
}
