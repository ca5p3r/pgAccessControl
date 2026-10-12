import { useEffect, useMemo, useRef, useState } from "react";
import { Check, Copy, Dices, Eye, EyeOff, Lock, Shield, Users, X } from "lucide-react";
import { useDependencies, useDeleteRole, useRoles, useSetMembership } from "../api/hooks";
import type { RoleDetail, RoleInput, RoleSummary } from "../api/types";
import { Avatar, Badge, Button, ErrorNote, Field, Modal, Notice, Spinner, Switch, cx, useDebounced, useToast } from "./ui";

/* ------------------------------------------------------------ attributes */
export function RoleBadges({ role, max }: { role: Pick<RoleSummary, "superuser" | "createdb" | "createrole" | "replication" | "bypassrls" | "valid_until" | "login" | "is_system">; max?: number }) {
  const items: JSX.Element[] = [];
  if (role.is_system) items.push(<Badge key="sys" tone="info">System</Badge>);
  if (role.superuser) items.push(<Badge key="su" tone="danger" title="Bypasses all permission checks">Superuser</Badge>);
  if (role.createrole) items.push(<Badge key="cr" tone="warn" title="Can create and alter roles">Create roles</Badge>);
  if (role.createdb) items.push(<Badge key="cd" tone="primary">Create DB</Badge>);
  if (role.replication) items.push(<Badge key="rp" tone="neutral">Replication</Badge>);
  if (role.bypassrls) items.push(<Badge key="rl" tone="warn" title="Bypasses row-level security">Bypass RLS</Badge>);
  if (role.login && role.valid_until && new Date(role.valid_until) < new Date()) items.push(<Badge key="ex" tone="danger">Expired</Badge>);
  const shown = max ? items.slice(0, max) : items;
  return (
    <span className="badge-row">
      {shown}
      {max && items.length > max && <Badge>+{items.length - max}</Badge>}
    </span>
  );
}

/* ------------------------------------------------------------ RolePicker */
export function RolePicker({ value, onChange, exclude = [], single, placeholder = "Search roles…", disabled }: { value: string[]; onChange: (v: string[]) => void; exclude?: string[]; single?: boolean; placeholder?: string; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");
  const dq = useDebounced(q, 200);
  const box = useRef<HTMLDivElement>(null);
  const { data, isFetching } = useRoles({ q: dq, include_system: true, limit: 30 }, open);

  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => !box.current?.contains(e.target as Node) && setOpen(false);
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, [open]);

  const options = (data?.items ?? []).filter((r) => !value.includes(r.name) && !exclude.includes(r.name));
  const add = (name: string) => {
    onChange(single ? [name] : [...value, name]);
    setQ("");
    setOpen(false); // keeps the menu from covering the Save button; typing or clicking reopens it
  };

  return (
    <div className={cx("picker", disabled && "disabled")} ref={box}>
      <div className="picker-box" onClick={() => !disabled && setOpen(true)}>
        {value.map((v) => (
          <span key={v} className="chip">
            {v}
            {!disabled && (
              <button type="button" aria-label={`Remove ${v}`} onClick={(e) => { e.stopPropagation(); onChange(value.filter((x) => x !== v)); }}>
                <X size={12} />
              </button>
            )}
          </span>
        ))}
        {!(single && value.length) && (
          <input
            value={q}
            disabled={disabled}
            placeholder={value.length ? "" : placeholder}
            onFocus={() => setOpen(true)}
            onChange={(e) => { setQ(e.target.value); setOpen(true); }}
            onKeyDown={(e) => {
              if (e.key === "Enter" && options[0]) { e.preventDefault(); add(options[0].name); }
              if (e.key === "Backspace" && !q && value.length) onChange(value.slice(0, -1));
              if (e.key === "Escape") setOpen(false);
            }}
          />
        )}
      </div>
      {open && (
        <div className="picker-menu">
          {isFetching && !options.length ? (
            <div className="picker-empty">Searching…</div>
          ) : options.length === 0 ? (
            <div className="picker-empty">No matching roles</div>
          ) : (
            options.map((r) => (
              <button type="button" key={r.name} className="picker-opt" onClick={() => add(r.name)}>
                <Avatar name={r.name} kind={r.kind} size={24} />
                <span className="grow">{r.name}</span>
                <span className="muted">{r.kind === "user" ? "user" : "role"}</span>
              </button>
            ))
          )}
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------- RoleForm */
function randomPassword(len = 20) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_#%+=";
  const buf = new Uint32Array(len);
  crypto.getRandomValues(buf);
  return [...buf].map((n) => chars[n % chars.length]).join("");
}

export function RoleForm({ mode, kind, initial, saving, onSubmit, onCancel, formId = "role-form" }: { mode: "create" | "edit"; kind: "user" | "role"; initial?: RoleDetail; saving?: boolean; onSubmit: (v: RoleInput) => void; onCancel?: () => void; formId?: string }) {
  const [name, setName] = useState(initial?.name ?? "");
  const [login, setLogin] = useState(initial?.login ?? kind === "user");
  const [password, setPassword] = useState("");
  const [removePw, setRemovePw] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [flags, setFlags] = useState({
    superuser: initial?.superuser ?? false,
    createdb: initial?.createdb ?? false,
    createrole: initial?.createrole ?? false,
    inherit: initial?.inherit ?? true,
    replication: initial?.replication ?? false,
    bypassrls: initial?.bypassrls ?? false,
  });
  const [limit, setLimit] = useState(String(initial?.connection_limit ?? -1));
  const [until, setUntil] = useState(initial?.valid_until?.slice(0, 10) ?? "");
  const [comment, setComment] = useState(initial?.comment ?? "");
  const [memberOf, setMemberOf] = useState<string[]>([]);
  const [members, setMembers] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const [touched, setTouched] = useState(false);
  const toast = useToast();

  const nameError = !name.trim() ? "Name is required" : /^pg_/i.test(name) ? 'Names starting with "pg_" are reserved' : new TextEncoder().encode(name).length > 63 ? "Maximum 63 bytes" : null;

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (nameError) return;
    const lim = Number.parseInt(limit, 10);
    const connection_limit = Number.isNaN(lim) ? -1 : lim;
    const valid_until = until ? `${until}T23:59:59Z` : null;
    if (mode === "create") {
      onSubmit({
        name: name.trim(), login, ...flags, connection_limit, comment: comment || null,
        ...(password ? { password } : {}),
        ...(until ? { valid_until } : {}),
        member_of: memberOf, members,
      });
      return;
    }
    // Edit: send only what changed so untouched attributes are never rewritten.
    const out: RoleInput = {};
    if (name.trim() !== initial!.name) out.rename_to = name.trim();
    if (login !== initial!.login) out.login = login;
    (Object.keys(flags) as (keyof typeof flags)[]).forEach((k) => { if (flags[k] !== initial![k]) out[k] = flags[k]; });
    if (connection_limit !== initial!.connection_limit) out.connection_limit = connection_limit;
    if (until !== (initial!.valid_until?.slice(0, 10) ?? "")) out.valid_until = valid_until;
    if (comment !== (initial!.comment ?? "")) out.comment = comment || null;
    if (password) out.password = password;
    if (removePw) out.remove_password = true;
    if (Object.keys(out).length === 0) { toast.info("Nothing to save"); return; }
    onSubmit(out);
  };

  const copy = async () => {
    await navigator.clipboard?.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <form id={formId} onSubmit={submit} className="form" autoComplete="off">
      <Field label={kind === "user" ? "Username" : "Role name"} error={touched ? nameError : null} hint={mode === "edit" ? "Renaming clears MD5 passwords; SCRAM passwords are unaffected." : undefined}>
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} autoFocus={mode === "create"} placeholder={kind === "user" ? "e.g. jane.doe" : "e.g. analytics_readonly"} spellCheck={false} />
      </Field>

      {login && (
        <Field label={mode === "create" ? "Password" : "New password"} hint={mode === "create" ? "Stored as a SCRAM-SHA-256 verifier computed by the server app, never in plain text. Leave empty for passwordless (e.g. certificate / peer auth)." : "Leave empty to keep the current password."}>
          <div className="input-group">
            <input className="input mono" type={showPw ? "text" : "password"} value={password} onChange={(e) => { setPassword(e.target.value); setRemovePw(false); }} autoComplete="new-password" placeholder={mode === "edit" ? "••••••••" : ""} />
            <button type="button" className="input-addon" onClick={() => setShowPw((s) => !s)} aria-label={showPw ? "Hide password" : "Show password"}>{showPw ? <EyeOff size={16} /> : <Eye size={16} />}</button>
            <button type="button" className="input-addon" onClick={() => { setPassword(randomPassword()); setShowPw(true); setRemovePw(false); }} aria-label="Generate password" title="Generate a strong password"><Dices size={16} /></button>
            <button type="button" className="input-addon" onClick={copy} disabled={!password} aria-label="Copy password">{copied ? <Check size={16} /> : <Copy size={16} />}</button>
          </div>
          {mode === "edit" && (
            <label className="check-inline">
              <input type="checkbox" checked={removePw} onChange={(e) => { setRemovePw(e.target.checked); if (e.target.checked) setPassword(""); }} /> Remove the password (user can no longer log in with a password)
            </label>
          )}
        </Field>
      )}

      <Field label="Description">
        <input className="input" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="What is this for?" maxLength={2000} />
      </Field>

      <div className="form-section">Capabilities</div>
      <div className="switch-grid">
        <Switch label="Can log in" hint={kind === "role" ? "Turns this role into a user" : "Required to connect to the database"} checked={login} onChange={setLogin} />
        <Switch label="Inherit privileges" hint="Use privileges of roles it belongs to" checked={flags.inherit} onChange={(v) => setFlags({ ...flags, inherit: v })} />
        <Switch label="Create databases" checked={flags.createdb} onChange={(v) => setFlags({ ...flags, createdb: v })} />
        <Switch label="Create roles" hint="Can create / alter other roles" checked={flags.createrole} onChange={(v) => setFlags({ ...flags, createrole: v })} />
        <Switch label="Replication" checked={flags.replication} onChange={(v) => setFlags({ ...flags, replication: v })} />
        <Switch label="Bypass row-level security" checked={flags.bypassrls} onChange={(v) => setFlags({ ...flags, bypassrls: v })} />
        <Switch label="Superuser" hint="Bypasses ALL permission checks" tone="danger" checked={flags.superuser} onChange={(v) => setFlags({ ...flags, superuser: v })} />
      </div>
      {flags.superuser && <Notice tone="warn">Superusers ignore every grant and revoke. Only enable this when the role truly needs unrestricted access.</Notice>}

      {login && (
        <div className="grid-2">
          <Field label="Connection limit" hint="-1 means unlimited">
            <input className="input" type="number" min={-1} value={limit} onChange={(e) => setLimit(e.target.value)} />
          </Field>
          <Field label="Password expires" hint={until ? "Expires at the end of this day (UTC)" : "Never"}>
            <input className="input" type="date" value={until} onChange={(e) => setUntil(e.target.value)} />
          </Field>
        </div>
      )}

      {mode === "create" && (
        <>
          <div className="form-section">Membership</div>
          <Field label="Member of" hint="Roles whose privileges this one receives">
            <RolePicker value={memberOf} onChange={setMemberOf} />
          </Field>
          {!login && (
            <Field label="Members" hint="Users or roles that should receive this role's privileges">
              <RolePicker value={members} onChange={setMembers} />
            </Field>
          )}
        </>
      )}
      {onCancel && (
        <div className="form-actions">
          <Button type="button" variant="ghost" onClick={onCancel}>Cancel</Button>
          <Button type="submit" variant="primary" loading={saving}>{mode === "create" ? `Create ${login ? "user" : "role"}` : "Save changes"}</Button>
        </div>
      )}
      {!onCancel && mode === "edit" && (
        <div className="form-actions">
          <Button type="submit" variant="primary" loading={saving}>Save changes</Button>
        </div>
      )}
    </form>
  );
}

/* ------------------------------------------------------- MembershipEditor */
function MembershipSection({ title, description, icon, name, direction, current, exclude }: { title: string; description: string; icon: JSX.Element; name: string; direction: "member-of" | "members"; current: string[]; exclude: string[] }) {
  const [value, setValue] = useState(current);
  const mut = useSetMembership(name, direction);
  const toast = useToast();
  const key = current.join("\u0000");
  useEffect(() => setValue(current), [key]); // eslint-disable-line react-hooks/exhaustive-deps
  const dirty = useMemo(() => value.slice().sort().join("\u0000") !== current.slice().sort().join("\u0000"), [value, current]);
  const added = value.filter((v) => !current.includes(v));
  const removed = current.filter((v) => !value.includes(v));
  return (
    <section className="card">
      <div className="card-head">
        <div className="card-icon">{icon}</div>
        <div className="grow">
          <h3>{title}</h3>
          <p className="muted">{description}</p>
        </div>
      </div>
      <RolePicker value={value} onChange={setValue} exclude={[name, ...exclude]} placeholder="Add…" />
      <div className="card-foot">
        <span className="muted">
          {dirty ? `${added.length ? `+${added.length} to add` : ""}${added.length && removed.length ? ", " : ""}${removed.length ? `−${removed.length} to remove` : ""}` : `${current.length} assigned`}
        </span>
        <div className="row gap">
          <Button variant="ghost" disabled={!dirty} onClick={() => setValue(current)}>Reset</Button>
          <Button variant="primary" disabled={!dirty} loading={mut.isPending} onClick={() => mut.mutate(value, { onSuccess: () => toast.success("Membership updated"), onError: toast.error })}>
            Save
          </Button>
        </div>
      </div>
    </section>
  );
}

export function MembershipEditor({ role }: { role: RoleDetail }) {
  const memberOf = role.memberships.map((m) => m.role);
  const members = role.members.map((m) => m.role);
  return (
    <div className="stack">
      <MembershipSection title="Member of" description={`${role.name} receives the privileges of these roles${role.inherit ? "" : " (only via SET ROLE, because it does not inherit)"}.`} icon={<Shield size={18} />} name={role.name} direction="member-of" current={memberOf} exclude={members} />
      <MembershipSection title="Members" description={`Users and roles that receive the privileges of ${role.name}.`} icon={<Users size={18} />} name={role.name} direction="members" current={members} exclude={memberOf} />
    </div>
  );
}

/* --------------------------------------------------------- DeleteRoleDialog */
export function DeleteRoleDialog({ name, onClose, onDeleted }: { name: string; onClose: () => void; onDeleted: () => void }) {
  const deps = useDependencies(name, true);
  const del = useDeleteRole();
  const [heir, setHeir] = useState<string[]>([]);
  const toast = useToast();
  const owns = deps.data?.owns_objects ?? false;
  const totalPriv = deps.data?.dependencies.reduce((a, d) => a + d.privileges, 0) ?? 0;
  const ready = !!deps.data && (!owns || heir.length === 1);

  return (
    <Modal
      title={`Delete “${name}”?`}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="danger" disabled={!ready} loading={del.isPending} icon={<Lock size={15} />}
            onClick={() => del.mutate({ name, reassign_to: heir[0] }, { onSuccess: () => { toast.success(`Deleted ${name}`); onDeleted(); }, onError: toast.error })}>
            Delete permanently
          </Button>
        </>
      }
    >
      {deps.isLoading ? (
        <Spinner label="Checking what depends on this role…" />
      ) : deps.error ? (
        <ErrorNote error={deps.error} />
      ) : (
        <div className="stack-sm">
          <p>This removes the role and its memberships. This cannot be undone.</p>
          {totalPriv > 0 && <Notice tone="info">{totalPriv} privilege grant{totalPriv === 1 ? "" : "s"} held by this role will be revoked.</Notice>}
          {owns && (
            <>
              <Notice tone="warn">
                This role owns database objects:
                <ul className="plain-list">
                  {deps.data!.dependencies.filter((d) => d.owned_objects > 0).map((d) => (
                    <li key={d.database || "_shared"}><strong>{d.database || "cluster-wide"}</strong> — {d.owned_objects} object{d.owned_objects === 1 ? "" : "s"}</li>
                  ))}
                </ul>
              </Notice>
              <Field label="Transfer ownership to" hint="Required. Owned objects are reassigned (never dropped) before the role is removed.">
                <RolePicker single value={heir} onChange={setHeir} exclude={[name]} />
              </Field>
            </>
          )}
        </div>
      )}
    </Modal>
  );
}
