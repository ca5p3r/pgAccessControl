import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft, History, KeyRound, Settings2, Shield, Trash2 } from "lucide-react";
import { useCan, useRole, useUpdateRole } from "../api/hooks";
import type { RoleDetail as RoleDetailT } from "../api/types";
import { Avatar, Badge, Button, ErrorNote, Notice, Spinner, Tabs, useToast } from "../components/ui";
import { DeleteRoleDialog, MembershipEditor, RoleBadges, RoleForm } from "../components/roles";
import { PermissionEditor } from "../components/PermissionEditor";
import { ActivityTable } from "../components/activity";

type TabId = "settings" | "membership" | "permissions" | "activity";

export function RoleDetail() {
  const { name = "" } = useParams();
  const { data: role, error, isLoading, refetch } = useRole(name);
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as TabId) || "settings";
  const [deleting, setDeleting] = useState(false);
  const [activityPage, setActivityPage] = useState(0);
  const nav = useNavigate();
  const { can } = useCan();

  if (isLoading) return <Spinner label="Loading…" />;
  if (error || !role) return (
    <div className="page">
      <Link to="/users" className="back"><ArrowLeft size={15} /> Back</Link>
      <ErrorNote error={error} retry={() => refetch()} />
    </div>
  );
  const base = role.kind === "user" ? "users" : "roles";

  return (
    <div className="page">
      <Link to={`/${base}`} className="back"><ArrowLeft size={15} /> {role.kind === "user" ? "Users" : "Roles"}</Link>
      <div className="detail-head">
        <Avatar name={role.name} kind={role.kind} size={56} />
        <div className="grow">
          <h1>{role.name} {role.is_current_user && <Badge tone="info">connected as</Badge>}</h1>
          <div className="detail-sub">
            <Badge tone={role.kind === "user" ? "primary" : "neutral"}>{role.kind === "user" ? "User" : "Role"}</Badge>
            <RoleBadges role={role} />
            {role.comment && <span className="muted">{role.comment}</span>}
          </div>
        </div>
        {!role.is_system && !role.is_current_user && can("admin") && (
          <Button variant="danger" icon={<Trash2 size={15} />} onClick={() => setDeleting(true)}>Delete</Button>
        )}
      </div>

      <Tabs<TabId>
        value={tab}
        onChange={(t) => setParams(t === "settings" ? {} : { tab: t }, { replace: true })}
        tabs={[
          { id: "settings", label: "Settings", icon: <Settings2 size={15} /> },
          { id: "membership", label: "Membership", icon: <Shield size={15} />, count: role.memberships.length + role.members.length },
          { id: "permissions", label: "Permissions", icon: <KeyRound size={15} /> },
          { id: "activity", label: "Activity", icon: <History size={15} /> },
        ]}
      />

      <div className="tab-body">
        {role.is_system && tab !== "permissions" && <Notice tone="info">This is a predefined PostgreSQL role. It can be assigned to others but not modified.</Notice>}
        {tab === "settings" && <SettingsTab role={role} />}
        {tab === "membership" && !role.is_system && <MembershipEditor role={role} />}
        {tab === "permissions" && <PermissionEditor role={role.name} />}
        {tab === "activity" && <ActivityTable filters={{ target: role.name }} page={activityPage} onPage={setActivityPage} size={15} />}
      </div>

      {deleting && <DeleteRoleDialog name={role.name} onClose={() => setDeleting(false)} onDeleted={() => nav(`/${base}`)} />}
    </div>
  );
}

function SettingsTab({ role }: { role: RoleDetailT }) {
  const update = useUpdateRole(role.name);
  const nav = useNavigate();
  const toast = useToast();
  if (role.is_system) return null;
  return (
    <section className="card narrow">
      <RoleForm
        key={`${role.name}:${role.oid}:${JSON.stringify([role.login, role.superuser, role.createdb, role.createrole, role.inherit, role.replication, role.bypassrls, role.connection_limit, role.valid_until, role.comment])}`}
        mode="edit"
        kind={role.kind}
        initial={role}
        saving={update.isPending}
        onSubmit={(v) =>
          update.mutate(v, {
            onSuccess: (r) => {
              toast.success("Saved");
              if (r.name !== role.name) nav(`/${r.kind === "user" ? "users" : "roles"}/${encodeURIComponent(r.name)}`, { replace: true });
            },
            onError: toast.error,
          })
        }
      />
    </section>
  );
}
