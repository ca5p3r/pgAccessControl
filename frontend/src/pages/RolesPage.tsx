import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { KeyRound, Pencil, Plus, Trash2, UserRound, Users } from "lucide-react";
import { useCreateRole, useRoles } from "../api/hooks";
import { Avatar, Badge, Button, Drawer, Empty, ErrorNote, IconButton, Pagination, SearchInput, Spinner, Switch, useDebounced, useToast } from "../components/ui";
import { DeleteRoleDialog, RoleBadges, RoleForm } from "../components/roles";

const PAGE = 25;

export function RolesPage({ kind }: { kind: "user" | "role" }) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q);
  const [page, setPage] = useState(0);
  const [system, setSystem] = useState(false);
  const [creating, setCreating] = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);
  const nav = useNavigate();
  const toast = useToast();
  const create = useCreateRole();
  const base = kind === "user" ? "users" : "roles";
  const noun = kind === "user" ? "user" : "role";

  useEffect(() => setPage(0), [dq, system, kind]);
  useEffect(() => { setQ(""); setSystem(false); }, [kind]);
  const { data, error, isLoading, isFetching, refetch } = useRoles({ kind, q: dq || undefined, include_system: system, limit: PAGE, offset: page * PAGE });

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>{kind === "user" ? "Users" : "Roles"}</h1>
          <p className="muted">
            {kind === "user"
              ? "Roles that can log in. Assign roles to grant them privileges."
              : "Reusable permission sets (group roles). Grant privileges to a role, then assign it to users."}
          </p>
        </div>
        <Button variant="primary" icon={<Plus size={16} />} onClick={() => setCreating(true)}>New {noun}</Button>
      </div>

      <div className="toolbar">
        <SearchInput value={q} onChange={setQ} placeholder={`Search ${base}…`} />
        {kind === "role" && <Switch label="Show system roles" checked={system} onChange={setSystem} />}
        <span className="grow" />
        <span className="muted">{data ? `${data.total.toLocaleString()} ${data.total === 1 ? noun : base}` : ""}</span>
      </div>

      {error ? (
        <ErrorNote error={error} retry={() => refetch()} />
      ) : isLoading ? (
        <Spinner label={`Loading ${base}…`} />
      ) : data!.items.length === 0 ? (
        <Empty icon={kind === "user" ? <UserRound size={30} /> : <Users size={30} />} title={q ? "No matches" : `No ${base} yet`}>
          {q ? "Try a different search." : <Button variant="primary" onClick={() => setCreating(true)}>Create the first {noun}</Button>}
        </Empty>
      ) : (
        <div className={`card flush ${isFetching ? "fetching" : ""}`}>
          <table className="table clickable">
            <thead>
              <tr>
                <th>Name</th>
                <th>Attributes</th>
                <th>Member of</th>
                {kind === "role" && <th className="num">Members</th>}
                <th />
              </tr>
            </thead>
            <tbody>
              {data!.items.map((r) => (
                <tr key={r.name} onClick={() => nav(`/${base}/${encodeURIComponent(r.name)}`)}>
                  <td>
                    <div className="name-cell">
                      <Avatar name={r.name} kind={r.kind} />
                      <div>
                        <div className="name">{r.name}</div>
                        {r.comment && <div className="muted small">{r.comment}</div>}
                      </div>
                    </div>
                  </td>
                  <td><RoleBadges role={r} max={3} /></td>
                  <td>
                    <span className="badge-row">
                      {r.member_of.slice(0, 3).map((m) => <Badge key={m} tone="primary">{m}</Badge>)}
                      {r.member_of.length > 3 && <Badge>+{r.member_of.length - 3}</Badge>}
                      {r.member_of.length === 0 && <span className="muted">—</span>}
                    </span>
                  </td>
                  {kind === "role" && <td className="num">{r.member_count}</td>}
                  <td className="actions" onClick={(e) => e.stopPropagation()}>
                    <IconButton label="Permissions" onClick={() => nav(`/${base}/${encodeURIComponent(r.name)}?tab=permissions`)}><KeyRound size={16} /></IconButton>
                    {!r.is_system && <IconButton label="Edit" onClick={() => nav(`/${base}/${encodeURIComponent(r.name)}`)}><Pencil size={16} /></IconButton>}
                    {!r.is_system && <IconButton label="Delete" className="danger" onClick={() => setDeleting(r.name)}><Trash2 size={16} /></IconButton>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination page={page} pageSize={PAGE} total={data!.total} onPage={setPage} />
        </div>
      )}

      {creating && (
        <Drawer
          title={`New ${noun}`}
          subtitle={kind === "user" ? "A role with LOGIN that can connect to the database." : "A group role without LOGIN. Grant it privileges, then add members."}
          onClose={() => setCreating(false)}
        >
          <RoleForm
            mode="create"
            kind={kind}
            saving={create.isPending}
            onCancel={() => setCreating(false)}
            onSubmit={(v) =>
              create.mutate(v, {
                onSuccess: (r) => { toast.success(`Created ${r.name}`); setCreating(false); nav(`/${base}/${encodeURIComponent(r.name)}`); },
                onError: toast.error,
              })
            }
          />
        </Drawer>
      )}
      {deleting && <DeleteRoleDialog name={deleting} onClose={() => setDeleting(null)} onDeleted={() => setDeleting(null)} />}
    </div>
  );
}
