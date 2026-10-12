import { useNavigate, useParams } from "react-router-dom";
import { KeyRound, Globe } from "lucide-react";
import { Avatar, Empty } from "../components/ui";
import { RolePicker } from "../components/roles";
import { PermissionEditor } from "../components/PermissionEditor";

/** Stand-alone permission editor for any role or user, plus the PUBLIC pseudo-role. */
export function PermissionsPage() {
  const { name } = useParams();
  const nav = useNavigate();
  const go = (n?: string) => nav(n ? `/permissions/${encodeURIComponent(n)}` : "/permissions");

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Permissions</h1>
          <p className="muted">Pick a user or role to review and change what it can access. Use PUBLIC to manage privileges that apply to everyone.</p>
        </div>
      </div>

      <section className="card chooser">
        <div className="chooser-pick">
          <label className="field-label">Principal</label>
          <RolePicker single value={name ? [name] : []} onChange={(v) => go(v[0])} placeholder="Search a user or role…" />
        </div>
        <span className="muted">or</span>
        <button className="chooser-public" onClick={() => go("PUBLIC")} aria-pressed={name === "PUBLIC"}>
          <Globe size={16} /> PUBLIC
        </button>
      </section>

      {name ? (
        <div className="selected-principal">
          <Avatar name={name} size={30} /> <h2>{name}</h2>
        </div>
      ) : null}
      {name ? <PermissionEditor key={name} role={name} /> : (
        <Empty icon={<KeyRound size={30} />} title="Choose who to manage">
          Select a user or role above to see their effective access across databases, schemas, tables, sequences and functions.
        </Empty>
      )}
    </div>
  );
}
