import { useState } from "react";
import { useRoles } from "../api/hooks";
import { Avatar, SearchInput, useDebounced } from "./ui";

/** Pick one user or role from a list that sits in the page flow. Unlike RolePicker's floating menu it cannot be
 *  clipped by a dialog's scroll area, and once someone is chosen it collapses to a single line. */
export function RoleChoice({ value, onChange, exclude = [], placeholder = "Search users and roles…" }: { value?: string; onChange: (v?: string) => void; exclude?: string[]; placeholder?: string }) {
  const [q, setQ] = useState("");
  const dq = useDebounced(q, 200);
  const { data, isFetching } = useRoles({ q: dq || undefined, include_system: false, limit: 50 }, !value);

  if (value) {
    return (
      <div className="role-chosen">
        <Avatar name={value} size={26} />
        <strong className="mono grow">{value}</strong>
        <button type="button" className="link-btn" onClick={() => onChange(undefined)}>Change</button>
      </div>
    );
  }
  const options = (data?.items ?? []).filter((r) => !exclude.includes(r.name));
  return (
    <div className="role-choice">
      <SearchInput value={q} onChange={setQ} placeholder={placeholder} />
      <div className="role-list" role="listbox" aria-label="Users and roles">
        {!data && isFetching ? <div className="role-empty">Searching…</div> : options.length === 0 ? <div className="role-empty">No matching users or roles</div> : options.map((r) => (
          <button type="button" role="option" aria-selected={false} key={r.name} className="role-opt" onClick={() => onChange(r.name)}>
            <Avatar name={r.name} kind={r.kind} size={24} />
            <span className="grow role-opt-name mono">{r.name}</span>
            <span className="muted small">{r.kind}</span>
          </button>
        ))}
        {data && data.total > data.items.length && <div className="role-empty">Showing {data.items.length} of {data.total.toLocaleString()}. Type to narrow down.</div>}
      </div>
    </div>
  );
}
