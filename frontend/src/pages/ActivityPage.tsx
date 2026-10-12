import { useCallback, useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Download, X } from "lucide-react";
import { downloadUrl, useAuditFacets, useMeta } from "../api/hooks";
import type { AuditFilters } from "../api/types";
import { ActivityTable } from "../components/activity";
import { Button, Notice, SearchInput, Switch, useDebounced } from "../components/ui";

const CATEGORIES = [
  { value: "", label: "All activity" },
  { value: "role.", label: "Role & user changes" },
  { value: "permission.", label: "Permission changes" },
  { value: "auth.", label: "Sign-ins" },
  { value: "access.", label: "Temporary access" },
  { value: "snapshot.", label: "Snapshots" },
  { value: "drift.", label: "Drift alerts" },
  { value: "account.", label: "Console accounts" },
  { value: "export.", label: "Exports" },
];
const KEYS = ["q", "actor", "action", "status", "date_from", "date_to", "target"] as const;

export function ActivityPage() {
  const [sp, setSp] = useSearchParams();
  const meta = useMeta();
  const facets = useAuditFacets();
  const [live, setLive] = useState(false);
  const page = Math.max(0, Number(sp.get("page") ?? 0) || 0);

  const filters: AuditFilters = Object.fromEntries(KEYS.map((k) => [k, sp.get(k) ?? undefined]).filter(([, v]) => v));
  const update = useCallback((changes: Record<string, string | null>, resetPage = true) => {
    setSp((prev) => {
      const next = new URLSearchParams(prev);
      for (const [k, v] of Object.entries(changes)) (v ? next.set(k, v) : next.delete(k));
      if (resetPage) next.delete("page");
      return next;
    }, { replace: true });
  }, [setSp]);

  const q = sp.get("q") ?? "";
  const [qInput, setQInput] = useState(q);
  const dq = useDebounced(qInput, 250);
  useEffect(() => { if (dq !== q) update({ q: dq }); }, [dq]); // eslint-disable-line react-hooks/exhaustive-deps

  const active = Object.keys(filters).length > 0;
  const clear = () => { setQInput(""); setSp({}, { replace: true }); };
  const exportParams = { ...filters };

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Activity</h1>
          <p className="muted">Every change made through this app: who did it, when, and the exact SQL. Direct changes made with other tools (psql, pgAdmin) are not recorded here.</p>
        </div>
        <div className="row gap">
          <Button onClick={() => (window.location.href = downloadUrl("/audit/export", { ...exportParams, format: "csv" }))} icon={<Download size={15} />}>CSV</Button>
          <Button onClick={() => (window.location.href = downloadUrl("/audit/export", { ...exportParams, format: "json" }))} icon={<Download size={15} />}>JSON</Button>
        </div>
      </div>

      {meta.data && !meta.data.audit_enabled && <Notice tone="warn">Audit history is disabled on the server.</Notice>}

      <div className="toolbar">
        <SearchInput value={qInput} onChange={setQInput} placeholder="Search who, what, SQL…" />
        <select className="select" value={sp.get("action") ?? ""} onChange={(e) => update({ action: e.target.value })} aria-label="Type of activity">
          {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
        </select>
        <select className="select" value={sp.get("actor") ?? ""} onChange={(e) => update({ actor: e.target.value })} aria-label="Who">
          <option value="">Anyone</option>
          {facets.data?.actors.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <select className="select" value={sp.get("status") ?? ""} onChange={(e) => update({ status: e.target.value })} aria-label="Outcome">
          <option value="">Any outcome</option>
          <option value="success">Succeeded</option>
          <option value="failed">Failed</option>
        </select>
        <label className="date-field"><span className="muted">From</span><input className="input" type="date" value={sp.get("date_from") ?? ""} max={sp.get("date_to") ?? undefined} onChange={(e) => update({ date_from: e.target.value })} /></label>
        <label className="date-field"><span className="muted">To</span><input className="input" type="date" value={sp.get("date_to") ?? ""} min={sp.get("date_from") ?? undefined} onChange={(e) => update({ date_to: e.target.value })} /></label>
        {active && <Button size="sm" variant="ghost" icon={<X size={14} />} onClick={clear}>Clear</Button>}
        <span className="grow" />
        <Switch label="Live" checked={live} onChange={setLive} />
      </div>
      {sp.get("target") && <Notice tone="info">Showing activity for <strong className="mono">{sp.get("target")}</strong>. <button className="link-btn" onClick={() => update({ target: null })}>Show all</button></Notice>}

      <ActivityTable filters={filters} page={page} onPage={(p) => update({ page: p ? String(p) : null }, false)} live={live} />
    </div>
  );
}
