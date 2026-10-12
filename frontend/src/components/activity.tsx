import { Fragment, useState } from "react";
import { Check, ChevronRight, Copy, History } from "lucide-react";
import { useAudit } from "../api/hooks";
import type { AuditEntry, AuditFilters } from "../api/types";
import { Avatar, Badge, Empty, ErrorNote, Notice, Pagination, Spinner, cx } from "./ui";

export function timeAgo(iso: string): string {
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 45) return "just now";
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  if (s < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (s < 86400) return rtf.format(-Math.round(s / 3600), "hour");
  if (s < 86400 * 30) return rtf.format(-Math.round(s / 86400), "day");
  return new Date(iso).toLocaleDateString();
}

const ACTIONS: Record<string, { label: string; tone: "success" | "primary" | "danger" | "info" | "neutral" | "warn" }> = {
  "role.create": { label: "Created", tone: "success" },
  "role.update": { label: "Updated", tone: "primary" },
  "role.delete": { label: "Deleted", tone: "danger" },
  "role.membership": { label: "Membership", tone: "info" },
  "permission.apply": { label: "Permissions", tone: "primary" },
  "auth.login": { label: "Sign-in", tone: "neutral" },
  "auth.logout": { label: "Sign-out", tone: "neutral" },
  "auth.login_failed": { label: "Failed sign-in", tone: "warn" },
  "export.permissions": { label: "Export", tone: "neutral" },
  "access.expired": { label: "Access ended", tone: "success" },
  "access.revoke_now": { label: "Access ended", tone: "success" },
  "access.schedule": { label: "Expiry set", tone: "info" },
  "access.extend": { label: "Expiry changed", tone: "info" },
  "access.cancel": { label: "Expiry removed", tone: "neutral" },
  "snapshot.create": { label: "Snapshot", tone: "primary" },
  "snapshot.delete": { label: "Snapshot", tone: "danger" },
  "snapshot.baseline": { label: "Baseline", tone: "primary" },
  "drift.detected": { label: "Drift", tone: "warn" },
  "drift.cleared": { label: "Drift cleared", tone: "success" },
  "account.create": { label: "Account", tone: "success" },
  "account.update": { label: "Account", tone: "primary" },
  "account.delete": { label: "Account", tone: "danger" },
  "account.password": { label: "Password", tone: "neutral" },
};

export const ActionBadge = ({ action }: { action: string }) => {
  const a = ACTIONS[action] ?? { label: action, tone: "neutral" as const };
  return <Badge tone={a.tone}>{a.label}</Badge>;
};

const fmtVal = (v: unknown) => (v === null || v === "" || v === undefined ? "none" : typeof v === "boolean" ? (v ? "yes" : "no") : Array.isArray(v) ? (v.length ? v.join(", ") : "none") : String(v));

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="code-copy" onClick={async () => { await navigator.clipboard?.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); }}>
      {done ? <Check size={14} /> : <Copy size={14} />} {done ? "Copied" : "Copy"}
    </button>
  );
}

function Details({ e }: { e: AuditEntry }) {
  const changes = (e.details.changes ?? null) as Record<string, [unknown, unknown]> | null;
  const added = (e.details.added as string[] | undefined) ?? [];
  const removed = (e.details.removed as string[] | undefined) ?? [];
  return (
    <div className="audit-detail">
      <dl className="meta-grid">
        <div><dt>Time</dt><dd>{new Date(e.ts).toLocaleString()} <span className="muted">({e.ts.slice(0, 19).replace("T", " ")} UTC)</span></dd></div>
        <div><dt>Who</dt><dd>{e.actor}{e.ip ? <span className="muted"> from {e.ip}</span> : null}</dd></div>
        {e.target && <div><dt>Target</dt><dd className="mono">{e.target}</dd></div>}
        {e.database && <div><dt>Database</dt><dd className="mono">{e.database}</dd></div>}
      </dl>
      {e.error && <Notice tone="danger"><strong>Error:</strong> {e.error}</Notice>}
      {changes && Object.keys(changes).length > 0 && (
        <div>
          <div className="detail-title">What changed</div>
          <ul className="change-list">
            {Object.entries(changes).filter(([k]) => k !== "member_of" && k !== "members").map(([k, [from, to]]) => (
              <li key={k}><span className="mono">{k}</span> <span className="from">{fmtVal(from)}</span> → <span className="to">{fmtVal(to)}</span></li>
            ))}
          </ul>
        </div>
      )}
      {(added.length > 0 || removed.length > 0) && (
        <div className="badge-row">
          {added.map((r) => <Badge key={`a${r}`} tone="success">+ {r}</Badge>)}
          {removed.map((r) => <Badge key={`r${r}`} tone="danger">− {r}</Badge>)}
        </div>
      )}
      {e.statements.length > 0 && (
        <div>
          <div className="detail-title">SQL executed <span className="muted">(passwords redacted)</span></div>
          <div className="code-wrap"><CopyButton text={e.statements.join("\n")} /><pre className="code">{e.statements.join("\n")}</pre></div>
        </div>
      )}
    </div>
  );
}

export function ActivityTable({ filters, page, onPage, size = 25, live = false }: { filters: AuditFilters; page: number; onPage: (p: number) => void; size?: number; live?: boolean }) {
  const { data, error, isLoading, isFetching, refetch } = useAudit(filters, page, size, live);
  const [open, setOpen] = useState<number | null>(null);

  if (error) return <ErrorNote error={error} retry={() => refetch()} />;
  if (isLoading) return <Spinner label="Loading activity…" />;
  if (!data!.enabled) return <Notice tone="warn">Audit history is turned off (<span className="mono">AUDIT_ENABLED=false</span>), so nothing is being stored. Entries are still written to the server log.</Notice>;
  if (data!.items.length === 0)
    return <Empty icon={<History size={28} />} title="No activity found">{Object.values(filters).some(Boolean) ? "Nothing matches these filters." : "Changes made through this app will appear here."}</Empty>;

  return (
    <div className={cx("card flush", isFetching && !live && "fetching")}>
      <table className="table audit">
        <thead>
          <tr><th>When</th><th>Who</th><th>Action</th><th>Summary</th><th /></tr>
        </thead>
        <tbody>
          {data!.items.map((e) => (
            <Fragment key={e.id}>
              <tr className={cx("audit-row", open === e.id && "open", e.status === "failed" && "failed")} onClick={() => setOpen(open === e.id ? null : e.id)}>
                <td className="nowrap" title={new Date(e.ts).toLocaleString()}>{timeAgo(e.ts)}</td>
                <td><span className="who"><Avatar name={e.actor} size={22} />{e.actor}</span></td>
                <td><ActionBadge action={e.action} /></td>
                <td className={cx(e.status === "failed" && "danger-text")}>{e.summary}</td>
                <td className="chev"><ChevronRight size={16} className={cx(open === e.id && "rot")} /></td>
              </tr>
              {open === e.id && <tr className="audit-expanded"><td colSpan={5}><Details e={e} /></td></tr>}
            </Fragment>
          ))}
        </tbody>
      </table>
      <Pagination page={page} pageSize={size} total={data!.total} onPage={onPage} />
    </div>
  );
}
