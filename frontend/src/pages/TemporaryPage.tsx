import { useState } from "react";
import { Link } from "react-router-dom";
import { CalendarClock, CalendarPlus, Hourglass, RotateCcw, Timer, X } from "lucide-react";
import { useCan, useTemporary, useTemporaryMutations } from "../api/hooks";
import type { TemporaryItem } from "../api/types";
import { timeAgo } from "../components/activity";
import { ExpiryPicker, toLocalInput, until } from "../components/expiry";
import { Avatar, Badge, Button, ConfirmDialog, Empty, ErrorNote, Field, Modal, Spinner, Switch, cx, useToast } from "../components/ui";

const STATUS: Record<string, { label: string; tone: "primary" | "success" | "neutral" | "danger" | "warn" }> = {
  pending: { label: "Scheduled", tone: "primary" },
  running: { label: "Running", tone: "warn" },
  expired: { label: "Ended", tone: "success" },
  cancelled: { label: "Kept permanently", tone: "neutral" },
  failed: { label: "Failed", tone: "danger" },
};

function ExtendDialog({ item, onClose }: { item: TemporaryItem; onClose: () => void }) {
  const { extend } = useTemporaryMutations();
  const toast = useToast();
  const [when, setWhen] = useState(toLocalInput(new Date(Math.max(Date.now(), new Date(item.expires_at).getTime()) + 7 * 86_400_000)));
  return (
    <Modal title="Change expiry" subtitle={`${item.grantee}: ${item.description}`} onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={extend.isPending} disabled={!when} onClick={() => extend.mutate({ id: item.id, expires_at: new Date(when).toISOString() }, { onSuccess: () => { toast.success("Expiry updated"); onClose(); }, onError: toast.error })}>Save</Button></>}>
      <Field label="New expiry time"><ExpiryPicker value={when} onChange={setWhen} /></Field>
    </Modal>
  );
}

export function TemporaryTable({ items, compact }: { items: TemporaryItem[]; compact?: boolean }) {
  const { can } = useCan();
  const m = useTemporaryMutations();
  const toast = useToast();
  const [extending, setExtending] = useState<TemporaryItem | null>(null);
  const [ending, setEnding] = useState<TemporaryItem | null>(null);
  const live = (i: TemporaryItem) => i.status === "pending" || i.status === "failed";

  return (
    <>
      <div className="card flush">
        <table className="table">
          <thead><tr><th>Who</th><th>Access</th><th>{compact ? "Ends" : "Ends / ended"}</th><th>Status</th>{can("operator") && <th />}</tr></thead>
          <tbody>
            {items.map((i) => {
              const u = until(i.expires_at);
              return (
                <tr key={i.id}>
                  <td><div className="name-cell"><Avatar name={i.grantee} size={28} /><Link to={`/permissions/${encodeURIComponent(i.grantee)}`} className="name">{i.grantee}</Link></div></td>
                  <td>
                    <div>{i.description}</div>
                    <div className="muted small">{i.kind === "grant" ? `privileges in ${i.database}` : "role membership"} · set by {i.created_by} {timeAgo(i.created_at)}</div>
                    {i.error && <div className="danger-text small">{i.error}</div>}
                  </td>
                  <td title={new Date(i.expires_at).toLocaleString()}>
                    {live(i) ? <span className={cx("expiry", u.tone)}>{u.text}</span> : <span className="muted">{i.finished_at ? timeAgo(i.finished_at) : u.text}</span>}
                    <div className="muted small">{new Date(i.expires_at).toLocaleString()}</div>
                  </td>
                  <td><Badge tone={STATUS[i.status].tone}>{STATUS[i.status].label}</Badge></td>
                  {can("operator") && (
                    <td className="actions wide">
                      {live(i) && <>
                        <Button size="sm" variant="ghost" icon={<CalendarPlus size={14} />} onClick={() => setExtending(i)}>Change</Button>
                        <Button size="sm" variant="ghost" onClick={() => m.cancel.mutate(i.id, { onSuccess: () => toast.success("Access kept permanently"), onError: toast.error })}>Keep</Button>
                        <Button size="sm" variant="ghost" icon={i.status === "failed" ? <RotateCcw size={14} /> : <X size={14} />} onClick={() => setEnding(i)}>{i.status === "failed" ? "Retry" : "End now"}</Button>
                      </>}
                    </td>
                  )}
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      {extending && <ExtendDialog item={extending} onClose={() => setExtending(null)} />}
      {ending && (
        <ConfirmDialog title="End this access now?" danger confirmLabel="End access" loading={m.revokeNow.isPending} onClose={() => setEnding(null)}
          onConfirm={() => m.revokeNow.mutate(ending.id, { onSuccess: () => { toast.success("Access ended"); setEnding(null); }, onError: (e) => { toast.error(e); setEnding(null); } })}>
          {ending.grantee} loses <strong>{ending.description}</strong> right away.
        </ConfirmDialog>
      )}
    </>
  );
}

export function TemporaryPage() {
  const [history, setHistory] = useState(false);
  const q = useTemporary({ status: history ? "history" : "pending" }, true);
  const items = q.data?.items ?? [];
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Temporary access</h1>
          <p className="muted">Grants and role memberships that end automatically. Set an expiry when you apply permissions (“Make this temporary”) or on a role's Membership tab.</p>
        </div>
        <Switch label="Show history" checked={history} onChange={setHistory} />
      </div>
      {q.error ? <ErrorNote error={q.error} retry={() => q.refetch()} /> : q.isLoading ? <Spinner /> : items.length === 0 ? (
        <Empty icon={history ? <Timer size={30} /> : <Hourglass size={30} />} title={history ? "Nothing has expired yet" : "No temporary access scheduled"}>
          {history ? "Access that ended, was kept or failed shows up here." : "Use it for contractors, on-call elevation or one-off investigations: access that cleans itself up."}
        </Empty>
      ) : <TemporaryTable items={items} />}
      {!history && items.length > 0 && <p className="muted small"><CalendarClock size={14} style={{ verticalAlign: "-2px" }} /> The server checks every few seconds. If it was offline at the deadline, access is removed as soon as it starts again.</p>}
    </div>
  );
}
