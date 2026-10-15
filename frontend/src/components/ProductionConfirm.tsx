import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { useServerContext } from "./server";

/** On a production server, changes need one deliberate extra click. Renders nothing elsewhere. */
export function ProductionConfirm({ onChange }: { onChange: (ok: boolean) => void }) {
  const { current } = useServerContext();
  const prod = current.environment === "production";
  const [ok, setOk] = useState(false);
  useEffect(() => { onChange(!prod || ok); }, [prod, ok]); // eslint-disable-line react-hooks/exhaustive-deps
  if (!prod) return null;
  return (
    <label className="prod-confirm">
      <ShieldAlert size={18} />
      <span><strong>This changes the production server “{current.name}”.</strong> I have checked the statements below and want to continue.</span>
      <input type="checkbox" checked={ok} onChange={(e) => setOk(e.target.checked)} aria-label="Confirm changing the production server" />
    </label>
  );
}
