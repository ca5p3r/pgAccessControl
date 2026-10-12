export const toLocalInput = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);

export function until(iso: string): { text: string; tone: "danger" | "warn" | "muted" } {
  const ms = new Date(iso).getTime() - Date.now();
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  const mins = Math.round(ms / 60_000);
  const text = Math.abs(mins) < 90 ? rtf.format(mins, "minute") : Math.abs(mins) < 2880 ? rtf.format(Math.round(mins / 60), "hour") : rtf.format(Math.round(mins / 1440), "day");
  return { text, tone: ms < 0 ? "danger" : ms < 24 * 3_600_000 ? "warn" : "muted" };
}

/** Quick presets plus a date/time picker, shared by the Review dialog, the membership editor and "change expiry". */
export function ExpiryPicker({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const preset = (hours: number) => onChange(toLocalInput(new Date(Date.now() + hours * 3_600_000)));
  return (
    <div className="expiry-picker">
      <div className="chip-toggles">
        {([["1 hour", 1], ["8 hours", 8], ["1 day", 24], ["1 week", 168], ["30 days", 720]] as const).map(([l, h]) => (
          <button key={l} type="button" className="chip-toggle" onClick={() => preset(h)}>{l}</button>
        ))}
      </div>
      <input className="input" type="datetime-local" value={value} min={toLocalInput(new Date())} onChange={(e) => onChange(e.target.value)} aria-label="Expires at" />
    </div>
  );
}
