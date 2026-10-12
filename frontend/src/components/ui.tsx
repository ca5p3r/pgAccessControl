import {
  cloneElement,
  createContext,
  isValidElement,
  useCallback,
  useContext,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactElement,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Info, Loader2, Search, X, XCircle } from "lucide-react";
import { ApiError } from "../api/client";

export const cx = (...c: (string | false | null | undefined)[]) => c.filter(Boolean).join(" ");

/* ---------------------------------------------------------------- Button */
type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "ghost" | "danger";
  size?: "sm" | "md";
  loading?: boolean;
  icon?: ReactNode;
};

export function Button({ variant = "secondary", size = "md", loading, icon, children, className, disabled, ...rest }: BtnProps) {
  return (
    <button className={cx("btn", `btn-${variant}`, `btn-${size}`, className)} disabled={disabled || loading} {...rest}>
      {loading ? <Loader2 size={15} className="spin" /> : icon}
      {children}
    </button>
  );
}

export function IconButton({ label, children, className, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button className={cx("icon-btn", className)} aria-label={label} title={label} {...rest}>
      {children}
    </button>
  );
}

/* ----------------------------------------------------------------- Badge */
export function Badge({ tone = "neutral", children, title }: { tone?: "neutral" | "primary" | "success" | "warn" | "danger" | "info"; children: ReactNode; title?: string }) {
  return (
    <span className={cx("badge", `badge-${tone}`)} title={title}>
      {children}
    </span>
  );
}

/* ---------------------------------------------------------------- Switch */
export function Switch({ checked, onChange, label, hint, tone, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint?: string; tone?: "danger"; disabled?: boolean }) {
  const id = useId();
  return (
    <label className={cx("switch-row", disabled && "disabled")} htmlFor={id}>
      <span className="switch-text">
        <span className="switch-label">{label}</span>
        {hint && <span className="switch-hint">{hint}</span>}
      </span>
      <input id={id} type="checkbox" role="switch" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span className={cx("switch-track", tone)} aria-hidden />
    </label>
  );
}

/* ----------------------------------------------------------------- Field */
export function Field({ label, hint, error, children }: { label: string; hint?: ReactNode; error?: string | null; children: ReactNode }) {
  const id = useId();
  // A lone native control is labelled directly; composite controls (input groups, pickers) as a group.
  const single = isValidElement(children) && ["input", "select", "textarea"].includes(children.type as string);
  const control = single ? (
    cloneElement(children as ReactElement<{ id?: string }>, { id })
  ) : (
    <div role="group" aria-labelledby={`${id}-label`}>
      {children}
    </div>
  );
  return (
    <div className="field">
      <label id={`${id}-label`} htmlFor={single ? id : undefined} className="field-label">{label}</label>
      {control}
      {error ? <div className="field-error">{error}</div> : hint ? <div className="field-hint">{hint}</div> : null}
    </div>
  );
}

export function SearchInput({ value, onChange, placeholder = "Search…", inputRef, ...rest }: { value: string; onChange: (v: string) => void; inputRef?: React.Ref<HTMLInputElement> } & Omit<InputHTMLAttributes<HTMLInputElement>, "onChange" | "value">) {
  return (
    <div className="search">
      <Search size={15} />
      <input ref={inputRef} value={value} onChange={(e) => onChange(e.target.value)} onKeyDown={(e) => e.key === "Escape" && value && onChange("")} placeholder={placeholder} aria-label={placeholder} {...rest} />
      {value && (
        <button className="search-clear" onClick={() => onChange("")} aria-label="Clear search">
          <X size={14} />
        </button>
      )}
    </div>
  );
}

/** Debounced value, for search boxes that hit the API. */
export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

/* --------------------------------------------------------------- Spinner */
export function Spinner({ label }: { label?: string }) {
  return (
    <div className="spinner-wrap" role="status">
      <Loader2 className="spin" size={22} />
      {label && <span>{label}</span>}
    </div>
  );
}

export function Empty({ icon, title, children }: { icon?: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      {icon && <div className="empty-icon">{icon}</div>}
      <div className="empty-title">{title}</div>
      {children && <div className="empty-body">{children}</div>}
    </div>
  );
}

export function ErrorNote({ error, retry }: { error: unknown; retry?: () => void }) {
  const e = error as ApiError;
  return (
    <div className="notice notice-danger" role="alert">
      <XCircle size={18} />
      <div className="grow">
        <strong>{e?.message ?? "Something went wrong"}</strong>
        {e?.hint && <div className="muted">{e.hint}</div>}
      </div>
      {retry && (
        <Button size="sm" onClick={retry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Notice({ tone = "info", children, icon }: { tone?: "info" | "warn" | "danger" | "success"; children: ReactNode; icon?: ReactNode }) {
  const defaultIcon = tone === "warn" ? <AlertTriangle size={18} /> : tone === "danger" ? <XCircle size={18} /> : tone === "success" ? <CheckCircle2 size={18} /> : <Info size={18} />;
  return (
    <div className={cx("notice", `notice-${tone}`)}>
      {icon ?? defaultIcon}
      <div className="grow">{children}</div>
    </div>
  );
}

/* ------------------------------------------------------------ Pagination */
export function Pagination({ page, pageSize, total, onPage }: { page: number; pageSize: number; total: number; onPage: (p: number) => void }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (total <= pageSize) return <div className="pager muted">{total} {total === 1 ? "item" : "items"}</div>;
  const from = page * pageSize + 1;
  const to = Math.min(total, (page + 1) * pageSize);
  return (
    <div className="pager">
      <span className="muted">
        {from}–{to} of {total.toLocaleString()}
      </span>
      <div className="pager-btns">
        <IconButton label="Previous page" disabled={page === 0} onClick={() => onPage(page - 1)}>
          <ChevronLeft size={16} />
        </IconButton>
        <span className="pager-num">
          {page + 1} / {pages}
        </span>
        <IconButton label="Next page" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}>
          <ChevronRight size={16} />
        </IconButton>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- Avatar */
const HUES = [248, 200, 160, 20, 330, 280, 40, 180];
export function Avatar({ name, kind, size = 36 }: { name: string; kind?: "user" | "role"; size?: number }) {
  const hue = useMemo(() => HUES[[...name].reduce((a, c) => a + c.charCodeAt(0), 0) % HUES.length], [name]);
  const initials = name.replace(/[^a-zA-Z0-9]+/g, " ").trim().slice(0, 2).toUpperCase() || "?";
  return (
    <span
      className={cx("avatar", kind === "role" && "avatar-role")}
      style={{ width: size, height: size, fontSize: size * 0.38, ["--hue" as string]: hue }}
      aria-hidden
    >
      {initials}
    </span>
  );
}

/* ----------------------------------------------------------------- Tabs */
export function Tabs<T extends string>({ tabs, value, onChange }: { tabs: { id: T; label: string; icon?: ReactNode; count?: number }[]; value: T; onChange: (t: T) => void }) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.id} role="tab" aria-selected={value === t.id} className={cx("tab", value === t.id && "active")} onClick={() => onChange(t.id)}>
          {t.icon}
          {t.label}
          {t.count !== undefined && <span className="tab-count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

/* ----------------------------------------------------------- Modal/Drawer */
function useEscape(onClose: () => void) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onClose]);
}

function Overlay({ onClose, variant, title, subtitle, children, footer, wide }: { onClose: () => void; variant: "modal" | "drawer"; title: string; subtitle?: string; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  useEscape(onClose);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = "";
      prev?.focus?.();
    };
  }, []);
  return createPortal(
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-label={title} className={cx(variant, wide && "wide")}>
        <header className="overlay-head">
          <div>
            <h2>{title}</h2>
            {subtitle && <p className="muted">{subtitle}</p>}
          </div>
          <IconButton label="Close" onClick={onClose}>
            <X size={18} />
          </IconButton>
        </header>
        <div className="overlay-body">{children}</div>
        {footer && <footer className="overlay-foot">{footer}</footer>}
      </div>
    </div>,
    document.body,
  );
}

export const Modal = (p: Omit<Parameters<typeof Overlay>[0], "variant">) => <Overlay variant="modal" {...p} />;
export const Drawer = (p: Omit<Parameters<typeof Overlay>[0], "variant">) => <Overlay variant="drawer" {...p} />;

/* --------------------------------------------------------------- Toasts */
interface ToastItem {
  id: number;
  tone: "success" | "error" | "info";
  message: string;
}
interface ToastApi {
  success: (m: string) => void;
  error: (e: unknown) => void;
  info: (m: string) => void;
}
const ToastCtx = createContext<ToastApi>({ success() {}, error() {}, info() {} });
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const next = useRef(1);
  const push = useCallback((tone: ToastItem["tone"], message: string) => {
    const id = next.current++;
    setItems((l) => [...l, { id, tone, message }]);
    setTimeout(() => setItems((l) => l.filter((t) => t.id !== id)), tone === "error" ? 7000 : 3500);
  }, []);
  const api = useMemo<ToastApi>(
    () => ({
      success: (m) => push("success", m),
      info: (m) => push("info", m),
      error: (e) => push("error", e instanceof Error ? e.message : String(e)),
    }),
    [push],
  );
  return (
    <ToastCtx.Provider value={api}>
      {children}
      {createPortal(
        <div className="toasts" aria-live="polite">
          {items.map((t) => (
            <div key={t.id} className={cx("toast", `toast-${t.tone}`)}>
              {t.tone === "success" ? <CheckCircle2 size={18} /> : t.tone === "error" ? <XCircle size={18} /> : <Info size={18} />}
              <span>{t.message}</span>
              <button onClick={() => setItems((l) => l.filter((x) => x.id !== t.id))} aria-label="Dismiss">
                <X size={14} />
              </button>
            </div>
          ))}
        </div>,
        document.body,
      )}
    </ToastCtx.Provider>
  );
}

/* --------------------------------------------------------------- Confirm */
export function ConfirmDialog({ title, children, confirmLabel = "Confirm", danger, loading, onConfirm, onClose }: { title: string; children: ReactNode; confirmLabel?: string; danger?: boolean; loading?: boolean; onConfirm: () => void; onClose: () => void }) {
  return (
    <Modal
      title={title}
      onClose={onClose}
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={danger ? "danger" : "primary"} loading={loading} onClick={onConfirm}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      {children}
    </Modal>
  );
}
