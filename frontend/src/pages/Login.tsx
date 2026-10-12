import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { api } from "../api/client";
import { useAuth } from "../api/hooks";
import { Button, Field, Notice } from "../components/ui";

export function Login() {
  const qc = useQueryClient();
  const auth = useAuth();
  const sso = new URLSearchParams(window.location.search).get("sso_error");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post("/auth/login", { username, password });
      await qc.invalidateQueries({ queryKey: ["auth"] });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="login-card" onSubmit={submit}>
        <span className="brand-mark big"><ShieldCheck size={28} /></span>
        <h1>pgAccessControl</h1>
        <p className="muted">Sign in to manage PostgreSQL roles and permissions.</p>
        {error && <Notice tone="danger">{error}</Notice>}
        {sso && !error && <Notice tone="danger">{sso === "no_access" ? "Your account signed in, but it is not in any group that may use this console. Ask an administrator." : sso === "access_denied" ? "Sign-in was cancelled." : "Single sign-on failed. Please try again."}</Notice>}
        {auth.data?.oidc_enabled && (
          <a className="btn btn-secondary btn-md block sso-btn" href="/api/auth/oidc/login"><ShieldCheck size={16} /> {auth.data.oidc_label || "Sign in with SSO"}</a>
        )}
        {auth.data?.oidc_enabled && auth.data.local_login !== false && <div className="divider"><span>or use a password</span></div>}
        {auth.data?.local_login !== false && (
          <>
        <Field label="Username">
          <input className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus autoComplete="username" />
        </Field>
        <Field label="Password">
          <input className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        </Field>
        <Button type="submit" variant="primary" loading={busy} disabled={!username || !password} className="block">
          Sign in
        </Button>
          </>
        )}
      </form>
    </div>
  );
}
