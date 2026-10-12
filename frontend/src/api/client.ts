export class ApiError extends Error {
  status: number;
  hint?: string | null;
  constructor(message: string, status: number, hint?: string | null) {
    super(message);
    this.status = status;
    this.hint = hint;
  }
}

export const UNAUTHORIZED_EVENT = "pgac:unauthorized";

type Params = Record<string, string | number | boolean | null | undefined>;

export function qs(params?: Params): string {
  if (!params) return "";
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === "" || v === false) continue;
    sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

async function request<T>(method: string, path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, {
      method,
      credentials: "same-origin",
      headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    });
  } catch (e) {
    if ((e as Error).name === "AbortError") throw e;
    throw new ApiError("Cannot reach the server. Check your connection.", 0);
  }
  if (res.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
  }
  if (!res.ok) {
    let detail = res.statusText;
    let hint: string | null = null;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") detail = data.detail;
      else if (Array.isArray(data.detail)) {
        // FastAPI validation errors
        detail = data.detail.map((d: { loc?: string[]; msg: string }) => `${d.loc?.slice(1).join(".") ?? ""}: ${d.msg}`).join("; ");
      }
      hint = data.hint ?? null;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(detail, res.status, hint);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T>(path: string, params?: Params, signal?: AbortSignal) => request<T>("GET", path + qs(params), undefined, signal),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>("PUT", path, body),
  patch: <T>(path: string, body: unknown) => request<T>("PATCH", path, body),
  del: <T = void>(path: string, params?: Params) => request<T>("DELETE", path + qs(params)),
};

/** Role names may contain any character, including "/". */
export const enc = encodeURIComponent;
