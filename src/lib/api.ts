// Typed client for the Tessera gateway. Every call goes to /api/* with cookies,
// and surfaces the server's error message on failure.

import type {
  AccessRequest,
  AuditEntry,
  Context,
  Decision,
  Resource,
  User,
} from "../../shared/types.ts";
import type { Flow, Workload } from "../../shared/segmentation.ts";

async function req<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const res = await fetch(`/api/${path}`, {
    method,
    credentials: "same-origin",
    headers: body !== undefined ? { "content-type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data: any = null;
  try {
    data = await res.json();
  } catch {
    /* no body */
  }
  if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
  return data as T;
}

export type ResourceMeta = Omit<Resource, "fields"> & { hasGrant: boolean };
export type FieldView = { label: string; value: string | null; redacted: boolean };

export interface Me {
  user: User | null;
  assurance?: "password" | "mfa" | "passkey";
  context?: Context;
  hasPasskey?: boolean;
}

export const api = {
  me: () => req<Me>("me"),
  login: (email: string, password: string) =>
    req<{ userId: string; name: string; sandbox: boolean; need2fa: boolean }>("login", "POST", {
      email,
      password,
    }),
  sandboxCode: (userId: string) => req<{ code: string }>(`sandbox-code?userId=${userId}`),
  verify: (userId: string, code: string, context: Context) =>
    req<{ user: User }>("verify", "POST", { userId, code, context }),
  logout: () => req<{ ok: true }>("logout", "POST"),
  setContext: (context: Context) => req<{ context: Context }>("context", "POST", { context }),

  resources: () => req<{ resources: ResourceMeta[] }>("resources"),
  access: (resourceId: string) =>
    req<{ decision: Decision; fields: FieldView[] | null }>("access", "POST", { resourceId }),
  stepup: (resourceId: string, code: string) =>
    req<{ decision: Decision; fields: FieldView[] | null }>("stepup", "POST", { resourceId, code }),

  segmentation: () =>
    req<{
      workloads: Workload[];
      flows: Flow[];
      matrix: { from: Workload; cells: { to: Workload; allowed: boolean | null }[] }[];
    }>("segmentation"),

  requests: () => req<{ requests: AccessRequest[] }>("requests"),
  requestAccess: (resourceId: string, reason: string) =>
    req<{ request: AccessRequest }>("requests", "POST", { resourceId, reason }),
  decideRequest: (id: string, approve: boolean) =>
    req<{ request: AccessRequest }>("requests/decide", "POST", { id, approve }),

  users: () => req<{ users: User[] }>("users"),
  createUser: (u: {
    name: string;
    email: string;
    password: string;
    role: "admin" | "member";
    department: string;
    clearance: string;
  }) => req<{ user: User; otpauth: string }>("users", "POST", u),
  deleteUser: (id: string) => req<{ ok: true }>(`users/${id}`, "DELETE"),

  audit: () => req<{ entries: AuditEntry[] }>("audit"),
  verifyAudit: () => req<{ ok: boolean; count: number; brokenAt?: number }>("audit/verify"),
};
