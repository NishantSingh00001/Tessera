// Data access: users, their credentials, sessions and the audit trail. Secrets
// live in their own namespace, never alongside the user record that the API
// returns, and never reach the browser.

import { hashPassword, newId, newToken } from "./crypto.ts";
import { open, seal, sha256Hex } from "./aead.ts";
import { newSecret, otpauthUri } from "./totp.ts";
import { kv } from "./store.ts";
import { PERSONAS, RESOURCES } from "../../shared/seed.ts";
import type {
  AccessRequest,
  AuditEntry,
  Clearance,
  Context,
  Department,
  Resource,
  Role,
  Session,
  User,
} from "../../shared/types.ts";

export const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes
export const DEMO_PASSWORD = "Sandbox#2026"; // shared sign-in secret for the built-in personas

interface Creds {
  passwordHash: string;
  /** TOTP seed, sealed at rest with AES-256-GCM (see aead.ts). */
  totpSealed: string;
}

const users = () => kv("users");
const creds = () => kv("creds");
const sessions = () => kv("sessions");
const audit = () => kv("audit");
const meta = () => kv("meta");

export async function listUsers(): Promise<User[]> {
  const keys = await users().list();
  const all = await Promise.all(keys.map((k) => users().get<User>(k)));
  return all.filter((u): u is User => !!u).sort((a, b) => a.createdAt - b.createdAt);
}

export const getUser = (id: string) => users().get<User>(id);

export interface NewUser {
  name: string;
  email: string;
  role: Role;
  department: Department;
  clearance: Clearance;
  password: string;
  sandbox?: boolean;
}

export async function createUser(
  input: NewUser,
): Promise<{ user: User; totpSecret: string; otpauth: string }> {
  const id = newId("u_");
  const totpSecret = newSecret();
  const user: User = {
    id,
    name: input.name,
    email: input.email.toLowerCase(),
    role: input.role,
    department: input.department,
    clearance: input.clearance,
    createdAt: Date.now(),
    sandbox: !!input.sandbox,
  };
  await users().set(id, user);
  await creds().set(id, {
    passwordHash: hashPassword(input.password),
    totpSealed: seal(totpSecret),
  } satisfies Creds);
  return { user, totpSecret, otpauth: otpauthUri(totpSecret, user.email) };
}

/** The decrypted TOTP seed for a user, or null. */
export async function getTotpSecret(id: string): Promise<string | null> {
  const c = await creds().get<Creds>(id);
  if (!c) return null;
  try {
    return open(c.totpSealed);
  } catch {
    return null;
  }
}

export async function deleteUser(id: string): Promise<void> {
  await users().delete(id);
  await creds().delete(id);
}

export async function findByEmail(email: string): Promise<User | null> {
  const all = await listUsers();
  return all.find((u) => u.email === email.toLowerCase()) ?? null;
}

export const getPasswordHash = async (id: string): Promise<string | null> =>
  (await creds().get<Creds>(id))?.passwordHash ?? null;

// ---- sessions ----
export async function createSession(
  userId: string,
  assurance: Session["assurance"],
  context: Context,
): Promise<Session> {
  const session: Session = { token: newToken(), userId, assurance, createdAt: Date.now(), context };
  await sessions().set(session.token, session);
  return session;
}

export async function getSession(token: string | undefined): Promise<Session | null> {
  if (!token) return null;
  const s = await sessions().get<Session>(token);
  if (!s) return null;
  if (Date.now() - s.createdAt > SESSION_TTL_MS) {
    await sessions().delete(token);
    return null;
  }
  return s;
}

export async function updateSession(s: Session): Promise<void> {
  await sessions().set(s.token, s);
}

export const endSession = (token: string) => sessions().delete(token);

// ---- audit (tamper-evident hash chain) ----
type AuditInput = Omit<AuditEntry, "id" | "at" | "seq" | "prevHash" | "hash">;

function canonical(e: AuditInput & { id: string; at: number; seq: number; prevHash: string }): string {
  return JSON.stringify([e.seq, e.at, e.userId, e.resourceId, e.verdict, e.reason, e.risk, e.prevHash]);
}

export async function appendAudit(entry: AuditInput): Promise<AuditEntry> {
  const head = (await meta().get<{ seq: number; hash: string }>("audit_head")) ?? {
    seq: 0,
    hash: "genesis",
  };
  const id = newId("a_");
  const at = Date.now();
  const seq = head.seq + 1;
  const prevHash = head.hash;
  const hash = sha256Hex(canonical({ ...entry, id, at, seq, prevHash }));
  const full: AuditEntry = { ...entry, id, at, seq, prevHash, hash };
  await audit().set(id, full);
  await meta().set("audit_head", { seq, hash });
  return full;
}

export async function listAudit(limit = 200): Promise<AuditEntry[]> {
  const keys = await audit().list();
  const all = await Promise.all(keys.map((k) => audit().get<AuditEntry>(k)));
  return all
    .filter((a): a is AuditEntry => !!a)
    .sort((a, b) => b.seq - a.seq)
    .slice(0, limit);
}

/** Recompute the chain in order and report the first break, if any. */
export async function verifyAuditChain(): Promise<{ ok: boolean; count: number; brokenAt?: number }> {
  const keys = await audit().list();
  const all = (await Promise.all(keys.map((k) => audit().get<AuditEntry>(k))))
    .filter((a): a is AuditEntry => !!a)
    .sort((a, b) => a.seq - b.seq);
  let prevHash = "genesis";
  for (const e of all) {
    const expected = sha256Hex(canonical({ ...e, prevHash }));
    if (e.prevHash !== prevHash || e.hash !== expected) {
      return { ok: false, count: all.length, brokenAt: e.seq };
    }
    prevHash = e.hash;
  }
  return { ok: true, count: all.length };
}

// ---- brute-force lockout ----
interface Lock {
  fails: number;
  until: number;
}
const MAX_FAILS = 5;

export async function checkLock(email: string): Promise<number> {
  const l = await kv("lockout").get<Lock>(email.toLowerCase());
  if (l && l.until > Date.now()) return Math.ceil((l.until - Date.now()) / 1000);
  return 0;
}

export async function recordFail(email: string): Promise<void> {
  const k = email.toLowerCase();
  const l = (await kv("lockout").get<Lock>(k)) ?? { fails: 0, until: 0 };
  l.fails += 1;
  if (l.fails >= MAX_FAILS) {
    // escalating lockout: 30s × 2^(extra fails), capped at 15 minutes
    const over = l.fails - MAX_FAILS;
    l.until = Date.now() + Math.min(15 * 60_000, 30_000 * 2 ** over);
  }
  await kv("lockout").set(k, l);
}

export async function clearFails(email: string): Promise<void> {
  await kv("lockout").delete(email.toLowerCase());
}

// ---- just-in-time access requests ----
const requests = () => kv("requests");
const GRANT_TTL_MS = 15 * 60 * 1000;

export async function createRequest(
  user: User,
  resource: Resource,
  reason: string,
): Promise<AccessRequest> {
  const req: AccessRequest = {
    id: newId("r_"),
    userId: user.id,
    userName: user.name,
    resourceId: resource.id,
    resourceName: resource.name,
    reason,
    status: "pending",
    createdAt: Date.now(),
  };
  await requests().set(req.id, req);
  return req;
}

export async function listRequests(): Promise<AccessRequest[]> {
  const keys = await requests().list();
  const all = await Promise.all(keys.map((k) => requests().get<AccessRequest>(k)));
  return all.filter((r): r is AccessRequest => !!r).sort((a, b) => b.createdAt - a.createdAt);
}

export async function decideRequest(
  id: string,
  approve: boolean,
  adminName: string,
): Promise<AccessRequest | null> {
  const r = await requests().get<AccessRequest>(id);
  if (!r || r.status !== "pending") return r ?? null;
  r.status = approve ? "approved" : "denied";
  r.decidedBy = adminName;
  r.decidedAt = Date.now();
  if (approve) r.expiresAt = Date.now() + GRANT_TTL_MS;
  await requests().set(id, r);
  return r;
}

/** Is there a live (approved, unexpired) grant for this user and resource? */
export async function hasActiveGrant(userId: string, resourceId: string): Promise<boolean> {
  const all = await listRequests();
  return all.some(
    (r) =>
      r.userId === userId &&
      r.resourceId === resourceId &&
      r.status === "approved" &&
      (r.expiresAt ?? 0) > Date.now(),
  );
}

export function getResource(id: string): Resource | undefined {
  return RESOURCES.find((r) => r.id === id);
}

// ---- seeding ----
export async function ensureSeed(): Promise<void> {
  if (await meta().get<boolean>("seeded")) return;
  for (const p of PERSONAS) {
    await createUser({
      name: p.name,
      email: p.email,
      role: p.role,
      department: p.department,
      clearance: p.clearance,
      password: DEMO_PASSWORD,
      sandbox: true,
    });
  }
  await meta().set("seeded", true);
}

/** Current TOTP code for a sandbox persona — a demo convenience so anyone can
 *  sign in without enrolling an authenticator. Only ever for sandbox accounts. */
export async function sandboxCode(userId: string): Promise<string | null> {
  const user = await getUser(userId);
  if (!user || !user.sandbox) return null;
  const secret = await getTotpSecret(userId);
  if (!secret) return null;
  const { totpAt } = await import("./totp.ts");
  return totpAt(secret);
}
