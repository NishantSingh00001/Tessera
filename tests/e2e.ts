// End-to-end exercise of the gateway function: it constructs real Request
// objects and calls the handler, threading the session cookie through, exactly
// as the browser would. Storage falls back to memory, so no Netlify needed.

import { check, eq, report, section } from "./assert.ts";
import handler from "../netlify/functions/api.mts";
import type { Context } from "../shared/types.ts";

const BASE = "https://tessera.test";
const ctx = {} as never;

function cookieFrom(res: Response): string | null {
  const sc = res.headers.get("set-cookie");
  if (!sc) return null;
  return sc.split(";")[0];
}

async function call(
  path: string,
  method: string,
  body?: unknown,
  cookie?: string | null,
): Promise<{ status: number; body: any; res: Response }> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["content-type"] = "application/json";
  if (cookie) headers["cookie"] = cookie;
  const res = await handler(
    new Request(`${BASE}/api/${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
    ctx,
  );
  let parsed: any = null;
  try {
    parsed = await res.clone().json();
  } catch {
    /* ignore */
  }
  return { status: res.status, body: parsed, res };
}

const managed: Context = {
  deviceManaged: true,
  diskEncrypted: true,
  osUpToDate: true,
  network: "office",
  authAgeMinutes: 1,
};

async function signIn(email: string, context: Context): Promise<string> {
  const login = await call("login", "POST", { email, password: "Sandbox#2026" });
  const { code } = (await call(`sandbox-code?userId=${login.body.userId}`, "GET")).body;
  const verify = await call("verify", "POST", { userId: login.body.userId, code, context });
  return cookieFrom(verify.res)!;
}

section("Sign-in: password then TOTP");
{
  const login = await call("login", "POST", { email: "admin@tessera.demo", password: "Sandbox#2026" });
  eq("password step asks for 2FA", login.body.need2fa, true);
  const { code } = (await call(`sandbox-code?userId=${login.body.userId}`, "GET")).body;
  const bad = await call("verify", "POST", { userId: login.body.userId, code: "000000" });
  eq("a wrong TOTP code is rejected", bad.status, 401);
  const verify = await call("verify", "POST", { userId: login.body.userId, code, context: managed });
  eq("correct code signs in", verify.status, 200);
  const cookie = cookieFrom(verify.res);
  check("a session cookie is issued", !!cookie);
  const me = await call("me", "GET", undefined, cookie);
  eq("session resolves to the admin", me.body.user.email, "admin@tessera.demo");
}

section("Brute force: the account locks");
{
  for (let i = 0; i < 5; i++) await call("login", "POST", { email: "rohan@tessera.demo", password: "wrong" });
  const locked = await call("login", "POST", { email: "rohan@tessera.demo", password: "Sandbox#2026" });
  eq("locked out after 5 wrong tries", locked.status, 429);
  await (await import("../netlify/lib/data.ts")).clearFails("rohan@tessera.demo");
}

section("Access decisions through the gate");
{
  const admin = await signIn("admin@tessera.demo", managed);
  const list = await call("resources", "GET", undefined, admin);
  eq("the catalogue lists every resource", list.body.resources.length, 7);

  const ok = await call("access", "POST", { resourceId: "payroll" }, admin);
  eq("admin on a managed device reaches payroll", ok.body.decision.verdict, "allow");
  check("fields are returned on allow", Array.isArray(ok.body.fields));

  const vendor = await signIn("arjun@tessera.demo", managed);
  const denied = await call("access", "POST", { resourceId: "payroll" }, vendor);
  eq("vendor is denied payroll", denied.body.decision.verdict, "deny");
  eq("no fields leak on deny", denied.body.fields, null);
}

section("Step-up re-verification");
{
  const meera = await signIn("meera@tessera.demo", {
    ...managed,
    deviceManaged: false,
    network: "home",
  });
  const first = await call("access", "POST", { resourceId: "wiki" }, meera);
  eq("elevated risk asks for step-up", first.body.decision.verdict, "step-up");
  const login = await call("login", "POST", { email: "meera@tessera.demo", password: "Sandbox#2026" });
  const { code } = (await call(`sandbox-code?userId=${login.body.userId}`, "GET")).body;
  const stepped = await call("stepup", "POST", { resourceId: "wiki", code }, meera);
  eq("access granted after step-up", stepped.body.decision.verdict, "allow");
}

section("Just-in-time access");
{
  const vendor = await signIn("arjun@tessera.demo", managed);
  const req = await call("requests", "POST", { resourceId: "payroll", reason: "quarterly reconciliation" }, vendor);
  eq("request is created pending", req.body.request.status, "pending");

  const admin = await signIn("admin@tessera.demo", managed);
  const decided = await call("requests/decide", "POST", { id: req.body.request.id, approve: true }, admin);
  eq("admin approves the request", decided.body.request.status, "approved");

  const afterGrant = await call("access", "POST", { resourceId: "payroll" }, vendor);
  eq("vendor now reaches payroll under the grant", afterGrant.body.decision.verdict, "allow");
}

section("Audit trail is written and verifiable");
{
  const admin = await signIn("admin@tessera.demo", managed);
  const audit = await call("audit", "GET", undefined, admin);
  check("audit entries exist", audit.body.entries.length > 0);
  const verify = await call("audit/verify", "GET", undefined, admin);
  eq("the hash chain verifies intact", verify.body.ok, true);

  const me = await call("users", "GET", undefined, admin);
  check("admin can list users", me.body.users.length >= 5);
  const vendor = await signIn("arjun@tessera.demo", managed);
  const forbidden = await call("users", "GET", undefined, vendor);
  eq("a member cannot list users", forbidden.status, 403);
}

report();
