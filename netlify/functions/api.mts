// The Tessera gateway. Every request from the browser enters here and nowhere
// else — the single guarded gate. This function authenticates the caller, runs
// the zero-trust policy engine on each access, records a tamper-evident audit
// entry, and administers users, just-in-time grants and passkeys.

import type { Config, Context as NetlifyContext } from "@netlify/functions";
import {
  bad,
  clearCookie,
  forbidden,
  HttpError,
  json,
  notFound,
  parseCookies,
  readJson,
  SESSION_COOKIE,
  sessionCookie,
  unauthorized,
} from "../lib/http.ts";
import { verifyPassword } from "../lib/crypto.ts";
import { verifyTotp } from "../lib/totp.ts";
import * as data from "../lib/data.ts";
import * as passkeys from "../lib/passkeys.ts";
import { decide, redactFields } from "../../shared/policy.ts";
import { segmentationMatrix, FLOWS, WORKLOADS } from "../../shared/segmentation.ts";
import { RESOURCES } from "../../shared/seed.ts";
import type { Context, Session, User } from "../../shared/types.ts";

export const config: Config = { path: "/api/*" };

const DEFAULT_CONTEXT: Context = {
  deviceManaged: false,
  diskEncrypted: true,
  osUpToDate: true,
  network: "home",
  authAgeMinutes: 0,
};

function publicUser(u: User) {
  return u; // User is already the safe shape (no secrets)
}

async function currentSession(req: Request): Promise<Session | null> {
  const token = parseCookies(req)[SESSION_COOKIE];
  return data.getSession(token);
}

async function requireUser(req: Request): Promise<{ session: Session; user: User }> {
  const session = await currentSession(req);
  if (!session) throw unauthorized();
  const user = await data.getUser(session.userId);
  if (!user) throw unauthorized();
  return { session, user };
}

async function requireAdmin(req: Request) {
  const ctx = await requireUser(req);
  if (ctx.user.role !== "admin") throw forbidden("Admin only");
  return ctx;
}

function origin(req: Request) {
  const url = new URL(req.url);
  return { rpID: url.hostname, origin: `${url.protocol}//${url.host}` };
}

export default async (req: Request, _ctx: NetlifyContext): Promise<Response> => {
  await data.ensureSeed();
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const method = req.method.toUpperCase();

  try {
    // ---------------------------------------------------------------- auth
    if (path === "login" && method === "POST") {
      const { email, password } = await readJson<{ email: string; password: string }>(req);
      const wait = await data.checkLock(email || "");
      if (wait > 0) throw new HttpError(429, `Too many attempts. Try again in ${wait}s.`);
      const user = await data.findByEmail(email || "");
      const hash = user ? await data.getPasswordHash(user.id) : null;
      if (!user || !hash || !verifyPassword(password || "", hash)) {
        await data.recordFail(email || "");
        throw unauthorized("Wrong email or password");
      }
      await data.clearFails(email);
      return json({ userId: user.id, name: user.name, sandbox: user.sandbox, need2fa: true });
    }

    if (path === "verify" && method === "POST") {
      const { userId, code, context } = await readJson<{
        userId: string;
        code: string;
        context?: Context;
      }>(req);
      const secret = await data.getTotpSecret(userId);
      const user = await data.getUser(userId);
      if (!secret || !user) throw unauthorized("Start again");
      if (!verifyTotp(secret, code || "")) throw unauthorized("That code didn't match");
      const session = await data.createSession(userId, "mfa", { ...DEFAULT_CONTEXT, ...context });
      return json(
        { user: publicUser(user) },
        200,
        { "set-cookie": sessionCookie(session.token, 30 * 60) },
      );
    }

    if (path === "sandbox-code" && method === "GET") {
      const code = await data.sandboxCode(url.searchParams.get("userId") || "");
      if (!code) throw notFound("Not a sandbox account");
      return json({ code });
    }

    if (path === "logout" && method === "POST") {
      const token = parseCookies(req)[SESSION_COOKIE];
      if (token) await data.endSession(token);
      return json({ ok: true }, 200, { "set-cookie": clearCookie() });
    }

    if (path === "me" && method === "GET") {
      const session = await currentSession(req);
      if (!session) return json({ user: null });
      const user = await data.getUser(session.userId);
      if (!user) return json({ user: null });
      return json({
        user: publicUser(user),
        assurance: session.assurance,
        context: session.context,
        hasPasskey: await passkeys.has(user.id),
      });
    }

    if (path === "context" && method === "POST") {
      const { session } = await requireUser(req);
      const { context } = await readJson<{ context: Context }>(req);
      session.context = { ...session.context, ...context };
      await data.updateSession(session);
      return json({ context: session.context });
    }

    // ------------------------------------------------------------- passkeys
    if (path === "passkey/register/options" && method === "POST") {
      const { user } = await requireUser(req);
      const options = await passkeys.registrationOptions(user, origin(req).rpID);
      return json(options);
    }
    if (path === "passkey/register/verify" && method === "POST") {
      const { user } = await requireUser(req);
      const body = await readJson<{ response: unknown }>(req);
      const { rpID, origin: o } = origin(req);
      const ok = await passkeys.verifyRegistration(user.id, body.response, rpID, o);
      return json({ ok });
    }
    if (path === "passkey/login/options" && method === "POST") {
      const { email } = await readJson<{ email: string }>(req);
      const user = await data.findByEmail(email || "");
      if (!user) throw unauthorized("No such account");
      const options = await passkeys.authenticationOptions(user.id, origin(req).rpID);
      return json({ userId: user.id, options });
    }
    if (path === "passkey/login/verify" && method === "POST") {
      const { userId, response, context } = await readJson<{
        userId: string;
        response: unknown;
        context?: Context;
      }>(req);
      const user = await data.getUser(userId);
      if (!user) throw unauthorized("No such account");
      const { rpID, origin: o } = origin(req);
      const ok = await passkeys.verifyAuthentication(userId, response, rpID, o);
      if (!ok) throw unauthorized("Passkey verification failed");
      const session = await data.createSession(userId, "passkey", { ...DEFAULT_CONTEXT, ...context });
      return json({ user: publicUser(user) }, 200, {
        "set-cookie": sessionCookie(session.token, 30 * 60),
      });
    }

    // ------------------------------------------------------------ resources
    if (path === "resources" && method === "GET") {
      const { user } = await requireUser(req);
      const list = await Promise.all(
        RESOURCES.map(async (r) => ({
          id: r.id,
          name: r.name,
          kind: r.kind,
          summary: r.summary,
          cloud: r.cloud,
          classification: r.classification,
          departments: r.departments,
          compliance: r.compliance,
          requiresManagedDevice: r.requiresManagedDevice,
          hasGrant: await data.hasActiveGrant(user.id, r.id),
        })),
      );
      return json({ resources: list });
    }

    if (path === "access" && method === "POST") {
      const { session, user } = await requireUser(req);
      const { resourceId } = await readJson<{ resourceId: string }>(req);
      const resource = data.getResource(resourceId);
      if (!resource) throw notFound("No such resource");
      const grant = await data.hasActiveGrant(user.id, resource.id);
      const decision = decide({ user, assurance: session.assurance, context: session.context, resource, grant });
      await data.appendAudit({
        userId: user.id,
        userName: user.name,
        resourceId: resource.id,
        resourceName: resource.name,
        verdict: decision.verdict,
        reason: decision.reason,
        risk: decision.risk,
        context: session.context,
      });
      const fields = decision.verdict === "allow" ? redactFields(user, resource, grant) : null;
      return json({ decision, fields });
    }

    if (path === "stepup" && method === "POST") {
      const { session, user } = await requireUser(req);
      const { resourceId, code } = await readJson<{ resourceId: string; code: string }>(req);
      const resource = data.getResource(resourceId);
      if (!resource) throw notFound("No such resource");
      const secret = await data.getTotpSecret(user.id);
      if (!secret || !verifyTotp(secret, code || "")) throw unauthorized("Step-up code didn't match");
      session.context = { ...session.context, authAgeMinutes: 0 };
      await data.updateSession(session);
      const grant = await data.hasActiveGrant(user.id, resource.id);
      const decision = decide({
        user,
        assurance: session.assurance,
        context: session.context,
        resource,
        grant,
        stepUp: true,
      });
      await data.appendAudit({
        userId: user.id,
        userName: user.name,
        resourceId: resource.id,
        resourceName: resource.name,
        verdict: decision.verdict,
        reason: `after step-up: ${decision.reason}`,
        risk: decision.risk,
        context: session.context,
      });
      const fields = decision.verdict === "allow" ? redactFields(user, resource, grant) : null;
      return json({ decision, fields });
    }

    // --------------------------------------------------------- segmentation
    if (path === "segmentation" && method === "GET") {
      await requireUser(req);
      return json({ workloads: WORKLOADS, flows: FLOWS, matrix: segmentationMatrix() });
    }

    // ------------------------------------------------------- JIT requests
    if (path === "requests" && method === "GET") {
      const { user } = await requireUser(req);
      const all = await data.listRequests();
      return json({ requests: user.role === "admin" ? all : all.filter((r) => r.userId === user.id) });
    }
    if (path === "requests" && method === "POST") {
      const { user } = await requireUser(req);
      const { resourceId, reason } = await readJson<{ resourceId: string; reason: string }>(req);
      const resource = data.getResource(resourceId);
      if (!resource) throw notFound("No such resource");
      const r = await data.createRequest(user, resource, reason || "(no reason given)");
      return json({ request: r });
    }
    if (path === "requests/decide" && method === "POST") {
      const { user } = await requireAdmin(req);
      const { id, approve } = await readJson<{ id: string; approve: boolean }>(req);
      const r = await data.decideRequest(id, !!approve, user.name);
      if (!r) throw notFound("No such request");
      return json({ request: r });
    }

    // ------------------------------------------------------------- admin
    if (path === "users" && method === "GET") {
      await requireAdmin(req);
      return json({ users: await data.listUsers() });
    }
    if (path === "users" && method === "POST") {
      await requireAdmin(req);
      const body = await readJson<data.NewUser>(req);
      if (!body.name || !body.email || !body.password) throw bad("Name, email and password are required");
      if (await data.findByEmail(body.email)) throw bad("That email already exists");
      const { user, otpauth } = await data.createUser({ ...body, sandbox: false });
      return json({ user, otpauth });
    }
    if (path.startsWith("users/") && method === "DELETE") {
      const { user: admin } = await requireAdmin(req);
      const id = path.slice("users/".length);
      if (id === admin.id) throw bad("You can't delete your own account");
      await data.deleteUser(id);
      return json({ ok: true });
    }

    if (path === "audit" && method === "GET") {
      await requireAdmin(req);
      return json({ entries: await data.listAudit() });
    }
    if (path === "audit/verify" && method === "GET") {
      await requireAdmin(req);
      return json(await data.verifyAuditChain());
    }

    throw notFound("Unknown route");
  } catch (err) {
    if (err instanceof HttpError) return json({ error: err.message }, err.status);
    console.error(err);
    return json({ error: "Something went wrong" }, 500);
  }
};
