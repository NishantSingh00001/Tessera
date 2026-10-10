import { check, eq, report, section } from "./assert.ts";
import { base32Encode, hashPassword, verifyPassword } from "../netlify/lib/crypto.ts";
import { totpAt, verifyTotp } from "../netlify/lib/totp.ts";
import { decide, redactFields, scoreRisk } from "../shared/policy.ts";
import { PERSONAS, RESOURCES } from "../shared/seed.ts";
import type { Clearance, Context, Department, Resource, Role, User } from "../shared/types.ts";

function user(p: (typeof PERSONAS)[number]): User {
  return {
    id: p.key,
    name: p.name,
    email: p.email,
    role: p.role as Role,
    department: p.department as Department,
    clearance: p.clearance as Clearance,
    createdAt: 0,
    sandbox: true,
  };
}

const byKey = Object.fromEntries(PERSONAS.map((p) => [p.key, user(p)]));
const res = (id: string): Resource => RESOURCES.find((r) => r.id === id)!;

const trusted: Context = {
  deviceManaged: true,
  diskEncrypted: true,
  osUpToDate: true,
  network: "office",
  authAgeMinutes: 5,
};
const homeUnmanaged: Context = {
  deviceManaged: false,
  diskEncrypted: true,
  osUpToDate: true,
  network: "home",
  authAgeMinutes: 5,
};

section("Risk scoring");
eq("trusted office session is low risk", scoreRisk(trusted), 0);
check("unmanaged + public is high", scoreRisk({ ...trusted, deviceManaged: false, network: "public" }) >= 60);

section("Least privilege: the wrong person is refused");
{
  const d = decide({ user: byKey.arjun, assurance: "mfa", context: trusted, resource: res("payroll") });
  eq("vendor → payroll is denied", d.verdict, "deny");
}
{
  const d = decide({ user: byKey.meera, assurance: "mfa", context: trusted, resource: res("payroll") });
  eq("engineer → payroll is denied (clearance)", d.verdict, "deny");
}
{
  const d = decide({ user: byKey.priya, assurance: "mfa", context: trusted, resource: res("payroll") });
  eq("HR (confidential) → payroll denied (below restricted)", d.verdict, "deny");
}

section("The right person, on a trusted device, is allowed");
{
  const d = decide({ user: byKey.rohan, assurance: "mfa", context: trusted, resource: res("payroll") });
  eq("finance (restricted) → payroll allowed", d.verdict, "allow");
}

section("Data-loss prevention: restricted data needs a managed device");
{
  const d = decide({ user: byKey.rohan, assurance: "mfa", context: homeUnmanaged, resource: res("payroll") });
  eq("finance → payroll on unmanaged device is denied", d.verdict, "deny");
  check("denial cites the managed-device rule", /managed device/i.test(d.reason), d.reason);
}

section("Adaptive step-up on elevated risk / weak auth");
{
  const d = decide({ user: byKey.meera, assurance: "mfa", context: homeUnmanaged, resource: res("wiki") });
  eq("engineer → wiki, unmanaged+home ⇒ step-up", d.verdict, "step-up");
}
{
  const d = decide({ user: byKey.meera, assurance: "password", context: trusted, resource: res("wiki") });
  eq("password-only ⇒ step-up to a second factor", d.verdict, "step-up");
}

section("Field redaction above clearance");
{
  const d = decide({ user: byKey.meera, assurance: "mfa", context: trusted, resource: res("wiki") });
  eq("engineer → wiki allowed", d.verdict, "allow");
  const dataLoss = d.elements.find((e) => e.id === "dataLoss")!;
  eq("but flagged as partial (redaction)", dataLoss.status, "caution");
  const view = redactFields(byKey.meera, res("wiki"));
  const vault = view.find((f) => f.label === "Production credentials vault")!;
  eq("restricted field is redacted for an internal user", vault.redacted, true);
  const rota = view.find((f) => f.label === "On-call rota")!;
  eq("internal field is visible", rota.redacted, false);
}

section("Every element is reported, every time");
for (const r of RESOURCES) {
  const d = decide({ user: byKey.admin, assurance: "passkey", context: trusted, resource: r });
  eq(`${r.id}: seven elements present`, d.elements.length, 7);
}

section("Public resource reaches everyone");
{
  const d = decide({ user: byKey.arjun, assurance: "password", context: homeUnmanaged, resource: res("handbook") });
  check("vendor → handbook is not denied", d.verdict !== "deny", d.verdict);
}

section("East-West microsegmentation is default-deny");
{
  const { canFlow } = await import("../shared/segmentation.ts");
  check("edge → api allowed", canFlow("edge", "api"));
  check("payroll service → payroll DB allowed", canFlow("payroll-svc", "payroll-db"));
  check("edge → payroll DB denied (no declared flow)", !canFlow("edge", "payroll-db"));
  check("customer DB → payroll DB denied (no lateral movement)", !canFlow("customer-db", "payroll-db"));
  check("api → payroll DB denied (must go via payroll service)", !canFlow("api", "payroll-db"));
}

section("Passwords: PBKDF2 round-trip");
{
  const h = hashPassword("correct horse battery staple");
  check("hash is not the plaintext", !h.includes("correct horse"));
  check("right password verifies", verifyPassword("correct horse battery staple", h));
  check("wrong password rejected", !verifyPassword("Tr0ub4dor&3", h));
}

section("TOTP: RFC 6238 SHA-1 test vectors");
{
  // RFC 6238 Appendix B uses the ASCII secret "12345678901234567890".
  const secret = base32Encode(Buffer.from("12345678901234567890"));
  const vectors: Array<[number, string]> = [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
  ];
  for (const [t, code] of vectors) {
    eq(`T=${t}s → ${code}`, totpAt(secret, t * 1000), code);
  }
  check("verify accepts the current code", verifyTotp(secret, totpAt(secret)));
  check("verify rejects a wrong code", !verifyTotp(secret, "000000", 59_000));
}

section("Encryption at rest: AES-256-GCM round-trip + tamper detection");
{
  const { seal, open } = await import("../netlify/lib/aead.ts");
  const sealed = seal("JBSWY3DPEHPK3PXP");
  check("ciphertext hides the plaintext", !sealed.includes("JBSWY3DPEHPK3PXP"));
  eq("decrypts back", open(sealed), "JBSWY3DPEHPK3PXP");
  const tampered = sealed.slice(0, -4) + (sealed.endsWith("AAAA") ? "BBBB" : "AAAA");
  let threw = false;
  try {
    open(tampered);
  } catch {
    threw = true;
  }
  check("tampered ciphertext is rejected", threw);
}

section("Data layer: seeding, audit chain, lockout, JIT");
{
  const data = await import("../netlify/lib/data.ts");
  const { kv } = await import("../netlify/lib/store.ts");
  const { RESOURCES: RES } = await import("../shared/seed.ts");

  await data.ensureSeed();
  const seeded = await data.listUsers();
  eq("seeding creates every persona", seeded.length, PERSONAS.length);
  const admin = await data.findByEmail("admin@tessera.demo");
  check("admin persona exists", !!admin);

  // audit chain
  const mk = (verdict: "allow" | "deny") => ({
    userId: admin!.id,
    userName: admin!.name,
    resourceId: "payroll",
    resourceName: "Payroll register",
    verdict,
    reason: "test",
    risk: 0,
    context: trusted,
  });
  await data.appendAudit(mk("allow"));
  await data.appendAudit(mk("deny"));
  await data.appendAudit(mk("allow"));
  const v1 = await data.verifyAuditChain();
  check("intact chain verifies", v1.ok, v1);
  eq("chain counts all entries", v1.count, 3);

  // tamper: rewrite one entry's reason directly in the store
  const entries = await data.listAudit();
  const victim = entries[1];
  await kv("audit").set(victim.id, { ...victim, reason: "tampered!" });
  const v2 = await data.verifyAuditChain();
  check("tampering is detected", !v2.ok, v2);
  check("break is located at the altered entry", v2.brokenAt === victim.seq, v2);

  // lockout
  await data.clearFails("lock@test.demo");
  for (let i = 0; i < 5; i++) await data.recordFail("lock@test.demo");
  check("account locks after repeated failures", (await data.checkLock("lock@test.demo")) > 0);
  await data.clearFails("lock@test.demo");
  eq("clearing failures lifts the lock", await data.checkLock("lock@test.demo"), 0);

  // JIT grant lets a blocked user through (but not past device rules)
  const arjun = await data.findByEmail("arjun@tessera.demo");
  const payroll = RES.find((r) => r.id === "payroll")!;
  const before = decide({ user: arjun!, assurance: "mfa", context: trusted, resource: payroll });
  eq("vendor denied without a grant", before.verdict, "deny");
  const after = decide({ user: arjun!, assurance: "mfa", context: trusted, resource: payroll, grant: true });
  eq("approved JIT grant lets the vendor in", after.verdict, "allow");
  const stillBlocked = decide({ user: arjun!, assurance: "mfa", context: homeUnmanaged, resource: payroll, grant: true });
  eq("grant still can't bypass the managed-device rule", stillBlocked.verdict, "deny");
}

report();
