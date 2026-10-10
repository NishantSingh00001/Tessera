// The policy engine: the heart of Postern. Given who is asking (an authenticated
// user at some assurance level), the live context of their session, and the
// resource they want, it works through the seven elements of a zero trust
// architecture and returns a single verdict with the reasoning for each element.
//
// This is pure decision logic. It evaluates access; it does not attack, probe, or
// simulate intrusions. Default is deny: access is granted only when every element
// that must pass does.

import {
  type Assurance,
  assuranceRank,
  type Clearance,
  clearanceRank,
  type Context,
  type Decision,
  type ElementResult,
  type Resource,
  type User,
  type Verdict,
} from "./types.ts";

export interface Request {
  user: User;
  assurance: Assurance;
  context: Context;
  resource: Resource;
  /** True once the user has passed an adaptive step-up re-verification. It can
   *  satisfy a weak-auth or elevated-risk hold, but never a hard rule (a managed
   *  device requirement, insufficient clearance, or high risk). */
  stepUp?: boolean;
  /** True when an admin-approved, unexpired just-in-time grant covers this exact
   *  user and resource. It lifts the clearance/department wall for the grant's
   *  lifetime, but device and risk rules still apply. */
  grant?: boolean;
}

/** A rough, explainable risk score from the session context, 0 (none) – 100. */
export function scoreRisk(ctx: Context): number {
  let r = 0;
  if (!ctx.deviceManaged) r += 35;
  if (!ctx.diskEncrypted) r += 15;
  if (!ctx.osUpToDate) r += 20;
  if (ctx.network === "public") r += 25;
  else if (ctx.network === "unknown") r += 30;
  else if (ctx.network === "home") r += 8;
  if (ctx.authAgeMinutes > 720) r += 20;
  else if (ctx.authAgeMinutes > 60) r += 8;
  return Math.min(100, r);
}

const CLEARANCE_LABEL: Record<Clearance, string> = {
  public: "Public",
  internal: "Internal",
  confidential: "Confidential",
  restricted: "Restricted",
};

export function decide(req: Request): Decision {
  const { user, assurance, context: ctx, resource } = req;
  const elements: ElementResult[] = [];
  const risk = scoreRisk(ctx);

  let worst: Verdict = "allow";
  const escalate = (v: Verdict) => {
    // deny beats step-up beats allow
    if (v === "deny") worst = "deny";
    else if (v === "step-up" && worst !== "deny") worst = "step-up";
  };

  // Element 1 — Identity: who is connecting.
  {
    const strong = assuranceRank(assurance) >= assuranceRank("mfa") || !!req.stepUp;
    elements.push({
      id: "identity",
      title: "Verify identity",
      status: strong ? "pass" : "caution",
      detail: strong
        ? `${user.name} is signed in with ${
            assurance === "passkey" ? "a passkey" : req.stepUp ? "a re-verified second factor" : "multi-factor auth"
          }.`
        : `${user.name} is signed in with a password only — weak for sensitive access.`,
    });
  }

  // Element 2 — Context: the device and connection the request arrives on.
  {
    const posture: string[] = [];
    posture.push(ctx.deviceManaged ? "managed device" : "unmanaged device");
    posture.push(ctx.diskEncrypted ? "disk encrypted" : "disk not encrypted");
    posture.push(ctx.osUpToDate ? "OS up to date" : "OS out of date");
    const bad = !ctx.deviceManaged || !ctx.diskEncrypted || !ctx.osUpToDate;
    elements.push({
      id: "context",
      title: "Assess access context",
      status: bad ? "caution" : "pass",
      detail: `${posture.join(", ")}; on the ${ctx.network} network.`,
    });
  }

  // Element 3 — Destination: where the connection is going.
  {
    elements.push({
      id: "destination",
      title: "Identify destination",
      status: "pass",
      detail: `${resource.name} — classified ${CLEARANCE_LABEL[resource.classification]}${
        resource.departments.length ? `, scoped to ${resource.departments.join(", ")}` : ""
      }.`,
    });
  }

  // Element 4 — Risk: adaptive signal from the context.
  {
    const band = risk >= 60 ? "high" : risk >= 30 ? "elevated" : "low";
    elements.push({
      id: "risk",
      title: "Assess risk",
      status: band === "high" ? "fail" : band === "elevated" ? "caution" : "pass",
      detail: `Session risk ${risk}/100 (${band}).`,
    });
  }

  // Element 5 — Prevent compromise: hard device requirements, step-up on risk.
  {
    if (resource.requiresManagedDevice && !ctx.deviceManaged) {
      escalate("deny");
      elements.push({
        id: "compromise",
        title: "Prevent compromise",
        status: "fail",
        detail: `${CLEARANCE_LABEL[resource.classification]} data requires a managed device. This device is unmanaged.`,
      });
    } else if (risk >= 60) {
      escalate("deny");
      elements.push({
        id: "compromise",
        title: "Prevent compromise",
        status: "fail",
        detail: "Session risk is too high to proceed, even with re-verification.",
      });
    } else if (!req.stepUp && (risk >= 30 || assuranceRank(assurance) < assuranceRank("mfa"))) {
      escalate("step-up");
      elements.push({
        id: "compromise",
        title: "Prevent compromise",
        status: "caution",
        detail:
          assuranceRank(assurance) < assuranceRank("mfa")
            ? "Step-up required: re-verify with a second factor before access."
            : "Elevated risk: step-up re-verification required before access.",
      });
    } else {
      elements.push({
        id: "compromise",
        title: "Prevent compromise",
        status: "pass",
        detail: "Device and session meet the bar for this resource.",
      });
    }
  }

  // Element 6 — Prevent data loss: clearance vs classification, redaction.
  {
    const cleared =
      clearanceRank(user.clearance) >= clearanceRank(resource.classification) || !!req.grant;
    const deptOk =
      resource.departments.length === 0 ||
      resource.departments.includes(user.department) ||
      !!req.grant;
    if (!cleared || !deptOk) {
      escalate("deny");
      elements.push({
        id: "dataLoss",
        title: "Prevent data loss",
        status: "fail",
        detail: !cleared
          ? `Clearance ${CLEARANCE_LABEL[user.clearance]} is below the required ${CLEARANCE_LABEL[resource.classification]}.`
          : `${user.department} is outside the departments scoped to this resource.`,
      });
    } else {
      const eff = effectiveClearance(user.clearance, resource.classification, req.grant);
      const redacted = resource.fields.filter(
        (f) => clearanceRank(eff) < clearanceRank(f.minClearance),
      ).length;
      elements.push({
        id: "dataLoss",
        title: "Prevent data loss",
        status: redacted > 0 ? "caution" : "pass",
        detail: req.grant
          ? `Temporary just-in-time grant in effect${redacted > 0 ? `; ${redacted} field(s) still above the grant are redacted.` : "; full record visible for the grant window."}`
          : redacted > 0
            ? `Access granted; ${redacted} field${redacted > 1 ? "s" : ""} above your clearance will be redacted.`
            : "Clearance and scope satisfied; full record visible.",
      });
    }
  }

  // Element 7 — Enforce policy: assemble the final, least-privilege verdict.
  {
    const verdict = worst;
    elements.push({
      id: "policy",
      title: "Enforce policy",
      status: verdict === "allow" ? "pass" : verdict === "step-up" ? "caution" : "fail",
      detail:
        verdict === "allow"
          ? "All elements satisfied. Access granted under least privilege."
          : verdict === "step-up"
            ? "Conditionally allowed once step-up verification succeeds."
            : "One or more elements failed. Access denied by default.",
    });
  }

  return { verdict: worst, reason: summarize(worst, elements), elements, risk };
}

function summarize(verdict: Verdict, elements: ElementResult[]): string {
  if (verdict === "allow") return "Access granted.";
  const failed = elements.find((e) => e.status === "fail");
  if (verdict === "deny") return failed ? `Denied: ${failed.detail}` : "Denied by policy.";
  const caution = elements.find((e) => e.id === "compromise" && e.status === "caution");
  return caution ? `Step-up: ${caution.detail}` : "Step-up verification required.";
}

/** Effective clearance, raising it to the resource's level during a JIT grant. */
export function effectiveClearance(
  base: Clearance,
  resourceClass: Clearance,
  grant?: boolean,
): Clearance {
  if (grant && clearanceRank(resourceClass) > clearanceRank(base)) return resourceClass;
  return base;
}

/** Which fields a user may actually see, with the rest redacted. */
export function redactFields(user: User, resource: Resource, grant?: boolean) {
  const eff = effectiveClearance(user.clearance, resource.classification, grant);
  return resource.fields.map((f) =>
    clearanceRank(eff) >= clearanceRank(f.minClearance)
      ? { label: f.label, value: f.value, redacted: false }
      : { label: f.label, value: null, redacted: true },
  );
}
