// East-West microsegmentation (Zscaler EDU-240, "Secure East-West Traffic").
//
// North-South access — a user reaching an app — is handled by the policy engine.
// This models the other half: which workloads may talk to which, inside the
// cloud. The posture is default-deny, so a workload can only reach the specific
// peers it is explicitly allowed to. That is what "minimise the attack surface"
// means in practice: a foothold on one workload cannot pivot to another unless a
// flow was declared.

import type { Cloud } from "./types.ts";

export interface Workload {
  id: string;
  name: string;
  cloud: Cloud;
  tier: "edge" | "service" | "data" | "platform";
}

export interface Flow {
  from: string;
  to: string;
  protocol: string;
  why: string;
}

export const WORKLOADS: Workload[] = [
  { id: "edge", name: "Edge / web", cloud: "aws", tier: "edge" },
  { id: "api", name: "API service", cloud: "aws", tier: "service" },
  { id: "auth", name: "Auth service", cloud: "aws", tier: "service" },
  { id: "payroll-svc", name: "Payroll service", cloud: "azure", tier: "service" },
  { id: "customer-db", name: "Customer DB", cloud: "aws", tier: "data" },
  { id: "payroll-db", name: "Payroll DB", cloud: "azure", tier: "data" },
  { id: "logging", name: "Audit log sink", cloud: "gcp", tier: "platform" },
];

/** The only flows that are permitted. Everything else is denied by default. */
export const FLOWS: Flow[] = [
  { from: "edge", to: "api", protocol: "HTTPS", why: "User requests enter through the edge only." },
  { from: "api", to: "auth", protocol: "gRPC", why: "The API verifies every request with the auth service." },
  { from: "api", to: "customer-db", protocol: "TLS/5432", why: "The API reads customer records." },
  { from: "payroll-svc", to: "payroll-db", protocol: "TLS/5432", why: "Only the payroll service touches payroll data." },
  { from: "api", to: "payroll-svc", protocol: "mTLS", why: "Payroll requests are brokered through its own service." },
  { from: "api", to: "logging", protocol: "HTTPS", why: "Services ship audit events to the log sink." },
  { from: "auth", to: "logging", protocol: "HTTPS", why: "Auth ships sign-in events to the log sink." },
  { from: "payroll-svc", to: "logging", protocol: "HTTPS", why: "Payroll ships access events to the log sink." },
];

const allowed = new Set(FLOWS.map((f) => `${f.from}->${f.to}`));

export function canFlow(from: string, to: string): boolean {
  if (from === to) return true; // a workload talking to itself isn't a cross-flow
  return allowed.has(`${from}->${to}`);
}

export function flowReason(from: string, to: string): string {
  if (from === to) return "Same workload.";
  const f = FLOWS.find((x) => x.from === from && x.to === to);
  if (f) return `Allowed (${f.protocol}): ${f.why}`;
  return "Denied by default. No flow was declared between these workloads.";
}

/** A full source×destination matrix for display. */
export function segmentationMatrix() {
  return WORKLOADS.map((src) => ({
    from: src,
    cells: WORKLOADS.map((dst) => ({
      to: dst,
      allowed: src.id === dst.id ? null : canFlow(src.id, dst.id),
    })),
  }));
}
