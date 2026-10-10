// Core domain types for Postern, shared by the browser and the Netlify functions.
// Everything here is pure data — no I/O — so the policy engine can be unit-tested.

/** Clearance levels, lowest to highest. A subject may reach a resource only if
 *  their clearance is at least the resource's required level. */
export const CLEARANCES = ["public", "internal", "confidential", "restricted"] as const;
export type Clearance = (typeof CLEARANCES)[number];

/** Rank used for comparisons. Higher means more sensitive / more privileged. */
export function clearanceRank(c: Clearance): number {
  return CLEARANCES.indexOf(c);
}

export const DEPARTMENTS = [
  "executive",
  "finance",
  "people", // HR
  "engineering",
  "sales",
  "external", // vendors / contractors
] as const;
export type Department = (typeof DEPARTMENTS)[number];

export const ROLES = ["admin", "member"] as const;
export type Role = (typeof ROLES)[number];

/** How strongly the current session proved who the user is. */
export const ASSURANCE = ["password", "mfa", "passkey"] as const;
export type Assurance = (typeof ASSURANCE)[number];

export function assuranceRank(a: Assurance): number {
  return ASSURANCE.indexOf(a);
}

/** A sandbox user. Secrets never leave the server; this is the safe shape. */
export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  department: Department;
  clearance: Clearance;
  createdAt: number;
  /** True for the built-in demo personas, shown with a convenience code helper. */
  sandbox: boolean;
}

/** Device + connection posture for the current session. In this sandbox these
 *  signals are chosen by the person to explore how the decision changes; in a
 *  real deployment they would come from a device agent and the network. */
export interface Context {
  deviceManaged: boolean; // enrolled, company-managed device
  diskEncrypted: boolean;
  osUpToDate: boolean;
  network: "office" | "home" | "public" | "unknown";
  /** Minutes since the user last actively authenticated. */
  authAgeMinutes: number;
}

export interface Session {
  token: string;
  userId: string;
  assurance: Assurance;
  createdAt: number;
  context: Context;
}

/** A thing a user might try to reach. Fields above the viewer's clearance are
 *  redacted rather than returned. */
export const CLOUDS = ["aws", "azure", "gcp", "on-prem"] as const;
export type Cloud = (typeof CLOUDS)[number];

export interface Resource {
  id: string;
  name: string;
  kind: "app" | "document" | "dataset";
  summary: string;
  /** Which cloud the workload runs in — workload tagging, EDU-240. */
  cloud: Cloud;
  classification: Clearance;
  /** Departments allowed at all; empty means any department. */
  departments: Department[];
  /** Compliance regimes this resource falls under (shown as labels). */
  compliance: Array<"NIST-CSF" | "SOC2" | "HIPAA" | "PCI-DSS" | "GDPR">;
  /** Restricted resources demand a managed device (data-loss prevention). */
  requiresManagedDevice: boolean;
  /** Field-level content; each field has its own minimum clearance. */
  fields: ResourceField[];
}

export interface ResourceField {
  label: string;
  value: string;
  minClearance: Clearance;
}

// ---- The seven elements of a zero trust architecture (Zscaler ZTCA) ----

export const ELEMENTS = [
  "identity", // 1. Who is connecting
  "context", // 2. What is the access context
  "destination", // 3. Where is the connection going
  "risk", // 4. Assess risk (adaptive control)
  "compromise", // 5. Prevent compromise
  "dataLoss", // 6. Prevent data loss
  "policy", // 7. Enforce policy
] as const;
export type ElementId = (typeof ELEMENTS)[number];

export type ElementStatus = "pass" | "caution" | "fail";

export interface ElementResult {
  id: ElementId;
  title: string;
  status: ElementStatus;
  detail: string;
}

export type Verdict = "allow" | "step-up" | "deny";

export interface Decision {
  verdict: Verdict;
  /** One-line summary suitable for the audit log. */
  reason: string;
  elements: ElementResult[];
  /** Risk score 0–100, higher is riskier, for display. */
  risk: number;
}

export interface AuditEntry {
  id: string;
  seq: number;
  at: number;
  userId: string;
  userName: string;
  resourceId: string;
  resourceName: string;
  verdict: Verdict;
  reason: string;
  risk: number;
  context: Context;
  /** Hash chain for tamper-evidence: hash = sha256(prevHash + canonical entry). */
  prevHash: string;
  hash: string;
}

/** A just-in-time elevation: a member asks for access they'd normally be denied,
 *  an admin grants it, and the grant expires on its own. */
export interface AccessRequest {
  id: string;
  userId: string;
  userName: string;
  resourceId: string;
  resourceName: string;
  reason: string;
  status: "pending" | "approved" | "denied";
  createdAt: number;
  decidedBy?: string;
  decidedAt?: number;
  /** When an approved grant stops working. */
  expiresAt?: number;
}
