// The sample organisation: a handful of resources with real classification and
// compliance labels, plus the built-in sandbox personas used for the demo.
// Keeping this separate from the engine means the catalogue can grow without
// touching the decision logic.

import type { Clearance, Department, Resource, Role } from "./types.ts";

export interface SeedPersona {
  key: string; // stable handle used to build the account
  name: string;
  email: string;
  role: Role;
  department: Department;
  clearance: Clearance;
  blurb: string;
}

/** Built-in personas. Passwords and TOTP secrets are assigned at seed time on
 *  the server; these are only the human-facing attributes. */
export const PERSONAS: SeedPersona[] = [
  {
    key: "admin",
    name: "Nishant Singh",
    email: "admin@tessera.demo",
    role: "admin",
    department: "executive",
    clearance: "restricted",
    blurb: "Security admin. Creates sandbox users and reviews the audit trail.",
  },
  {
    key: "priya",
    name: "Priya Menon",
    email: "priya@tessera.demo",
    role: "member",
    department: "people",
    clearance: "confidential",
    blurb: "People lead. Can see benefits and payroll names, not bank details.",
  },
  {
    key: "rohan",
    name: "Rohan Desai",
    email: "rohan@tessera.demo",
    role: "member",
    department: "finance",
    clearance: "restricted",
    blurb: "Finance. Cleared for payroll in full — on a managed device.",
  },
  {
    key: "meera",
    name: "Meera Iyer",
    email: "meera@tessera.demo",
    role: "member",
    department: "engineering",
    clearance: "internal",
    blurb: "Engineer. Reaches the wiki; blocked from finance and HR data.",
  },
  {
    key: "arjun",
    name: "Arjun Rao",
    email: "arjun@tessera.demo",
    role: "member",
    department: "external",
    clearance: "public",
    blurb: "External vendor. Only the public handbook — nothing internal.",
  },
];

export const RESOURCES: Resource[] = [
  {
    id: "handbook",
    name: "Company handbook",
    kind: "document",
    summary: "Policies, holidays and the code of conduct. Open to everyone.",
    cloud: "on-prem",
    classification: "public",
    departments: [],
    compliance: [],
    requiresManagedDevice: false,
    fields: [
      { label: "Code of conduct", value: "Be kind, be honest, raise concerns early.", minClearance: "public" },
      { label: "Leave policy", value: "24 days annual leave, 12 public holidays.", minClearance: "public" },
    ],
  },
  {
    id: "wiki",
    name: "Engineering wiki",
    kind: "app",
    summary: "Architecture notes, runbooks and on-call rota.",
    cloud: "aws",
    classification: "internal",
    departments: ["engineering", "executive"],
    compliance: ["SOC2"],
    requiresManagedDevice: false,
    fields: [
      { label: "Service catalogue", value: "32 services across 4 domains.", minClearance: "internal" },
      { label: "On-call rota", value: "Primary: Meera. Secondary: unassigned.", minClearance: "internal" },
      { label: "Production credentials vault", value: "vault://prod/* (break-glass only)", minClearance: "restricted" },
    ],
  },
  {
    id: "pipeline",
    name: "Sales pipeline",
    kind: "dataset",
    summary: "Open opportunities, stages and forecast.",
    cloud: "gcp",
    classification: "internal",
    departments: ["sales", "executive"],
    compliance: ["SOC2"],
    requiresManagedDevice: false,
    fields: [
      { label: "Open opportunities", value: "48 deals, ₹6.2 cr weighted.", minClearance: "internal" },
      { label: "Named accounts", value: "Aster, Brindle, Cove, Dune…", minClearance: "confidential" },
    ],
  },
  {
    id: "customers",
    name: "Customer records",
    kind: "dataset",
    summary: "Customer contacts and usage. Personal data under GDPR.",
    cloud: "aws",
    classification: "confidential",
    departments: ["sales", "engineering", "executive"],
    compliance: ["GDPR", "SOC2"],
    requiresManagedDevice: true,
    fields: [
      { label: "Account count", value: "1,284 active accounts.", minClearance: "internal" },
      { label: "Contact emails", value: "ops@aster.example, cfo@brindle.example…", minClearance: "confidential" },
      { label: "Exportable CSV", value: "customers_full.csv (1,284 rows)", minClearance: "restricted" },
    ],
  },
  {
    id: "benefits",
    name: "Benefits & health claims",
    kind: "dataset",
    summary: "Employee health-benefit enrolment and claims. HIPAA-regulated.",
    cloud: "azure",
    classification: "restricted",
    departments: ["people", "executive"],
    compliance: ["HIPAA", "SOC2"],
    requiresManagedDevice: true,
    fields: [
      { label: "Enrolled employees", value: "41 of 44.", minClearance: "confidential" },
      { label: "Open claims", value: "3 claims, 1 under review.", minClearance: "restricted" },
      { label: "Claim details", value: "Diagnosis codes and amounts per employee.", minClearance: "restricted" },
    ],
  },
  {
    id: "payroll",
    name: "Payroll register",
    kind: "dataset",
    summary: "Monthly salary run. Names, amounts and bank details.",
    cloud: "azure",
    classification: "restricted",
    departments: ["finance", "people", "executive"],
    compliance: ["SOC2", "PCI-DSS"],
    requiresManagedDevice: true,
    fields: [
      { label: "Headcount", value: "44 employees.", minClearance: "internal" },
      { label: "Employee names", value: "Full roster with designations.", minClearance: "confidential" },
      { label: "Gross salary", value: "Per-employee monthly gross.", minClearance: "restricted" },
      { label: "Bank accounts", value: "Account and IFSC per employee.", minClearance: "restricted" },
    ],
  },
  {
    id: "board",
    name: "Board deck — Q3",
    kind: "document",
    summary: "Strategy, financials and headcount plan for the board.",
    cloud: "gcp",
    classification: "restricted",
    departments: ["executive"],
    compliance: ["SOC2"],
    requiresManagedDevice: true,
    fields: [
      { label: "Agenda", value: "Strategy, runway, hiring plan.", minClearance: "confidential" },
      { label: "Financials", value: "Revenue, burn and runway figures.", minClearance: "restricted" },
      { label: "M&A discussion", value: "Confidential target shortlist.", minClearance: "restricted" },
    ],
  },
];
