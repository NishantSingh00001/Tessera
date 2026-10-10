const ARCH = [
  ["A request arrives", "Every call from the browser hits one function — the gate. There's no other way in; nothing talks to a resource directly."],
  ["Identity is verified", "The session is resolved from a signed, HttpOnly cookie. Sign-in is password (PBKDF2) + TOTP, or a WebAuthn passkey. Secrets are encrypted at rest with AES-256-GCM."],
  ["The seven elements run", "The policy engine scores identity, context, destination, risk, compromise, data loss and policy — default-deny, least privilege."],
  ["The verdict is enforced", "Allow returns the record with over-clearance fields redacted. Step-up asks for re-verification. Deny returns nothing but an explanation."],
  ["It's written to the ledger", "Every decision appends a hash-chained audit entry, so the record is tamper-evident and verifiable end to end."],
];

type Row = { feature: string; detail: string };
const MAP: { provider: string; items: Row[] }[] = [
  {
    provider: "Zscaler",
    items: [
      { feature: "Seven-element policy engine", detail: "Mastering the Fundamentals of Zero Trust (EDU-104) + Zero Trust Cyber Associate (ZTCA) — identity, context, destination, risk, compromise, data loss, policy." },
      { feature: "The gateway / exchange model", detail: "Zscaler Zero Trust Cloud (EDU-240) — one brokered gate, nothing connects directly." },
      { feature: "Multi-cloud workload tagging", detail: "EDU-240 — resources tagged by cloud (AWS/Azure/GCP) and classification." },
      { feature: "East-West microsegmentation", detail: "EDU-240 Secure East-West Traffic — default-deny flows between workloads." },
      { feature: "Clearance-based redaction & export control", detail: "Data Security / Endpoint DLP (EDU-220/222)." },
      { feature: "Tamper-evident audit & access monitoring", detail: "Security Operations (EDU-250)." },
      { feature: "Secure transport & protocols", detail: "Introduction to Networking for Cyber Professionals (EDU-101) — mTLS/TLS on declared flows." },
      { feature: "The admin console & policy administration", detail: "Zscaler for Users – Administrator (EDU-200)." },
    ],
  },
  {
    provider: "Google Cloud Cybersecurity Certificate",
    items: [
      { feature: "Authentication, authorization, auditing (AAA)", detail: "Course 3, Identify and Protect — the whole spine of Tessera." },
      { feature: "Security lifecycle & least privilege", detail: "Course 1, Security Principles in Cloud Computing." },
      { feature: "Compliance posture (NIST CSF, SOC, HIPAA)", detail: "Course 2, Strategies for Cloud Security Risk Management." },
      { feature: "Logging & alert monitoring", detail: "Course 4, Detect, Respond, Recover — the audit trail and access monitoring." },
      { feature: "End-to-end security analyst workflow", detail: "Course 5, the capstone." },
    ],
  },
  {
    provider: "Fortinet",
    items: [
      { feature: "Access control & secure network architecture", detail: "Certified Fundamentals (FCF) — identity, segmentation, least privilege." },
      { feature: "Threat landscape awareness (design choices)", detail: "FCF — why default-deny and managed-device rules exist." },
    ],
  },
];

const EXTRA = [
  "WebAuthn passkeys (phishing-resistant auth)",
  "Brute-force lockout with escalating backoff",
  "AES-256-GCM encryption at rest",
  "Hash-chained, tamper-evident audit log",
  "Just-in-time, time-boxed access grants",
  "Strict Content-Security-Policy and security headers",
];

export function Learn() {
  return (
    <div>
      <div className="page-head">
        <h1>How it works &amp; what it shows</h1>
        <p className="muted">
          Tessera is a working zero-trust access gateway, built to put the certifications below into
          running code — and to go a step past them.
        </p>
      </div>

      <div className="card pad-lg" style={{ marginBottom: 20 }}>
        <span className="eyebrow">THE PATH OF A REQUEST</span>
        <div style={{ marginTop: 12 }}>
          {ARCH.map((a, i) => (
            <div className="arch-step" key={i}>
              <span className="num">{String(i + 1).padStart(2, "0")}</span>
              <div>
                <strong>{a[0]}</strong>
                <div className="muted tiny">{a[1]}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card pad-lg" style={{ marginBottom: 20 }}>
        <span className="eyebrow">BEYOND THE COURSES</span>
        <p className="muted tiny" style={{ margin: "8px 0 12px" }}>
          Features built to show engineering depth past any single syllabus:
        </p>
        <div className="row wrap" style={{ gap: 8 }}>
          {EXTRA.map((e) => (
            <span key={e} className="badge" style={{ color: "var(--accent-bright)" }}>{e}</span>
          ))}
        </div>
      </div>

      <h2 style={{ fontSize: 20, margin: "26px 0 14px" }}>Course map</h2>
      <div className="grid" style={{ gridTemplateColumns: "1fr" }}>
        {MAP.map((group) => (
          <div className="card" key={group.provider}>
            <strong style={{ display: "block", marginBottom: 6 }}>{group.provider}</strong>
            {group.items.map((it) => (
              <div className="course-item" key={it.feature}>
                <strong className="tiny">{it.feature}</strong>
                <span className="muted tiny">{it.detail}</span>
              </div>
            ))}
          </div>
        ))}
      </div>

      <div className="card" style={{ marginTop: 20 }}>
        <strong>A deliberate boundary</strong>
        <p className="muted tiny" style={{ marginTop: 6 }}>
          Tessera only builds the defences. It doesn't simulate attacks, run intrusions, or set traps
          — the Zscaler Deception course is noted here but intentionally not implemented. The strength
          is shown by the gate holding and refusing the wrong request, not by attacking it.
        </p>
      </div>
    </div>
  );
}
