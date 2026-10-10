import { useEffect, useState } from "react";
import { api, type ResourceMeta } from "../lib/api.ts";

const FRAMEWORKS = ["NIST-CSF", "SOC2", "HIPAA", "PCI-DSS", "GDPR"] as const;

const NOTE: Record<string, string> = {
  "NIST-CSF": "Identify, Protect, Detect, Respond, Recover — the backbone of the risk-management course.",
  SOC2: "Trust-services criteria: security, availability, confidentiality.",
  HIPAA: "Protected health information — strict access and audit duties.",
  "PCI-DSS": "Cardholder and bank data handling controls.",
  GDPR: "Personal-data protection and least-privilege processing.",
};

export function Compliance() {
  const [resources, setResources] = useState<ResourceMeta[]>([]);
  useEffect(() => {
    api.resources().then((r) => setResources(r.resources));
  }, []);

  return (
    <div>
      <div className="page-head">
        <h1>Compliance posture</h1>
        <p className="muted">
          Each protected resource is tagged with the regimes it falls under, so access controls and the
          audit trail can be mapped straight onto the frameworks an auditor asks about.
        </p>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(200px,1fr))", marginBottom: 20 }}>
        {FRAMEWORKS.map((f) => {
          const n = resources.filter((r) => r.compliance.includes(f as never)).length;
          return (
            <div className="tile" key={f}>
              <div className="n">{n}</div>
              <div className="l">
                <strong>{f}</strong>
                <div className="tiny faint">{NOTE[f]}</div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="card" style={{ overflowX: "auto" }}>
        <table className="matrix">
          <thead>
            <tr>
              <th className="rowh">Resource</th>
              {FRAMEWORKS.map((f) => (
                <th key={f}>{f}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {resources.map((r) => (
              <tr key={r.id}>
                <td className="rowh">{r.name}</td>
                {FRAMEWORKS.map((f) => (
                  <td key={f} className={r.compliance.includes(f as never) ? "yes" : "cell-deny"}>
                    {r.compliance.includes(f as never) ? "✓" : "·"}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
