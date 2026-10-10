import { useEffect, useState } from "react";
import { api } from "../lib/api.ts";
import type { Flow, Workload } from "../../shared/segmentation.ts";

export function Segmentation() {
  const [workloads, setWorkloads] = useState<Workload[]>([]);
  const [flows, setFlows] = useState<Flow[]>([]);
  const [matrix, setMatrix] = useState<
    { from: Workload; cells: { to: Workload; allowed: boolean | null }[] }[]
  >([]);

  useEffect(() => {
    api.segmentation().then((r) => {
      setWorkloads(r.workloads);
      setFlows(r.flows);
      setMatrix(r.matrix);
    });
  }, []);

  return (
    <div>
      <div className="page-head">
        <h1>East-West segmentation</h1>
        <p className="muted">
          User-to-app access is only half of zero trust. This is the other half: which workloads may
          talk to which, inside the cloud. The posture is default-deny, so a foothold on one workload
          can't pivot to another unless a flow was explicitly declared — that's how the attack surface
          stays small.
        </p>
      </div>

      <div className="card" style={{ overflowX: "auto", marginBottom: 20 }}>
        <strong style={{ display: "block", marginBottom: 12 }}>Allowed flows (source → destination)</strong>
        <table className="matrix">
          <thead>
            <tr>
              <th className="rowh">from ↓ / to →</th>
              {workloads.map((w) => (
                <th key={w.id}>{w.name}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.map((row) => (
              <tr key={row.from.id}>
                <td className="rowh">{row.from.name}</td>
                {row.cells.map((c) => (
                  <td
                    key={c.to.id}
                    className={c.allowed === null ? "cell-self" : c.allowed ? "cell-allow" : "cell-deny"}
                    title={`${row.from.name} → ${c.to.name}`}
                  >
                    {c.allowed === null ? "—" : c.allowed ? "✓" : "·"}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted tiny" style={{ marginTop: 10 }}>
          <span style={{ color: "var(--allow)" }}>✓ allowed</span> &nbsp;·&nbsp; · denied by default
          &nbsp;·&nbsp; — same workload
        </p>
      </div>

      <div className="card">
        <strong style={{ display: "block", marginBottom: 10 }}>Why each flow exists</strong>
        <ul className="flows" style={{ margin: 0, paddingLeft: 18 }}>
          {flows.map((f) => (
            <li key={`${f.from}-${f.to}`} className="tiny">
              <span className="mono" style={{ color: "var(--accent-bright)" }}>
                {f.from} → {f.to}
              </span>{" "}
              <span className="badge" style={{ fontSize: 10 }}>{f.protocol}</span> <span className="muted">{f.why}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
