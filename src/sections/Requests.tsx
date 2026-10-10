import { useEffect, useState } from "react";
import { api, type Me } from "../lib/api.ts";
import type { AccessRequest } from "../../shared/types.ts";

function since(ms: number) {
  const m = Math.round((Date.now() - ms) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  return `${Math.round(m / 60)}h ago`;
}

export function Requests({ me }: { me: Me }) {
  const isAdmin = me.user?.role === "admin";
  const [reqs, setReqs] = useState<AccessRequest[]>([]);
  const load = () => api.requests().then((r) => setReqs(r.requests));
  useEffect(() => {
    load();
  }, []);

  async function decide(id: string, approve: boolean) {
    await api.decideRequest(id, approve);
    await load();
  }

  return (
    <div>
      <div className="page-head">
        <h1>{isAdmin ? "Access requests" : "My access requests"}</h1>
        <p className="muted">
          {isAdmin
            ? "Just-in-time elevation: approve to grant a 15-minute, resource-scoped bypass of the clearance wall. Device and risk rules still apply during the grant."
            : "Requests you've raised for resources you weren't cleared for. An admin grants them time-boxed."}
        </p>
      </div>

      {reqs.length === 0 ? (
        <div className="card muted">No requests yet. Try opening a resource you're not cleared for in the workspace.</div>
      ) : (
        <div className="card" style={{ overflowX: "auto" }}>
          <table className="tbl">
            <thead>
              <tr>
                {isAdmin && <th>Who</th>}
                <th>Resource</th>
                <th>Reason</th>
                <th>Status</th>
                <th>When</th>
                {isAdmin && <th></th>}
              </tr>
            </thead>
            <tbody>
              {reqs.map((r) => (
                <tr key={r.id}>
                  {isAdmin && <td>{r.userName}</td>}
                  <td>{r.resourceName}</td>
                  <td className="muted">{r.reason}</td>
                  <td>
                    <span
                      className="badge"
                      style={{
                        color:
                          r.status === "approved"
                            ? "var(--allow)"
                            : r.status === "denied"
                              ? "var(--deny)"
                              : "var(--stepup)",
                      }}
                    >
                      {r.status}
                      {r.status === "approved" && r.expiresAt && r.expiresAt > Date.now()
                        ? " · active"
                        : r.status === "approved"
                          ? " · expired"
                          : ""}
                    </span>
                  </td>
                  <td className="muted tiny">{since(r.createdAt)}</td>
                  {isAdmin && (
                    <td>
                      {r.status === "pending" ? (
                        <span className="row" style={{ gap: 6 }}>
                          <button className="btn sm primary" onClick={() => decide(r.id, true)}>Approve</button>
                          <button className="btn sm danger" onClick={() => decide(r.id, false)}>Deny</button>
                        </span>
                      ) : (
                        <span className="muted tiny">by {r.decidedBy}</span>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
