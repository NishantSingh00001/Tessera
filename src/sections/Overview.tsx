import { useEffect, useState } from "react";
import { api, type Me } from "../lib/api.ts";
import { registerPasskey } from "../lib/passkey.ts";
import { ClearanceBadge } from "../components/common.tsx";

export function Overview({ me, refreshMe, go }: { me: Me; refreshMe: () => Promise<void>; go: (v: string) => void }) {
  const u = me.user!;
  const [counts, setCounts] = useState({ resources: 0, pending: 0, grants: 0 });
  const [pkMsg, setPkMsg] = useState("");

  useEffect(() => {
    (async () => {
      const [{ resources }, { requests }] = await Promise.all([api.resources(), api.requests()]);
      setCounts({
        resources: resources.length,
        grants: resources.filter((r) => r.hasGrant).length,
        pending: requests.filter((r) => r.status === "pending").length,
      });
    })();
  }, []);

  async function addPasskey() {
    setPkMsg("");
    try {
      const ok = await registerPasskey();
      setPkMsg(ok ? "Passkey registered — you can use it to sign in next time." : "Couldn't register the passkey.");
      await refreshMe();
    } catch (e) {
      setPkMsg((e as Error).message || "Passkey registration failed.");
    }
  }

  return (
    <div>
      <div className="page-head">
        <h1>Welcome, {u.name.split(" ")[0]}</h1>
        <p className="muted">
          You're signed in through the gate. Here's your standing, and where to go next.
        </p>
      </div>

      <div className="card pad-lg" style={{ marginBottom: 18 }}>
        <div className="row spread wrap" style={{ gap: 16 }}>
          <div>
            <div className="eyebrow">IDENTITY</div>
            <h2 style={{ fontSize: 22, margin: "6px 0" }}>{u.name}</h2>
            <div className="muted">{u.email}</div>
          </div>
          <div className="row wrap" style={{ gap: 10 }}>
            <span className="badge">{u.role}</span>
            <span className="badge">{u.department}</span>
            <ClearanceBadge level={u.clearance} />
            <span className="badge" style={{ color: "var(--accent-bright)" }}>
              auth: {me.assurance}
            </span>
          </div>
        </div>
      </div>

      <div className="grid tiles" style={{ marginBottom: 18 }}>
        <div className="tile">
          <div className="n">{counts.resources}</div>
          <div className="l">Resources behind the gate</div>
        </div>
        <div className="tile">
          <div className="n" style={{ textTransform: "capitalize" }}>{u.clearance}</div>
          <div className="l">Your clearance ceiling</div>
        </div>
        <div className="tile">
          <div className="n">{counts.grants}</div>
          <div className="l">Active JIT grants</div>
        </div>
        <div className="tile">
          <div className="n">{counts.pending}</div>
          <div className="l">Pending access requests</div>
        </div>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(260px,1fr))" }}>
        <div className="card">
          <strong>Try the gate</strong>
          <p className="muted tiny" style={{ margin: "6px 0 12px" }}>
            Open the workspace, toggle your device posture, and watch a decision get made element by
            element. Switch to a managed/unmanaged device and the same request can flip.
          </p>
          <button className="btn primary sm" onClick={() => go("workspace")}>Go to workspace</button>
        </div>
        <div className="card">
          <strong>Add a passkey</strong>
          <p className="muted tiny" style={{ margin: "6px 0 12px" }}>
            {me.hasPasskey
              ? "You already have a passkey registered on this account."
              : "Register a phishing-resistant passkey on this device for your strongest sign-in."}
          </p>
          <button className="btn sm" onClick={addPasskey} disabled={me.hasPasskey}>
            {me.hasPasskey ? "Passkey active" : "Register a passkey"}
          </button>
          {pkMsg && <p className="tiny" style={{ marginTop: 8, color: "var(--accent-bright)" }}>{pkMsg}</p>}
        </div>
        {u.role === "admin" && (
          <div className="card">
            <strong>Admin</strong>
            <p className="muted tiny" style={{ margin: "6px 0 12px" }}>
              Create sandbox users, approve access requests, and verify the audit chain's integrity.
            </p>
            <button className="btn sm" onClick={() => go("admin")}>Open admin console</button>
          </div>
        )}
      </div>
    </div>
  );
}
