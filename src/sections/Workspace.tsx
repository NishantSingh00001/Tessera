import { useEffect, useState } from "react";
import { api, type FieldView, type Me, type ResourceMeta } from "../lib/api.ts";
import type { Context, Decision } from "../../shared/types.ts";
import {
  ClearanceBadge,
  CloudTag,
  ComplianceTags,
  RiskMeter,
  Trace,
  VerdictBadge,
} from "../components/common.tsx";

function PostureBar({ me, onChange }: { me: Me; onChange: (c: Context) => void }) {
  const ctx = me.context!;
  const toggle = (patch: Partial<Context>) => onChange({ ...ctx, ...patch });
  const Switch = ({ on, label, onClick }: { on: boolean; label: string; onClick: () => void }) => (
    <button className="toggle" onClick={onClick} type="button">
      <span>{label}</span>
      <span className={`switch ${on ? "on" : ""}`} />
    </button>
  );
  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <div className="row spread" style={{ marginBottom: 12 }}>
        <strong>Your device & connection</strong>
        <span className="muted tiny">these signals feed the policy engine live</span>
      </div>
      <div className="posture">
        <Switch on={ctx.deviceManaged} label="Managed device" onClick={() => toggle({ deviceManaged: !ctx.deviceManaged })} />
        <Switch on={ctx.diskEncrypted} label="Disk encrypted" onClick={() => toggle({ diskEncrypted: !ctx.diskEncrypted })} />
        <Switch on={ctx.osUpToDate} label="OS up to date" onClick={() => toggle({ osUpToDate: !ctx.osUpToDate })} />
        <label className="toggle" style={{ cursor: "default" }}>
          <span>Network</span>
          <select
            value={ctx.network}
            onChange={(e) => toggle({ network: e.target.value as Context["network"] })}
            style={{ width: "auto", padding: "4px 6px" }}
          >
            <option value="office">Office</option>
            <option value="home">Home</option>
            <option value="public">Public Wi-Fi</option>
            <option value="unknown">Unknown</option>
          </select>
        </label>
      </div>
    </div>
  );
}

export function Workspace({ me, refreshMe }: { me: Me; refreshMe: () => Promise<void> }) {
  const [resources, setResources] = useState<ResourceMeta[]>([]);
  const [open, setOpen] = useState<ResourceMeta | null>(null);
  const [decision, setDecision] = useState<Decision | null>(null);
  const [fields, setFields] = useState<FieldView[] | null>(null);
  const [show, setShow] = useState(false);
  const [stepCode, setStepCode] = useState("");
  const [reason, setReason] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => api.resources().then((r) => setResources(r.resources));
  useEffect(() => {
    load();
  }, []);

  async function openResource(r: ResourceMeta) {
    setOpen(r);
    setDecision(null);
    setFields(null);
    setNote("");
    setStepCode("");
    setReason("");
    setShow(false);
    const res = await api.access(r.id);
    setDecision(res.decision);
    setFields(res.fields);
    requestAnimationFrame(() => setShow(true));
    if (res.decision.verdict === "step-up" && me.user?.sandbox) {
      try {
        setStepCode((await api.sandboxCode(me.user.id)).code);
      } catch {
        /* ignore */
      }
    }
  }

  async function doStepUp() {
    if (!open) return;
    setBusy(true);
    setNote("");
    try {
      const res = await api.stepup(open.id, stepCode);
      setShow(false);
      setDecision(res.decision);
      setFields(res.fields);
      requestAnimationFrame(() => setShow(true));
      if (res.decision.verdict !== "allow") setNote("Still blocked — see the trace for why.");
    } catch (e) {
      setNote((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function requestAccess() {
    if (!open) return;
    setBusy(true);
    setNote("");
    try {
      await api.requestAccess(open.id, reason || "Access needed for my work.");
      setNote("Request sent to an admin. You'll get a time-boxed grant once approved.");
    } catch (e) {
      setNote((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function changeContext(c: Context) {
    await api.setContext(c);
    await refreshMe();
    await load();
    if (open) openResource(open);
  }

  return (
    <div>
      <div className="page-head">
        <h1>Workspace</h1>
        <p className="muted">
          Everything you might reach. Open one and the gate decides in real time — the seven-element
          trace shows exactly why.
        </p>
      </div>

      <PostureBar me={me} onChange={changeContext} />

      <div className="grid res-grid">
        {resources.map((r) => (
          <button key={r.id} className="res-card" onClick={() => openResource(r)}>
            <div className="row spread">
              <ClearanceBadge level={r.classification} />
              <CloudTag cloud={r.cloud} />
            </div>
            <div className="res-name">{r.name}</div>
            <div className="muted tiny" style={{ marginBottom: 10 }}>{r.summary}</div>
            <div className="row spread">
              <ComplianceTags items={r.compliance} />
              {r.hasGrant && <span className="badge" style={{ color: "var(--allow)" }}>grant active</span>}
            </div>
          </button>
        ))}
      </div>

      {open && (
        <div className="drawer-scrim" onClick={() => setOpen(null)}>
          <div className="drawer" onClick={(e) => e.stopPropagation()}>
            <div className="row spread" style={{ marginBottom: 6 }}>
              <span className="eyebrow">GATE DECISION</span>
              <button className="btn ghost sm" onClick={() => setOpen(null)}>Close</button>
            </div>
            <h2 style={{ fontSize: 22 }}>{open.name}</h2>
            <div className="row wrap" style={{ gap: 8, margin: "10px 0 18px" }}>
              <ClearanceBadge level={open.classification} />
              <CloudTag cloud={open.cloud} />
              <ComplianceTags items={open.compliance} />
            </div>

            {!decision ? (
              <p className="muted">Evaluating…</p>
            ) : (
              <>
                <div className="row spread" style={{ marginBottom: 14 }}>
                  <VerdictBadge verdict={decision.verdict} />
                  <div style={{ width: 150 }}>
                    <RiskMeter value={decision.risk} />
                  </div>
                </div>

                <Trace decision={decision} show={show} />

                {decision.verdict === "allow" && fields && (
                  <div className="card" style={{ marginTop: 16 }}>
                    <strong style={{ display: "block", marginBottom: 6 }}>Record</strong>
                    {fields.map((f) => (
                      <div className="field-row" key={f.label}>
                        <span className="muted">{f.label}</span>
                        {f.redacted ? (
                          <span className="redacted">redacted · above your clearance</span>
                        ) : (
                          <span style={{ textAlign: "right" }}>{f.value}</span>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {decision.verdict === "step-up" && (
                  <div className="card" style={{ marginTop: 16 }}>
                    <strong>Step-up required</strong>
                    <p className="muted tiny" style={{ margin: "4px 0 10px" }}>
                      Re-verify with your authenticator to continue.
                    </p>
                    <div className="row" style={{ gap: 8 }}>
                      <input
                        value={stepCode}
                        onChange={(e) => setStepCode(e.target.value)}
                        className="mono"
                        maxLength={6}
                        placeholder="000000"
                        style={{ maxWidth: 140, letterSpacing: 4 }}
                      />
                      <button className="btn primary" onClick={doStepUp} disabled={busy}>
                        Verify
                      </button>
                    </div>
                  </div>
                )}

                {decision.verdict === "deny" && (
                  <div className="card" style={{ marginTop: 16 }}>
                    <strong>Request just-in-time access</strong>
                    <p className="muted tiny" style={{ margin: "4px 0 10px" }}>
                      Ask an admin for a temporary, time-boxed grant to this resource.
                    </p>
                    <div className="field">
                      <textarea
                        value={reason}
                        onChange={(e) => setReason(e.target.value)}
                        rows={2}
                        placeholder="Why do you need access?"
                      />
                    </div>
                    <button className="btn" onClick={requestAccess} disabled={busy}>
                      Send request
                    </button>
                  </div>
                )}

                {note && <p className="tiny" style={{ marginTop: 12, color: "var(--accent-bright)" }}>{note}</p>}
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
