import type { Clearance, Decision, ElementResult, Verdict } from "../../shared/types.ts";

const CLR_LABEL: Record<string, string> = {
  public: "Public",
  internal: "Internal",
  confidential: "Confidential",
  restricted: "Restricted",
};

export function ClearanceBadge({ level }: { level: Clearance | string }) {
  return (
    <span className={`badge clr-${level}`}>
      <span className="dot" />
      {CLR_LABEL[level] ?? level}
    </span>
  );
}

export function CloudTag({ cloud }: { cloud: string }) {
  const label = cloud === "on-prem" ? "On-prem" : cloud.toUpperCase();
  return <span className="badge mono">{label}</span>;
}

export function ComplianceTags({ items }: { items: string[] }) {
  if (!items.length) return null;
  return (
    <span className="row wrap" style={{ gap: 6 }}>
      {items.map((c) => (
        <span key={c} className="badge" style={{ fontSize: 11 }}>
          {c}
        </span>
      ))}
    </span>
  );
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  const label = verdict === "allow" ? "Allowed" : verdict === "step-up" ? "Step-up" : "Denied";
  const icon = verdict === "allow" ? "✓" : verdict === "step-up" ? "↑" : "✕";
  return (
    <span className={`verdict ${verdict}`}>
      <span aria-hidden>{icon}</span>
      {label}
    </span>
  );
}

const STATUS_COLOR: Record<string, string> = {
  pass: "var(--allow)",
  caution: "var(--stepup)",
  fail: "var(--deny)",
};

export function ElementRow({ el, index, show }: { el: ElementResult; index: number; show: boolean }) {
  return (
    <div className={`trace-row ${show ? "in" : ""}`} style={{ transitionDelay: `${index * 90}ms` }}>
      <div className="trace-rail">
        <span className="trace-node" style={{ background: STATUS_COLOR[el.status] }} />
      </div>
      <div className="trace-body">
        <div className="row spread" style={{ gap: 10 }}>
          <strong className="trace-title">
            <span className="mono faint" style={{ marginRight: 8 }}>
              {String(index + 1).padStart(2, "0")}
            </span>
            {el.title}
          </strong>
          <span className="mono tiny" style={{ color: STATUS_COLOR[el.status] }}>
            {el.status}
          </span>
        </div>
        <div className="muted tiny">{el.detail}</div>
      </div>
    </div>
  );
}

export function Trace({ decision, show }: { decision: Decision; show: boolean }) {
  return (
    <div className="trace">
      {decision.elements.map((el, i) => (
        <ElementRow key={el.id} el={el} index={i} show={show} />
      ))}
    </div>
  );
}

export function RiskMeter({ value }: { value: number }) {
  const color = value >= 60 ? "var(--deny)" : value >= 30 ? "var(--stepup)" : "var(--allow)";
  return (
    <div className="risk">
      <div className="row spread tiny muted">
        <span>Session risk</span>
        <span className="mono" style={{ color }}>
          {value}/100
        </span>
      </div>
      <div className="risk-track">
        <div className="risk-fill" style={{ width: `${value}%`, background: color }} />
      </div>
    </div>
  );
}
