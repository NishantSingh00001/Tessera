import { useState } from "react";
import { api } from "../lib/api.ts";
import { loginWithPasskey } from "../lib/passkey.ts";
import type { Context, User } from "../../shared/types.ts";
import { ClearanceBadge } from "../components/common.tsx";

const PERSONAS = [
  { email: "admin@tessera.demo", name: "Nishant Singh", role: "Security admin", clearance: "restricted", blurb: "Runs the console, creates users, reviews the audit trail." },
  { email: "rohan@tessera.demo", name: "Rohan Desai", role: "Finance", clearance: "restricted", blurb: "Cleared for payroll in full — on a managed device." },
  { email: "priya@tessera.demo", name: "Priya Menon", role: "People / HR", clearance: "confidential", blurb: "Sees benefits and names, not bank details." },
  { email: "meera@tessera.demo", name: "Meera Iyer", role: "Engineering", clearance: "internal", blurb: "Reaches the wiki; blocked from finance and HR." },
  { email: "arjun@tessera.demo", name: "Arjun Rao", role: "External vendor", clearance: "public", blurb: "Only the public handbook — nothing internal." },
];

const DEMO_PASSWORD = "Sandbox#2026";

const SIGNIN_CONTEXT: Context = {
  deviceManaged: true,
  diskEncrypted: true,
  osUpToDate: true,
  network: "office",
  authAgeMinutes: 1,
};

export function SignIn({ onSignedIn }: { onSignedIn: (u: User) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState(DEMO_PASSWORD);
  const [stage, setStage] = useState<"creds" | "2fa">("creds");
  const [userId, setUserId] = useState("");
  const [code, setCode] = useState("");
  const [sandbox, setSandbox] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function pickPersona(pEmail: string) {
    setErr("");
    setEmail(pEmail);
    setPassword(DEMO_PASSWORD);
    setBusy(true);
    try {
      const r = await api.login(pEmail, DEMO_PASSWORD);
      setUserId(r.userId);
      setSandbox(r.sandbox);
      if (r.sandbox) {
        const c = await api.sandboxCode(r.userId);
        setCode(c.code);
      }
      setStage("2fa");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function submitCreds(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      const r = await api.login(email, password);
      setUserId(r.userId);
      setSandbox(r.sandbox);
      if (r.sandbox) setCode((await api.sandboxCode(r.userId)).code);
      setStage("2fa");
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function submitCode(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setBusy(true);
    try {
      const { user } = await api.verify(userId, code, SIGNIN_CONTEXT);
      onSignedIn(user);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function passkey() {
    setErr("");
    if (!email) {
      setErr("Enter your email first, then use your passkey.");
      return;
    }
    setBusy(true);
    try {
      const user = await loginWithPasskey(email, SIGNIN_CONTEXT);
      onSignedIn(user);
    } catch (e) {
      setErr((e as Error).message || "Passkey sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-wrap">
      <div className="auth-hero">
        <span className="eyebrow">ZERO TRUST ACCESS GATEWAY</span>
        <h1>Nothing passes the gate without proving itself.</h1>
        <p className="lead">
          Tessera brokers every request to every app. It checks who you are, the device you're on,
          where you're connecting from and what you're reaching — then allows, challenges, or denies,
          and writes it to a tamper-evident log. This is a live demo; sign in as anyone below.
        </p>
        <svg className="gate-art" viewBox="0 0 420 180" fill="none" aria-hidden>
          <rect x="1" y="1" width="418" height="178" rx="12" fill="#0d121d" stroke="#262f45" />
          <text x="20" y="28" fill="#667089" fontFamily="IBM Plex Mono" fontSize="11">request</text>
          <circle cx="40" cy="92" r="9" fill="#7c83ff" />
          <line x1="52" y1="92" x2="150" y2="92" stroke="#39445f" strokeWidth="2" strokeDasharray="4 4" />
          <rect x="150" y="44" width="120" height="96" rx="10" fill="#121725" stroke="#7c83ff" />
          <text x="210" y="88" fill="#e8ecf6" fontFamily="Archivo" fontWeight="700" fontSize="15" textAnchor="middle">TESSERA</text>
          <text x="210" y="106" fill="#949db8" fontFamily="IBM Plex Mono" fontSize="9" textAnchor="middle">7-element policy</text>
          <line x1="270" y1="70" x2="360" y2="70" stroke="#3dd68c" strokeWidth="2" />
          <text x="372" y="74" fill="#3dd68c" fontFamily="IBM Plex Mono" fontSize="10">allow</text>
          <line x1="270" y1="92" x2="360" y2="92" stroke="#f2b347" strokeWidth="2" />
          <text x="372" y="96" fill="#f2b347" fontFamily="IBM Plex Mono" fontSize="10">step</text>
          <line x1="270" y1="114" x2="360" y2="114" stroke="#fb5e6b" strokeWidth="2" />
          <text x="372" y="118" fill="#fb5e6b" fontFamily="IBM Plex Mono" fontSize="10">deny</text>
        </svg>
      </div>

      <div className="auth-panel">
        {stage === "creds" ? (
          <>
            <h3 style={{ fontSize: 20, marginBottom: 4 }}>Sign in</h3>
            <p className="muted tiny" style={{ marginBottom: 16 }}>
              Pick a sandbox identity to see access from their point of view.
            </p>
            <div style={{ marginBottom: 18 }}>
              {PERSONAS.map((p) => (
                <button key={p.email} className="persona" onClick={() => pickPersona(p.email)} disabled={busy}>
                  <span className="avatar">{p.name[0]}</span>
                  <span style={{ flex: 1 }}>
                    <span className="row spread">
                      <strong style={{ fontSize: 14 }}>{p.name}</strong>
                      <ClearanceBadge level={p.clearance} />
                    </span>
                    <span className="muted tiny">{p.role} — {p.blurb}</span>
                  </span>
                </button>
              ))}
            </div>
            <details>
              <summary className="muted tiny" style={{ cursor: "pointer", marginBottom: 12 }}>
                Or sign in manually
              </summary>
              <form onSubmit={submitCreds}>
                <div className="field">
                  <label>Email</label>
                  <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@tessera.demo" />
                </div>
                <div className="field">
                  <label>Password</label>
                  <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                <div className="row" style={{ gap: 8 }}>
                  <button className="btn primary" disabled={busy}>Continue</button>
                  <button type="button" className="btn ghost" onClick={passkey} disabled={busy}>
                    Use a passkey
                  </button>
                </div>
              </form>
            </details>
            {err && <p style={{ color: "var(--deny)", marginTop: 12 }}>{err}</p>}
          </>
        ) : (
          <form onSubmit={submitCode}>
            <h3 style={{ fontSize: 20, marginBottom: 4 }}>Two-factor verification</h3>
            <p className="muted tiny" style={{ marginBottom: 16 }}>
              Enter the 6-digit code from your authenticator.
              {sandbox && " For this sandbox account it's filled in for you."}
            </p>
            <div className="field">
              <label>Authenticator code</label>
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                className="mono"
                inputMode="numeric"
                maxLength={6}
                style={{ fontSize: 20, letterSpacing: 6 }}
              />
            </div>
            <div className="row" style={{ gap: 8 }}>
              <button className="btn primary" disabled={busy}>Verify & enter</button>
              <button type="button" className="btn ghost" onClick={() => { setStage("creds"); setCode(""); }}>
                Back
              </button>
            </div>
            {err && <p style={{ color: "var(--deny)", marginTop: 12 }}>{err}</p>}
          </form>
        )}
      </div>
    </div>
  );
}
