import { useEffect, useState } from "react";
import { api } from "../lib/api.ts";
import type { AuditEntry, User } from "../../shared/types.ts";
import { ClearanceBadge, VerdictBadge } from "../components/common.tsx";

const DEPARTMENTS = ["executive", "finance", "people", "engineering", "sales", "external"];
const CLEARANCES = ["public", "internal", "confidential", "restricted"];

function Users() {
  const [users, setUsers] = useState<User[]>([]);
  const [form, setForm] = useState({
    name: "",
    email: "",
    password: "",
    role: "member",
    department: "engineering",
    clearance: "internal",
  });
  const [created, setCreated] = useState<{ otpauth: string; email: string } | null>(null);
  const [err, setErr] = useState("");
  const load = () => api.users().then((r) => setUsers(r.users));
  useEffect(() => {
    load();
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setCreated(null);
    try {
      const r = await api.createUser(form as never);
      setCreated({ otpauth: r.otpauth, email: r.user.email });
      setForm({ ...form, name: "", email: "", password: "" });
      await load();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function remove(id: string) {
    await api.deleteUser(id);
    await load();
  }

  return (
    <div className="grid" style={{ gridTemplateColumns: "1fr", gap: 18 }}>
      <div className="card">
        <strong style={{ display: "block", marginBottom: 12 }}>Create a sandbox user</strong>
        <form onSubmit={submit}>
          <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(160px,1fr))" }}>
            <div className="field">
              <label>Name</label>
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </div>
            <div className="field">
              <label>Email</label>
              <input value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} required />
            </div>
            <div className="field">
              <label>Temporary password</label>
              <input value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required />
            </div>
            <div className="field">
              <label>Role</label>
              <select value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                <option value="member">member</option>
                <option value="admin">admin</option>
              </select>
            </div>
            <div className="field">
              <label>Department</label>
              <select value={form.department} onChange={(e) => setForm({ ...form, department: e.target.value })}>
                {DEPARTMENTS.map((d) => (
                  <option key={d}>{d}</option>
                ))}
              </select>
            </div>
            <div className="field">
              <label>Clearance</label>
              <select value={form.clearance} onChange={(e) => setForm({ ...form, clearance: e.target.value })}>
                {CLEARANCES.map((c) => (
                  <option key={c}>{c}</option>
                ))}
              </select>
            </div>
          </div>
          <button className="btn primary">Create user</button>
          {err && <span style={{ color: "var(--deny)", marginLeft: 12 }}>{err}</span>}
        </form>
        {created && (
          <div className="card" style={{ marginTop: 14, background: "var(--bg-2)" }}>
            <strong className="tiny">User created — enrol their authenticator</strong>
            <p className="muted tiny" style={{ margin: "6px 0" }}>
              This account isn't a sandbox persona, so it has no auto-filled code. Add this TOTP URI to an
              authenticator app for {created.email}:
            </p>
            <code className="mono tiny" style={{ wordBreak: "break-all", color: "var(--accent-bright)" }}>
              {created.otpauth}
            </code>
          </div>
        )}
      </div>

      <div className="card" style={{ overflowX: "auto" }}>
        <strong style={{ display: "block", marginBottom: 12 }}>All users ({users.length})</strong>
        <table className="tbl">
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Department</th>
              <th>Clearance</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.name}</td>
                <td className="muted">{u.email}</td>
                <td>{u.role}</td>
                <td>{u.department}</td>
                <td>
                  <ClearanceBadge level={u.clearance} />
                </td>
                <td>
                  <button className="btn sm danger" onClick={() => remove(u.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [integrity, setIntegrity] = useState<{ ok: boolean; count: number; brokenAt?: number } | null>(null);
  useEffect(() => {
    api.audit().then((r) => setEntries(r.entries));
  }, []);

  async function verify() {
    setIntegrity(await api.verifyAudit());
  }

  return (
    <div className="card" style={{ overflowX: "auto" }}>
      <div className="row spread" style={{ marginBottom: 12 }}>
        <strong>Audit trail — hash-chained</strong>
        <button className="btn sm" onClick={verify}>Verify integrity</button>
      </div>
      {integrity && (
        <p
          className="tiny"
          style={{ color: integrity.ok ? "var(--allow)" : "var(--deny)", marginBottom: 12 }}
        >
          {integrity.ok
            ? `✓ Chain intact across all ${integrity.count} entries — nothing has been altered or removed.`
            : `✕ Chain broken at entry #${integrity.brokenAt}. The log has been tampered with.`}
        </p>
      )}
      <table className="tbl">
        <thead>
          <tr>
            <th>#</th>
            <th>Who</th>
            <th>Resource</th>
            <th>Verdict</th>
            <th>Risk</th>
            <th>Hash</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id}>
              <td className="mono faint">{e.seq}</td>
              <td>{e.userName}</td>
              <td>
                {e.resourceName}
                <div className="muted tiny">{e.reason}</div>
              </td>
              <td>
                <VerdictBadge verdict={e.verdict} />
              </td>
              <td className="mono">{e.risk}</td>
              <td className="mono faint" title={e.hash}>
                {e.hash.slice(0, 10)}…
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Admin() {
  const [tab, setTab] = useState<"users" | "audit">("users");
  return (
    <div>
      <div className="page-head">
        <h1>Admin console</h1>
        <p className="muted">Manage identities and inspect the tamper-evident record of every decision.</p>
      </div>
      <div className="row" style={{ gap: 8, marginBottom: 18 }}>
        <button className={`btn sm ${tab === "users" ? "primary" : "ghost"}`} onClick={() => setTab("users")}>
          Users
        </button>
        <button className={`btn sm ${tab === "audit" ? "primary" : "ghost"}`} onClick={() => setTab("audit")}>
          Audit trail
        </button>
      </div>
      {tab === "users" ? <Users /> : <Audit />}
    </div>
  );
}
