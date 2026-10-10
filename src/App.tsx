import { useEffect, useState } from "react";
import { api, type Me } from "./lib/api.ts";
import { SignIn } from "./sections/SignIn.tsx";
import { Overview } from "./sections/Overview.tsx";
import { Workspace } from "./sections/Workspace.tsx";
import { Segmentation } from "./sections/Segmentation.tsx";
import { Requests } from "./sections/Requests.tsx";
import { Admin } from "./sections/Admin.tsx";
import { Compliance } from "./sections/Compliance.tsx";
import { Learn } from "./sections/Learn.tsx";

type View = "overview" | "workspace" | "requests" | "segmentation" | "compliance" | "admin" | "learn";

const NAV: { group: string; items: { id: View; label: string; icon: string; admin?: boolean }[] }[] = [
  {
    group: "ACCESS",
    items: [
      { id: "overview", label: "Overview", icon: "◆" },
      { id: "workspace", label: "Workspace", icon: "▤" },
      { id: "requests", label: "Access requests", icon: "⇅" },
    ],
  },
  {
    group: "ARCHITECTURE",
    items: [
      { id: "segmentation", label: "Segmentation", icon: "⊞" },
      { id: "compliance", label: "Compliance", icon: "✓" },
    ],
  },
  {
    group: "OPERATIONS",
    items: [{ id: "admin", label: "Admin console", icon: "⚙", admin: true }],
  },
  {
    group: "LEARN",
    items: [{ id: "learn", label: "How it works", icon: "◇" }],
  },
];

function Mark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden>
      <rect width="32" height="32" rx="7" fill="#121725" stroke="#262f45" />
      <path d="M9 23V13a7 7 0 0 1 14 0v10" fill="none" stroke="#7c83ff" strokeWidth="2.2" />
      <circle cx="16" cy="15" r="2.4" fill="#3dd68c" />
      <rect x="15" y="16.5" width="2" height="5" rx="1" fill="#3dd68c" />
    </svg>
  );
}

export function App() {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [view, setView] = useState<View>("overview");
  const [menu, setMenu] = useState(false);

  const refreshMe = async () => {
    const m = await api.me();
    setMe(m);
  };

  useEffect(() => {
    api
      .me()
      .then(setMe)
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div style={{ display: "grid", placeItems: "center", minHeight: "100vh" }}>
        <span className="muted mono">Loading the gate…</span>
      </div>
    );
  }

  if (!me?.user) {
    return <SignIn onSignedIn={(user) => { setMe({ ...me, user } as Me); refreshMe(); }} />;
  }

  const isAdmin = me.user.role === "admin";
  const go = (v: string) => {
    setView(v as View);
    setMenu(false);
  };

  async function logout() {
    await api.logout();
    setMe({ user: null });
    setView("overview");
  }

  return (
    <div className="shell">
      {menu && <div className="scrim" onClick={() => setMenu(false)} />}
      <aside className={`sidebar ${menu ? "open" : ""}`}>
        <div className="brand">
          <Mark />
          <b>Tessera</b>
        </div>
        {NAV.map((g) => {
          const items = g.items.filter((it) => !it.admin || isAdmin);
          if (!items.length) return null;
          return (
            <div key={g.group}>
              <div className="nav-group">{g.group}</div>
              {items.map((it) => (
                <button
                  key={it.id}
                  className={`nav-item ${view === it.id ? "active" : ""}`}
                  onClick={() => go(it.id)}
                >
                  <span className="ic">{it.icon}</span>
                  {it.label}
                </button>
              ))}
            </div>
          );
        })}
      </aside>

      <div className="main">
        <div className="topbar">
          <button className="btn ghost sm menu-btn" onClick={() => setMenu(true)}>☰ Menu</button>
          <div className="row" style={{ gap: 12, marginLeft: "auto" }}>
            <span className="muted tiny">
              {me.user.name} · <span className="mono">{me.user.clearance}</span>
            </span>
            <button className="btn ghost sm" onClick={logout}>Sign out</button>
          </div>
        </div>
        <div className="content">
          {view === "overview" && <Overview me={me} refreshMe={refreshMe} go={go} />}
          {view === "workspace" && <Workspace me={me} refreshMe={refreshMe} />}
          {view === "requests" && <Requests me={me} />}
          {view === "segmentation" && <Segmentation />}
          {view === "compliance" && <Compliance />}
          {view === "admin" && isAdmin && <Admin />}
          {view === "learn" && <Learn />}
        </div>
      </div>
    </div>
  );
}
