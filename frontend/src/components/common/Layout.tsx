import { useEffect, useState, type ReactNode } from "react";
import {
  Box,
  ChevronRight,
  Fingerprint,
  LayoutDashboard,
  LogOut,
  Menu,
  Shield,
  UploadCloud,
  X,
} from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { DEMO_MODE } from "../../config";
import { artifactUrl, go, type Route } from "../../routes";
import { safeMessage } from "../../services/api/client";
export default function Layout({
  route,
  count,
  children,
}: {
  route: Route;
  count: number;
  children: ReactNode;
}) {
  const { user, signOut } = useAuth();
  const [mobile, setMobile] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setMobile(false);
    setError("");
  }, [route.page, route.id, route.tab]);
  useEffect(() => {
    if (!mobile) return;
    const close = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobile(false);
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, [mobile]);
  const artifactActive = ["artifacts", "detail", "upload", "security"].includes(
    route.page,
  );
  const label = route.page === "security" ? route.tab : route.page;
  async function exit() {
    setBusy(true);
    setError("");
    try {
      await signOut();
      go("/login");
    } catch (e) {
      setError(safeMessage(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="app-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(e) => {
          e.preventDefault();
          document.getElementById("main-content")?.focus();
        }}
      >
        Skip to content
      </a>
      <aside
        className={"sidebar " + (mobile ? "mobile-open" : "")}
        aria-label="Workspace navigation"
      >
        <button className="brand" onClick={() => go("/dashboard")}>
          <span className="brand-icon">
            <Shield size={20} />
          </span>
          <span>
            model<span>shield</span>
            <small>MODEL SECURITY PLATFORM</small>
          </span>
        </button>
        <button
          className="mobile-close btn outline"
          aria-label="Close menu"
          onClick={() => setMobile(false)}
        >
          <X size={18} />
        </button>
        <div className="workspace">
          <b>M</b>
          <span>
            ModelShield
            <small>
              {DEMO_MODE
                ? "Demonstration workspace"
                : "Authenticated workspace"}
            </small>
          </span>
        </div>
        <nav>
          <small className="nav-label">WORKSPACE</small>
          <button
            className={route.page === "dashboard" ? "active" : ""}
            aria-current={route.page === "dashboard" ? "page" : undefined}
            onClick={() => go("/dashboard")}
          >
            <LayoutDashboard size={17} />
            Dashboard
          </button>
          <button
            className={artifactActive ? "active" : ""}
            aria-current={artifactActive ? "page" : undefined}
            onClick={() => go("/artifacts")}
          >
            <Box size={17} />
            Artifacts<em>{count}</em>
          </button>
          <button
            className={route.page === "upload" ? "active" : ""}
            onClick={() => go("/artifacts/new")}
          >
            <UploadCloud size={17} />
            Upload artifact
          </button>
          {route.id && (
            <>
              <small className="nav-label secondary">SECURITY ANALYSIS</small>
              {(["findings", "evidence", "graph", "provenance"] as const).map(
                (tab) => (
                  <button
                    key={tab}
                    className={route.tab === tab ? "active" : ""}
                    aria-current={route.tab === tab ? "page" : undefined}
                    onClick={() => go(artifactUrl(route.id!, tab))}
                  >
                    <Fingerprint size={17} />
                    {tab === "graph"
                      ? "Evidence graph"
                      : tab[0].toUpperCase() + tab.slice(1)}
                  </button>
                ),
              )}
            </>
          )}
        </nav>
        <div className="sidebar-bottom">
          {error && (
            <p role="alert" className="form-error">
              {error}
            </p>
          )}
          <button
            className="user-row"
            disabled={busy}
            onClick={exit}
            aria-label="Sign out"
          >
            <span className="avatar">
              {user?.name.slice(0, 2).toUpperCase()}
            </span>
            <b>
              {user?.name}
              <small>{busy ? "Signing out…" : user?.role}</small>
            </b>
            <LogOut size={18} />
          </button>
        </div>
      </aside>
      {mobile && (
        <button
          className="scrim"
          onClick={() => setMobile(false)}
          aria-label="Close navigation"
        />
      )}
      <div className="main-area">
        <header className="topbar">
          <div className="crumb">
            <button
              className="mobile-menu"
              onClick={() => setMobile(true)}
              aria-label="Open navigation"
              aria-expanded={mobile}
            >
              <Menu size={20} />
            </button>
            Workspace
            <ChevronRight size={14} />
            <b>{label?.replace("-", " ")}</b>
          </div>
          <span className="env">{DEMO_MODE ? "DEMO DATA" : "LIVE API"}</span>
        </header>
        <main id="main-content" tabIndex={-1} className="page-body">
          {DEMO_MODE && (
            <p className="demo-banner">
              Demo mode: example records only. Uploaded files are not
              transmitted or scanned.
            </p>
          )}
          {children}
          <footer>
            © 2026 ModelShield
            <span>Artifact intake and security evidence</span>
          </footer>
        </main>
      </div>
      <nav className="mobile-nav" aria-label="Primary navigation">
        <button onClick={() => go("/dashboard")}>
          <LayoutDashboard size={20} />
          <span>Dashboard</span>
        </button>
        <button onClick={() => go("/artifacts")}>
          <Box size={20} />
          <span>Artifacts</span>
        </button>
        <button onClick={() => go("/artifacts/new")}>
          <UploadCloud size={20} />
          <span>Upload</span>
        </button>
        <button disabled={busy} onClick={exit}>
          <LogOut size={20} />
          <span>Sign out</span>
        </button>
      </nav>
    </div>
  );
}
