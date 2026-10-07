import { useState } from "react";
import type { FormEvent } from "react";
import {
  ArrowRight,
  Eye,
  EyeOff,
  LockKeyhole,
  Shield,
  ShieldCheck,
} from "lucide-react";
import "./login.css";
import { DEMO_MODE } from "../../config";
import { ApiError, safeMessage } from "../../services/api/client";

export default function LoginPage({
  onLogin,
}: {
  onLogin: (email: string, password: string) => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!email.trim() || !password) {
      setError("Enter your work email and password to continue.");
      return;
    }
    setError("");
    setBusy(true);
    try {
      await onLogin(email.trim(), password);
    } catch (error) {
      setError(error instanceof ApiError && error.status === 401
        ? "Invalid email or password."
        : safeMessage(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <main className="login-shell">
      <div className="login-brand">
        <div className="brand-mark">
          <Shield size={20} fill="currentColor" />
        </div>
        <span className="login-brand-name">
          model<span>shield</span>
          <small>MODEL SECURITY PLATFORM</small>
        </span>
      </div>
      <section className="login-card">
        <div className="login-icon">
          <LockKeyhole size={20} />
        </div>
        <div className="login-kicker">SECURE MODEL GOVERNANCE</div>
        <h1>Welcome back</h1>
        <p>Sign in to your ModelShield workspace.</p>
        {DEMO_MODE && (
          <p className="demo-banner">
            Demo session: credentials are not sent to a server. Use any email
            and password to explore the interface.
          </p>
        )}
        <form onSubmit={submit}>
          <label htmlFor="email">Work email</label>
          <input
            id="email"
            required
            disabled={busy}
            type="email"
            autoComplete="username"
            placeholder="you@company.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <div className="password-label">
            <label htmlFor="password">Password</label>
            <button
              type="button"
              onClick={() =>
                setError(
                  "Contact your workspace administrator to reset your password.",
                )
              }
            >
              Forgot password?
            </button>
          </div>
          <div className="password-field">
            <input
              id="password"
              required
              disabled={busy}
              type={showPassword ? "text" : "password"}
              autoComplete="current-password"
              placeholder="Enter your password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button
              type="button"
              aria-label={showPassword ? "Hide password" : "Show password"}
              onClick={() => setShowPassword((v) => !v)}
            >
              {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>
          {error && (
            <div className="login-error" role="alert">
              {error}
            </div>
          )}
          <button
            className="btn primary login-submit"
            type="submit"
            disabled={busy}
          >
            {busy ? "Signing in…" : "Sign in"} <ArrowRight size={15} />
          </button>
        </form>
        <div className="login-trust">
          <ShieldCheck size={14} /> Use your workspace credentials
        </div>
      </section>
      <footer className="login-footer">
        <span>© 2026 ModelShield</span>
        <span>Privacy</span>
        <span>Help</span>
      </footer>
    </main>
  );
}
