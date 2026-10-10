import { useState, type FormEvent } from "react";
import { Activity, ArrowRight, Eye, EyeOff, LockKeyhole, Shield, ShieldCheck } from "lucide-react";
import "./login.css";
import { DEMO_MODE } from "../../config";
import { ApiError, safeMessage } from "../../services/api/client";

type Props = {
  onLogin: (email: string, password: string) => Promise<void>;
  onSignUp: (name: string, email: string, password: string) => Promise<void>;
};

export default function LoginPage({ onLogin, onSignUp }: Props) {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [busy, setBusy] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError("");
    if (mode === "signup" && password.length < 12) {
      setError("Use a password with at least 12 characters.");
      return;
    }
    if (mode === "signup" && password !== confirmPassword) {
      setError("Your passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      if (mode === "signup") await onSignUp(name.trim(), email.trim(), password);
      else await onLogin(email.trim(), password);
    } catch (cause) {
      setError(cause instanceof ApiError && cause.status === 401
        ? "Invalid email or password."
        : safeMessage(cause));
    } finally {
      setBusy(false);
    }
  }

  const signup = mode === "signup";
  return (
    <main className="login-shell">
      <div className="login-brand">
        <div className="brand-mark"><Shield size={20} fill="currentColor" /></div>
        <span className="login-brand-name">model<span>shield</span><small>MODEL SECURITY PLATFORM</small></span>
      </div>
      <div className="auth-stage">
        <section className="auth-intro" aria-label="ModelShield security platform">
          <div className="auth-orbit" aria-hidden="true">
            <i className="orbit orbit-one" /><i className="orbit orbit-two" />
            <span className="orbit-core"><ShieldCheck size={34} /></span>
            <i className="orbit-point point-one" /><i className="orbit-point point-two" />
            <i className="orbit-point point-three" />
          </div>
          <div className="auth-intro-copy">
            <span className="auth-live"><i /> MODEL TRUST CENTER</span>
            <h2>Confidence in every model you ship.</h2>
            <p>One secure workspace for artifact intelligence, evidence, and release decisions.</p>
          </div>
          <div className="auth-signals">
            <div><Activity size={16} /><span><b>Continuous oversight</b><small>From intake to release</small></span></div>
            <div><ShieldCheck size={16} /><span><b>Evidence you can trust</b><small>Traceable by design</small></span></div>
          </div>
          <span className="auth-coordinate">MS / TRUST SYSTEM 01</span>
        </section>
        <section className="login-card">
        <div className="login-icon">{signup ? <ShieldCheck size={20} /> : <LockKeyhole size={20} />}</div>
        <div className="login-kicker">SECURE MODEL GOVERNANCE</div>
        <h1>{signup ? "Create your account" : "Welcome back"}</h1>
        <p>{signup ? "Set up your ModelShield workspace account." : "Sign in to your ModelShield workspace."}</p>
        {DEMO_MODE && <p className="demo-banner">Demo mode: account details stay in this browser session and are not sent to a server.</p>}
        <form onSubmit={submit}>
          {signup && <>
            <label htmlFor="name">Full name</label>
            <input id="name" required minLength={2} maxLength={100} disabled={busy} autoComplete="name" placeholder="Your name" value={name} onChange={(e) => setName(e.target.value)} />
          </>}
          <label htmlFor="email">Work email</label>
          <input id="email" required disabled={busy} type="email" autoComplete="email" placeholder="you@company.com" value={email} onChange={(e) => setEmail(e.target.value)} />
          <div className="password-label">
            <label htmlFor="password">Password</label>
            {signup ? <span className="password-hint">At least 12 characters</span> : <button type="button" onClick={() => setError("Contact your workspace administrator to reset your password.")}>Forgot password?</button>}
          </div>
          <div className="password-field">
            <input id="password" required minLength={signup ? 12 : undefined} disabled={busy} type={showPassword ? "text" : "password"} autoComplete={signup ? "new-password" : "current-password"} placeholder={signup ? "Create a password" : "Enter your password"} value={password} onChange={(e) => setPassword(e.target.value)} />
            <button type="button" aria-label={showPassword ? "Hide password" : "Show password"} onClick={() => setShowPassword((v) => !v)}>{showPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button>
          </div>
          {signup && <>
            <label htmlFor="confirm-password">Confirm password</label>
            <input id="confirm-password" required disabled={busy} type={showPassword ? "text" : "password"} autoComplete="new-password" placeholder="Re-enter your password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} />
          </>}
          {error && <div className="login-error" role="alert">{error}</div>}
          <button className="btn primary login-submit" type="submit" disabled={busy}>
            {busy ? (signup ? "Creating account..." : "Signing in...") : (signup ? "Create account" : "Sign in")} <ArrowRight size={15} />
          </button>
        </form>
        <div className="login-switch">
          {signup ? "Already have an account?" : "New to ModelShield?"}{" "}
          <button type="button" disabled={busy} onClick={() => { setMode(signup ? "login" : "signup"); setError(""); }}>
            {signup ? "Sign in" : "Create an account"}
          </button>
        </div>
        <div className="login-trust"><ShieldCheck size={14} /> {signup ? "Your account is created securely" : "Use your workspace credentials"}</div>
        </section>
      </div>
      <footer className="login-footer"><span>© 2026 ModelShield</span><span>Privacy</span><span>Help</span></footer>
    </main>
  );
}
