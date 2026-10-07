import { useState } from 'react';
import type { FormEvent } from 'react';
import { ArrowRight, Eye, EyeOff, LockKeyhole, Shield, ShieldCheck } from 'lucide-react';
import './login.css';

export default function LoginPage({ onLogin }: { onLogin: () => void }) {
  const [showPassword, setShowPassword] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  function submit(event: FormEvent) {
    event.preventDefault();
    if (!email.trim() || !password) { setError('Enter your work email and password to continue.'); return; }
    setError('');
    onLogin();
  }
  return <main className="login-shell">
    <div className="login-brand"><div className="brand-mark"><Shield size={20} fill="currentColor" /></div><span className="login-brand-name">model<span>shield</span><small>MODEL SECURITY PLATFORM</small></span></div>
    <section className="login-card"><div className="login-icon"><LockKeyhole size={20} /></div><div className="login-kicker">SECURE MODEL GOVERNANCE</div><h1>Welcome back</h1><p>Sign in to your ModelShield workspace.</p>
      <form onSubmit={submit}><label htmlFor="email">Work email</label><input id="email" type="email" autoComplete="username" placeholder="you@company.com" value={email} onChange={e => setEmail(e.target.value)} /><div className="password-label"><label htmlFor="password">Password</label><button type="button" onClick={() => setError('Contact your workspace administrator to reset your password.')}>Forgot password?</button></div><div className="password-field"><input id="password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" placeholder="Enter your password" value={password} onChange={e => setPassword(e.target.value)} /><button type="button" aria-label={showPassword ? 'Hide password' : 'Show password'} onClick={() => setShowPassword(v => !v)}>{showPassword ? <EyeOff size={16} /> : <Eye size={16} />}</button></div>{error && <div className="login-error">{error}</div>}<button className="btn primary login-submit" type="submit">Sign in <ArrowRight size={15} /></button></form>
      <div className="login-divider"><span />or<span /></div><button className="sso-button" onClick={onLogin}>Continue with SSO</button><div className="login-trust"><ShieldCheck size={14} /> Protected with enterprise-grade security</div></section>
    <footer className="login-footer"><span>© 2026 ModelShield</span><span>Privacy</span><span>Help</span></footer>
  </main>;
}

