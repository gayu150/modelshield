import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity, AlertTriangle, ArrowDown, ArrowDownUp, ArrowRight, Bell, Box, Check, ChevronDown, ChevronLeft, ChevronRight, CircleHelp, Clock3, FileKey2, FileText, Fingerprint, LayoutDashboard, LockKeyhole, Menu, MoreHorizontal, Plus, Search, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Sparkles, X } from 'lucide-react';
import type { Artifact, Decision } from './types/artifact';
import LoginPage from './pages/LoginPage';
import { listArtifacts, uploadArtifact } from './services/api/artifacts';

const seed: Artifact[] = [
  { id: 'MOD-0042', name: 'fraud-detection-v3.pkl', model: 'Fraud Detection', version: '3.1.0', format: 'PICKLE', uploadedBy: 'Priya Sharma', uploadedAt: 'Today, 10:24 AM', decision: 'APPROVED', findings: 0, hash: 'a81f93c4…d29b' },
  { id: 'MOD-0041', name: 'customer-churn.onnx', model: 'Customer Churn', version: '2.4.1', format: 'ONNX', uploadedBy: 'Arjun Mehta', uploadedAt: 'Today, 9:12 AM', decision: 'QUARANTINED', findings: 2, hash: '6c0de821…1f44' },
  { id: 'MOD-0040', name: 'recommendation-v2.safetensors', model: 'Recommendations', version: '2.0.0', format: 'SAFETENSORS', uploadedBy: 'Priya Sharma', uploadedAt: 'Yesterday, 4:38 PM', decision: 'CONDITIONAL', findings: 1, hash: '9b7a31f0…c612' },
  { id: 'MOD-0039', name: 'sentiment-analysis.h5', model: 'Sentiment Analysis', version: '1.8.2', format: 'HDF5', uploadedBy: 'Dev Patel', uploadedAt: 'Yesterday, 2:05 PM', decision: 'APPROVED', findings: 0, hash: 'f3028ad1…b095' },
  { id: 'MOD-0038', name: 'legacy-classifier.pth', model: 'Legacy Classifier', version: '1.2.0', format: 'PYTORCH', uploadedBy: 'Maya Iyer', uploadedAt: 'Sep 26, 2026', decision: 'BLOCKED', findings: 4, hash: '1ce4bd69…774a' },
];
const mockMode = import.meta.env.VITE_USE_MOCK_DATA !== 'false';

const nav = [
  { title: 'WORKSPACE', items: [{ label: 'Dashboard', icon: LayoutDashboard }, { label: 'Artifacts', icon: Box, count: '24' }, { label: 'Review queue', icon: ShieldAlert, count: '3' }] },
  { title: 'GOVERNANCE', items: [{ label: 'Policies', icon: FileKey2 }, { label: 'Audit trail', icon: Activity }] },
];

function Badge({ status }: { status: Decision }) {
  const meta: Record<Decision, { icon: typeof Check; label: string }> = {
    APPROVED: { icon: Check, label: 'Approved' }, CONDITIONAL: { icon: AlertTriangle, label: 'Conditional' },
    QUARANTINED: { icon: Clock3, label: 'Quarantined' }, BLOCKED: { icon: X, label: 'Blocked' },
  };
  const Icon = meta[status].icon;
  return <span className={`badge ${status.toLowerCase()}`}><Icon size={13} strokeWidth={2.3} />{meta[status].label}</span>;
}

function App() {
  const [signedIn, setSignedIn] = useState(true);
  const [artifacts, setArtifacts] = useState(seed);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('All statuses');
  const [notice, setNotice] = useState('');
  const [menuOpen, setMenuOpen] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const filtered = useMemo(() => artifacts.filter(a => `${a.name} ${a.model} ${a.id} ${a.uploadedBy}`.toLowerCase().includes(query.toLowerCase()) && (filter === 'All statuses' || a.decision === filter.toUpperCase())), [artifacts, query, filter]);

  useEffect(() => {
    if (mockMode) return;
    let active = true;
    listArtifacts().then(result => { if (active) setArtifacts(result); })
      .catch(() => { if (active) setNotice('Could not load artifacts. Check that the API is running.'); });
    return () => { active = false; };
  }, []);

  if (!signedIn) return <LoginPage onLogin={() => setSignedIn(true)} />;

  async function uploadFiles(files: FileList | null) {
    if (!files?.length) return;
    if (!mockMode) {
      try {
        const uploaded = await Promise.all(Array.from(files, file => uploadArtifact({ file })));
        setArtifacts(prev => [...uploaded, ...prev]);
        setNotice(`${uploaded.length} artifact${uploaded.length === 1 ? '' : 's'} uploaded to quarantine`);
      } catch {
        setNotice('Upload failed. Check the API and try again.');
      }
      return;
    }
    const added = Array.from(files).map((file, index): Artifact => ({ id: `MOD-${String(43 + index).padStart(4, '0')}`, name: file.name, model: file.name.replace(/\.[^.]+$/, '').replace(/[-_]/g, ' '), version: '1.0.0', format: file.name.split('.').pop()?.toUpperCase() ?? 'UNKNOWN', uploadedBy: 'You', uploadedAt: 'Just now', decision: 'QUARANTINED', findings: 0, hash: 'Pending verification' }));
    setArtifacts(prev => [...added, ...prev]);
    setNotice(`${added.length} artifact${added.length === 1 ? '' : 's'} added to quarantine`);
    window.setTimeout(() => setNotice(''), 3600);
  }

  return <div className="app-shell">
    <aside className={`sidebar ${mobileNav ? 'mobile-open' : ''}`}>
      <div className="brand"><div className="brand-mark"><Shield size={20} fill="currentColor" /></div><span>model<span className="brand-light">shield</span></span><button className="mobile-close icon-button" onClick={() => setMobileNav(false)} aria-label="Close menu"><X size={18} /></button></div>
      <div className="org-switch"><div className="org-icon">N</div><div className="org-copy"><strong>Northstar AI</strong><span>Enterprise workspace</span></div><ChevronDown size={15} /></div>
      <nav>{nav.map(group => <div className="nav-group" key={group.title}><div className="nav-title">{group.title}</div>{group.items.map(item => <button key={item.label} className={`nav-item ${item.label === 'Dashboard' ? 'active' : ''}`} onClick={() => item.label !== 'Dashboard' && setNotice(`${item.label} module is ready to connect`)}><item.icon size={17} /><span>{item.label}</span>{item.count && <span className="nav-count">{item.count}</span>}</button>)}</div>)}</nav>
      <div className="sidebar-bottom"><div className="help-card"><div className="help-icon"><CircleHelp size={16} /></div><strong>Need a hand?</strong><span>Visit the help center</span><ArrowRight size={15} className="help-arrow" /></div><button className="profile" onClick={() => setSignedIn(false)} title="Sign out"><div className="avatar">PS</div><span className="profile-copy"><strong>Priya Sharma</strong><small>Security reviewer</small></span><MoreHorizontal size={18} /></button></div>
    </aside>
    {mobileNav && <button className="scrim" onClick={() => setMobileNav(false)} aria-label="Close navigation" />}
    <main className="main-area">
      <header className="topbar"><div className="crumb"><button className="mobile-menu icon-button" onClick={() => setMobileNav(true)} aria-label="Open menu"><Menu size={19} /></button><span>Workspace</span><ChevronRight size={14} /><strong>Dashboard</strong></div><div className="top-actions"><span className="env-pill"><span />Production</span><button className="icon-button notification" aria-label="Notifications" onClick={() => setNotice('You’re all caught up')}><Bell size={18} /><i /></button><div className="top-avatar">PS</div></div></header>
      <div className="content">
        <section className="welcome-row"><div><div className="eyebrow"><Sparkles size={13} /> SECURITY OVERVIEW</div><h1>Good morning, Priya <span>✦</span></h1><p>Here’s what’s happening across your model releases today.</p></div><button className="button primary" onClick={() => inputRef.current?.click()}><Plus size={17} /> Upload artifact</button><input ref={inputRef} className="visually-hidden" type="file" multiple accept=".pkl,.pickle,.pth,.pt,.h5,.hdf5,.onnx,.safetensors,.zip,.tar,.gz" onChange={e => uploadFiles(e.target.files)} /></section>
        <section className="stats-grid">
          <article className="stat-card"><div className="stat-top"><span>Total artifacts</span><span className="stat-icon blue"><Box size={17} /></span></div><div className="stat-number">24</div><div className="stat-foot"><span className="trend"><ArrowDown size={12} className="trend-up" /> 12%</span><span>vs. last month</span><span className="stat-note">Across 6 projects</span></div></article>
          <article className="stat-card"><div className="stat-top"><span>Approved</span><span className="stat-icon green"><ShieldCheck size={17} /></span></div><div className="stat-number">18</div><div className="stat-foot"><span className="trend">75%</span><span>of all artifacts</span><span className="mini-progress"><i /></span></div></article>
          <article className="stat-card"><div className="stat-top"><span>Needs review</span><span className="stat-icon amber"><Clock3 size={17} /></span></div><div className="stat-number">3</div><div className="stat-foot"><span className="attention">2 high priority</span><span className="stat-note">Oldest: 2h ago</span></div></article>
          <article className="stat-card"><div className="stat-top"><span>Blocked</span><span className="stat-icon red"><LockKeyhole size={17} /></span></div><div className="stat-number">3</div><div className="stat-foot"><span>12.5% block rate</span><span className="stat-note">This month</span></div></article>
        </section>
        <section className="insight-banner"><div className="insight-icon"><Fingerprint size={20} /></div><div className="insight-copy"><strong>Every release decision, backed by evidence.</strong><span>Artifacts are hashed, scanned, and evaluated against your active policies.</span></div><div className="pipeline"><span className="pipe-step done"><i><Check size={11} /></i>Upload</span><b /><span className="pipe-step done"><i><Check size={11} /></i>Scan</span><b /><span className="pipe-step done"><i><Check size={11} /></i>Evidence</span><b /><span className="pipe-step current"><i><Shield size={11} /></i>Decision</span></div><button className="banner-arrow" onClick={() => setNotice('Release pipeline details are available in artifact records')} aria-label="View release pipeline"><ArrowRight size={17} /></button></section>
        <section className="artifacts-section"><div className="section-head"><div><div className="section-title-row"><h2>Recent artifacts</h2><span className="total-pill">24</span></div><p>Track model security and release status</p></div><button className="text-button" onClick={() => setNotice('Showing all artifacts')}>View all artifacts <ArrowRight size={15} /></button></div>
          <div className="table-toolbar"><label className="search-box"><Search size={16} /><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search artifacts..." /><kbd>⌘ K</kbd></label><div className="toolbar-actions"><div className="filter-wrap"><button className="button secondary filter-button" onClick={() => setMenuOpen(v => !v)}><SlidersHorizontal size={15} /> {filter}<ChevronDown size={14} /></button>{menuOpen && <div className="filter-menu">{['All statuses', 'Approved', 'Conditional', 'Quarantined', 'Blocked'].map(item => <button key={item} onClick={() => { setFilter(item); setMenuOpen(false); }}>{item}{filter === item && <Check size={14} />}</button>)}</div>}</div><button className="button secondary export-button" onClick={() => setNotice('Artifact export is coming soon')}><ArrowDownUp size={15} /> Export</button></div></div>
          <div className="table-wrap"><table><thead><tr><th><span>ARTIFACT <ArrowDown size={12} /></span></th><th>STATUS</th><th>FINDINGS</th><th>UPLOADED BY</th><th>LAST UPDATED</th><th></th></tr></thead><tbody>{filtered.map(item => <tr key={item.id} onClick={() => setNotice(`${item.name} · ${item.id} · SHA-256 ${item.hash}`)}><td><div className="artifact-cell"><div className={`file-icon ${item.format.toLowerCase()}`}><FileText size={17} /></div><div className="file-name"><strong>{item.name}</strong><span>{item.id} <i /> {item.format}</span></div></div></td><td><Badge status={item.decision} /></td><td><span className={item.findings ? 'findings-count' : 'findings-clear'}>{item.findings ? <><AlertTriangle size={13} /> {item.findings} finding{item.findings > 1 ? 's' : ''}</> : <><Check size={13} /> No findings</>}</span></td><td><div className="uploader"><span className={`tiny-avatar avatar-${item.uploadedBy.split(' ')[0].toLowerCase()}`}>{item.uploadedBy.split(' ').map(s => s[0]).join('')}</span>{item.uploadedBy}</div></td><td className="date-cell">{item.uploadedAt}</td><td><button className="row-more" aria-label={`More options for ${item.name}`} onClick={e => { e.stopPropagation(); setNotice(`More actions for ${item.name}`); }}><MoreHorizontal size={18} /></button></td></tr>)}</tbody></table>{filtered.length === 0 && <div className="empty-state"><Search size={20} /><strong>No artifacts found</strong><span>Try another search or status filter.</span></div>}</div>
          <div className="table-footer"><span>Showing <strong>{filtered.length ? 1 : 0}–{filtered.length}</strong> of <strong>{filtered.length}</strong> artifacts</span><div className="pagination"><button disabled aria-label="Previous page"><ChevronLeft size={15} /></button><button className="page-active">1</button><button disabled>2</button><button disabled>3</button><span>…</span><button disabled>5</button><button disabled aria-label="Next page"><ChevronRight size={15} /></button></div></div>
        </section>
        <footer className="footer"><span>© 2026 ModelShield</span><span><i className="system-dot" /> All systems operational</span><a href="#security" onClick={e => { e.preventDefault(); setNotice('Security documentation will be available soon'); }}>Security <ArrowRight size={12} /></a></footer>
      </div>
    </main>
    {notice && <div className="toast"><div className="toast-check"><Check size={15} /></div><span>{notice}</span><button onClick={() => setNotice('')} aria-label="Dismiss notification"><X size={15} /></button></div>}
  </div>;
}

export default App;
