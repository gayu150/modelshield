import { Activity, Check, FileKey2, ShieldCheck } from 'lucide-react';

export default function GovernancePage({ section = 'all' }: { section?: 'all' | 'policies' | 'audit' }) {
  const title = section === 'policies' ? 'Release policies' : section === 'audit' ? 'Audit trail' : 'Governance';
  const description = section === 'policies'
    ? 'Versioned rules that determine whether model artifacts can ship.'
    : section === 'audit'
      ? 'Traceable decisions and changes across your workspace.'
      : 'Manage release policies and follow the evidence behind model decisions.';

  return <>
    <div className="page-head"><div><div className="kicker"><i/>CONTROL CENTER</div><h1>{title}</h1><p>{description}</p></div></div>
    <div className="lower-grid governance-grid">
      {section !== 'audit' && <section className="event-card">
        <div className="policy-top"><FileKey2/><span>ACTIVE</span></div>
        <h2>Release policies</h2><p>Versioned rules that determine whether model artifacts can ship.</p>
        <div className="event"><ShieldCheck/><span><b>Production Model Security</b><small>PROD-SEC-004 ? Version 2.0</small></span><time>Active</time></div>
        <div className="rule">Critical finding <strong>Block release</strong></div>
      </section>}
      {section !== 'policies' && <section className="event-card">
        <Activity/><h2>Audit trail</h2><p>Traceable decisions and changes across your workspace.</p>
        <div className="event"><Check/><span><b>Release decision recorded</b><small>fraud-detection-v3.pkl ? Priya Sharma</small></span><time>10:26 AM</time></div>
        <div className="event"><Activity/><span><b>Artifact submitted for review</b><small>customer-churn.onnx</small></span><time>9:14 AM</time></div>
      </section>}
    </div>
  </>;
}
