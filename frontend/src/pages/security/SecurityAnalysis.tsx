import { useEffect, useState } from "react";
import type { Artifact } from "../../types/artifact";
import type { Finding } from "../../types/security";
import { artifactUrl, go, type SecurityTab } from "../../routes";
import { DEMO_MODE } from "../../config";
import { example } from "../../data/security";
import {
  getFindings,
  getEvidence,
  getGraph,
  getRisk,
} from "../../services/api/security";
import { useResource } from "../../hooks/useResource";
import {
  EmptyState,
  ErrorState,
  Loading,
  Pagination,
} from "../../components/common/Feedback";
import EvidenceGraph from "../../components/security/EvidenceGraph";
import FindingDetails from "../../components/security/FindingDetails";
import { compareHashes } from "../../utils/security";
import "./security.css";
const labels: Record<SecurityTab, string> = {
  findings: "Findings",
  evidence: "Evidence",
  graph: "Evidence graph",
  provenance: "Provenance",
  passport: "Security Passport",
  decision: "Governance Decision",
};

function Findings({
  artifact,
  onEvidence,
  inspectId,
}: {
  artifact: Artifact;
  onEvidence: (id: string) => void;
  inspectId?: string;
}) {
  const resource = useResource(
    (signal) =>
      DEMO_MODE
        ? Promise.resolve(example(artifact).findings)
        : getFindings(artifact.id, signal),
    [artifact.id],
  );
  const risk = useResource(
    (signal) => DEMO_MODE ? Promise.resolve(undefined) : getRisk(artifact.id, signal),
    [artifact.id],
  );
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Finding>();
  useEffect(() => {
    if (inspectId && resource.data)
      setSelected(resource.data.find((f) => f.id === inspectId));
  }, [inspectId, resource.data]);
  if (resource.loading) return <Loading>Loading findings...</Loading>;
  if (resource.error)
    return <ErrorState message={resource.error} onRetry={resource.reload} />;
  const findings = resource.data || [];
  const filtered = findings.filter(
    (f) =>
      (severity === "ALL" || f.severity === severity) &&
      (f.title + " " + f.id + " " + f.scanner)
        .toLowerCase()
        .includes(search.toLowerCase()),
  );
  const current = Math.min(page, Math.max(1, Math.ceil(filtered.length / 10)));
  return (
    <>
      <section className="risk-summary" aria-label="Recorded risk summary">
        <h3>Evidence-based risk summary</h3>
        {risk.loading && <p>Loading risk context...</p>}
        {risk.error && <ErrorState message={risk.error} onRetry={risk.reload} />}
        {risk.data && <><p><strong>{risk.data.state}</strong> · Integrity: {risk.data.integrity} · Scan: {risk.data.scanStatus}</p><ul>{risk.data.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul></>}
        {DEMO_MODE && <p>Example counts only. No risk assessment has run.</p>}
        <h4>Recorded severity distribution</h4>
        <div className="severity-counts">
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
            <span key={s} className={"severity severity-" + s.toLowerCase()}>
              {s}: {findings.filter((f) => f.severity === s).length}
            </span>
          ))}
        </div>
        <p>
          These are reported scanner findings. Severity counts and zero findings
          do not independently establish release safety.
        </p>
      </section>
      <div className="toolbar">
        <input
          aria-label="Search findings"
          placeholder="Search title, ID or scanner"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
        <select
          aria-label="Filter by severity"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setPage(1);
          }}
        >
          <option value="ALL">All severities</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <button
          className="btn outline"
          onClick={() => {
            setSeverity("ALL");
            setSearch("");
            setPage(1);
          }}
        >
          Reset
        </button>
        <button className="btn outline" onClick={resource.reload}>
          Refresh findings
        </button>
      </div>
      {filtered.length ? (
        <div className="table-scroll">
          <table className="artifact-table">
            <thead>
              <tr>
                <th scope="col">Finding</th>
                <th scope="col">Severity</th>
                <th scope="col">Scanner</th>
                <th scope="col">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice((current - 1) * 10, current * 10).map((f) => (
                <tr key={f.id}>
                  <td>
                    <button
                      className="link-button"
                      onClick={() => setSelected(f)}
                    >
                      {f.title}
                    </button>
                    <br />
                    <small>{f.id}</small>
                  </td>
                  <td>
                    <span
                      className={
                        "severity severity-" + f.severity.toLowerCase()
                      }
                    >
                      {f.severity}
                    </span>
                  </td>
                  <td>
                    {f.scanner} | {f.scannerVersion}
                  </td>
                  <td>{f.evidenceIds.length}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState
          title={
            findings.length
              ? "No findings match your filters"
              : "No findings recorded"
          }
        >
          Check scanner completion and evidence coverage before interpreting an
          empty report.
        </EmptyState>
      )}
      <Pagination page={current} total={filtered.length} onChange={setPage} />
      {selected && (
        <FindingDetails
          key={selected.id}
          finding={selected}
          onClose={() => setSelected(undefined)}
          onEvidence={(id) => {
            setSelected(undefined);
            onEvidence(id);
          }}
        />
      )}
    </>
  );
}
function EvidenceView({
  artifact,
  selectedId,
}: {
  artifact: Artifact;
  selectedId?: string;
}) {
  const resource = useResource(
    (signal) =>
      DEMO_MODE
        ? Promise.resolve(example(artifact).evidence)
        : getEvidence(artifact.id, signal),
    [artifact.id],
  );
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  useEffect(() => {
    if (selectedId) setSearch(selectedId);
  }, [selectedId]);
  if (resource.loading) return <Loading>Loading evidence...</Loading>;
  if (resource.error)
    return <ErrorState message={resource.error} onRetry={resource.reload} />;
  const evidence = resource.data || [];
  const filtered = evidence
    .filter((e) =>
      (e.id + " " + e.title + " " + e.scanner + " " + e.kind)
        .toLowerCase()
        .includes(search.toLowerCase()),
    )
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp));
  const current = Math.min(page, Math.max(1, Math.ceil(filtered.length / 10)));
  return (
    <>
      <div className="toolbar">
        <input
          aria-label="Search evidence"
          placeholder="Search ID, title, kind or scanner"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setPage(1);
          }}
        />
        <button
          className="btn outline"
          onClick={() => {
            setSearch("");
            setPage(1);
          }}
        >
          Show all evidence
        </button>
        <button className="btn outline" onClick={resource.reload}>
          Refresh evidence
        </button>
      </div>
      {filtered.length ? (
        <ol className="evidence-timeline">
          {filtered.slice((current - 1) * 10, current * 10).map((e) => (
            <li key={e.id}>
              <article
                className={
                  "evidence-card " +
                  (e.id === selectedId ? "selected-evidence" : "")
                }
              >
                <h3>{e.title}</h3>
                <p>
                  {e.kind} | {e.scanner}
                </p>
                {e.findingType && <p>Finding type: {e.findingType}</p>}
                {e.severity && <p>Severity: {e.severity}</p>}
                {e.location && <p>Location: {e.location}</p>}
                {e.verificationStatus && <p>Evidence status: {e.verificationStatus}</p>}
                <time dateTime={e.timestamp}>
                  {new Date(e.timestamp).toLocaleString()}
                </time>
                <p>{e.summary}</p>
                <details>
                  <summary>View evidence content</summary>
                  <pre>{e.content}</pre>
                </details>
                <small>{e.id}</small>
              </article>
            </li>
          ))}
        </ol>
      ) : (
        <EmptyState
          title={search ? "No matching evidence" : "No evidence recorded"}
        >
          {selectedId
            ? "The referenced evidence is unavailable in this report."
            : ""}
        </EmptyState>
      )}
      <Pagination page={current} total={filtered.length} onChange={setPage} />
    </>
  );
}
function GraphView({
  artifact,
  onInspect,
}: {
  artifact: Artifact;
  onInspect: (id: string, kind: string) => void;
}) {
  const resource = useResource(
    (signal) =>
      DEMO_MODE
        ? Promise.resolve(example(artifact).graph)
        : getGraph(artifact.id, signal),
    [artifact.id],
  );
  if (resource.loading) return <Loading>Loading evidence graph...</Loading>;
  if (resource.error)
    return <ErrorState message={resource.error} onRetry={resource.reload} />;
  return resource.data ? (
    <EvidenceGraph graph={resource.data} onInspect={onInspect} />
  ) : null;
}
function ProvenanceView({ artifact }: { artifact: Artifact }) {
  const p = DEMO_MODE
    ? example(artifact).provenance
    : artifact.provenance || {};
  return (
    <>
      <p>
        Signature status is reported by the backend. Matching hashes establish
        consistency between the supplied values, not model safety.
      </p>
      <dl className="provenance">
        <dt>Source</dt>
        <dd>{p.source || "Not recorded"}</dd>
        <dt>Publisher</dt>
        <dd>{p.publisher || "Not recorded"}</dd>
        <dt>Repository</dt>
        <dd>{p.repository || "Not recorded"}</dd>
        <dt>Revision</dt>
        <dd>{p.revision || "Not recorded"}</dd>
        <dt>Origin</dt>
        <dd>{p.origin || "Not recorded"}</dd>
        <dt>Origin verification</dt>
        <dd>{p.verificationStatus || "UNKNOWN"} — uploader supplied, not independently verified</dd>
        <dt>Signature</dt>
        <dd>{p.signatureStatus || "UNKNOWN"}</dd>
        <dt>Integrity comparison</dt>
        <dd>{compareHashes(p.expectedHash, p.observedHash)}</dd>
        <dt>Artifact SHA-256</dt>
        <dd>{artifact.hash}</dd>
        <dt>Expected SHA-256</dt>
        <dd>{p.expectedHash || "Not recorded"}</dd>
        <dt>Observed SHA-256</dt>
        <dd>{p.observedHash || "Not recorded"}</dd>
      </dl>
    </>
  );
}
export default function SecurityAnalysis({
  artifact,
  tab,
}: {
  artifact: Artifact;
  tab: SecurityTab;
}) {
  const [selectedEvidence, setSelectedEvidence] = useState<string>();
  const [selectedFinding, setSelectedFinding] = useState<string>();
  const [graphNotice, setGraphNotice] = useState("");
  function evidence(id: string) {
    setSelectedEvidence(id);
    go(artifactUrl(artifact.id, "evidence"));
  }
  function inspect(id: string, kind: string) {
    setGraphNotice("");
    const category = kind.toLowerCase();
    if (category === "artifact") {
      go(artifactUrl(id));
      return;
    }
    if (category === "finding") {
      setSelectedFinding(id);
      go(artifactUrl(artifact.id, "findings"));
      return;
    }
    if (category === "evidence") {
      evidence(id);
      return;
    }
    if (category === "hash" || category === "provenance") {
      go(artifactUrl(artifact.id, "provenance"));
      return;
    }
    if (category === "policy") {
      go("/policies");
      return;
    }
    if (category === "decision") {
      go(artifactUrl(artifact.id, "passport"));
      return;
    }
    setGraphNotice(
      "This node has no finding or evidence detail view. Its connections are shown below.",
    );
  }
  return (
    <section className="detail-card security-analysis">
      <h2>Security analysis</h2>
      {DEMO_MODE && (
        <p className="demo-banner">
          Illustrative interface fixtures. No scanner or verification has run on
          the selected artifact.
        </p>
      )}
      <nav className="security-tabs" aria-label="Artifact security sections">
        {(Object.keys(labels) as SecurityTab[]).map((t) => (
          <a
            key={t}
            className={"btn outline " + (tab === t ? "selected-tab" : "")}
            href={"#" + artifactUrl(artifact.id, t)}
            aria-current={tab === t ? "page" : undefined}
          >
            {labels[t]}
          </a>
        ))}
      </nav>
      <h3>{labels[tab]}</h3>
      {graphNotice && <p role="status">{graphNotice}</p>}
      {tab === "findings" && (
        <Findings
          artifact={artifact}
          onEvidence={evidence}
          inspectId={selectedFinding}
        />
      )}
      {tab === "evidence" && (
        <EvidenceView artifact={artifact} selectedId={selectedEvidence} />
      )}
      {tab === "graph" && <GraphView artifact={artifact} onInspect={inspect} />}
      {tab === "provenance" && <ProvenanceView artifact={artifact} />}
    </section>
  );
}
