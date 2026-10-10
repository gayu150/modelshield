import { useMemo, useState } from "react";
import { Clock3, FileCode2, Search, ShieldAlert, ShieldCheck, ClipboardCheck } from "lucide-react";
import type { Artifact } from "../../types/artifact";
import type { DecisionRecord } from "../../types/governance";
import { Status } from "../../components/common/Registry";
import DecisionModal from "../../components/governance/DecisionModal";
import { useAuth } from "../../context/AuthContext";
import { DEMO_MODE } from "../../config";

type DecisionFilter = "ALL" | "FINDINGS" | "REVIEW_REQUIRED" | "QUARANTINED" | "APPROVED" | "CONDITIONAL" | "BLOCKED";

export default function ReviewQueuePage({
  items,
  onOpen,
  onDecision,
}: {
  items: Artifact[];
  onOpen: (id: string) => void;
  onDecision: (artifactId: string, record: DecisionRecord) => void;
}) {
  const { user } = useAuth();
  const canReview = DEMO_MODE || ["security reviewer", "governance admin", "admin"].includes(user?.role.trim().toLowerCase() || "");
  const [query, setQuery] = useState("");
  const [filterType, setFilterType] = useState<DecisionFilter>("ALL");
  const [reviewing, setReviewing] = useState<Artifact>();

  const queued = useMemo(() => items.filter((item) => {
    if (filterType === "FINDINGS" && item.findings === 0) return false;
    if (filterType === "REVIEW_REQUIRED" && !item.reviewRequired) return false;
    if (filterType === "QUARANTINED" && ![undefined, "NOT_SCANNED", "QUEUED", "RUNNING"].includes(item.scanStatus)) return false;
    if (filterType !== "ALL" && filterType !== "FINDINGS" && filterType !== "REVIEW_REQUIRED" && filterType !== "QUARANTINED" && item.decision !== filterType) return false;
    const text = `${item.name} ${item.model} ${item.id} ${item.uploadedBy} ${item.format}`.toLowerCase();
    return text.includes(query.trim().toLowerCase());
  }), [items, query, filterType]);

  const awaitingScan = items.filter((item) => [undefined, "NOT_SCANNED", "QUEUED", "RUNNING"].includes(item.scanStatus)).length;
  const awaitingReview = items.filter((item) => item.reviewRequired).length;
  const approved = items.filter((item) => item.decision === "APPROVED").length;
  const needsAttention = awaitingReview;
  const filters: { label: string; value: DecisionFilter; count: number }[] = [
    { label: "All artifacts", value: "ALL", count: items.length },
    { label: "With findings", value: "FINDINGS", count: items.filter((item) => item.findings > 0).length },
    { label: "Needs review", value: "REVIEW_REQUIRED", count: awaitingReview },
    { label: "Awaiting scan", value: "QUARANTINED", count: awaitingScan },
    { label: "Approved", value: "APPROVED", count: approved },
    { label: "Conditional", value: "CONDITIONAL", count: items.filter((item) => item.decision === "CONDITIONAL").length },
    { label: "Blocked", value: "BLOCKED", count: items.filter((item) => item.decision === "BLOCKED").length },
  ];

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker"><i /> RELEASE GOVERNANCE</div>
          <h1>Review Queue</h1>
          <p>The policy engine scans each artifact, records its decision, and explains the rules and evidence behind that outcome.</p>
        </div>
      </div>

      <div className="registry-summary policy-summary">
        <b>{awaitingScan.toString().padStart(2, "0")} <small>awaiting scan</small></b>
        <i />
        <b className="green-text">{approved.toString().padStart(2, "0")} <small>approved</small></b>
        <i />
        <b className="amber-text">{needsAttention.toString().padStart(2, "0")} <small>needs review</small></b>
        <span><ClipboardCheck size={13} /> Policy proposal + human sign-off</span>
      </div>

      <section className="list-card">
        <div className="toolbar policy-toolbar">
          <label className="policy-search">
            <Search size={15} />
            <input
              aria-label="Search policy decisions"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search artifact, model, format, or owner"
            />
          </label>
          <div className="decision-filters" aria-label="Filter policy decisions">
            {filters.map((filter) => (
              <button
                key={filter.value}
                className="btn outline selected-filter"
                aria-pressed={filterType === filter.value}
                onClick={() => setFilterType(filter.value)}
              >
                {filter.label} <span>{filter.count}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="table-scroll">
          <table className="artifact-table policy-decisions-table">
            <thead>
              <tr>
                <th scope="col">ARTIFACT</th>
                <th scope="col">POLICY OUTCOME</th>
                <th scope="col">POLICY DECISION</th>
                <th scope="col">SCAN FINDINGS</th>
                <th scope="col">OWNER</th>
                <th scope="col">UPLOADED</th>
                <th scope="col">ACTION</th>
              </tr>
            </thead>
            <tbody>
              {queued.map((item) => (
                <tr key={item.id}>
                  <td>
                    <div className="artifact-cell">
                      <span className={`file-tile ${item.format.toLowerCase()}`}><FileCode2 size={17} /></span>
                      <span>
                        <button className="link-button" onClick={() => onOpen(item.id)}>{item.name}</button>
                        <small>{item.id} · {item.format}</small>
                      </span>
                    </div>
                  </td>
                  <td>
                    {item.decision === "QUARANTINED" ? (
                      <span className="status quarantined"><Clock3 size={13} /> {item.reviewRequired ? "Review required" : item.scanStatus === "COMPLETED" ? "Quarantined" : "Awaiting scan"}</span>
                    ) : <Status value={item.decision} />}
                  </td>
                  <td>{item.policyOutcome ? <span className={`status ${item.policyOutcome.toLowerCase()}`}>{item.policyOutcome}</span> : <span className="muted">Not evaluated</span>}</td>
                  <td>
                    {item.findings > 0 ? (
                      <span className="has-findings"><ShieldAlert size={13} /> {item.findings} findings</span>
                    ) : (
                      <span className="no-findings"><ShieldCheck size={13} /> {item.decision === "QUARANTINED" ? "Not scanned" : "No findings"}</span>
                    )}
                  </td>
                  <td>{item.uploadedBy}</td>
                  <td className="muted">{item.uploadedAt}</td>
                  <td>{item.reviewRequired ? <button className="btn primary" disabled={!canReview} title={canReview ? "Record a reasoned review decision" : "A Security Reviewer or administrator role is required"} onClick={() => setReviewing(item)}>Review</button> : <button className="link-button" onClick={() => onOpen(item.id)}>Open record</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!queued.length && (
            <div className="empty">
              <Search size={22} />
              <b>{query || filterType !== "ALL" ? "No matching artifacts" : "No artifacts yet"}</b>
              <span>{query || filterType !== "ALL" ? "Try another search or decision filter." : "Uploaded artifacts will appear here."}</span>
            </div>
          )}
        </div>
      </section>
      {reviewing && <DecisionModal artifact={reviewing} onClose={() => setReviewing(undefined)} onSuccess={(record) => { onDecision(reviewing.id, record); setReviewing(undefined); }} />}
    </>
  );
}
