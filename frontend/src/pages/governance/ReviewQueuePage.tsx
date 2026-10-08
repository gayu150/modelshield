import { useMemo, useState } from "react";
import {
  ArrowRight,
  Clock3,
  FileCode2,
  Filter,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { Artifact } from "../../types/artifact";
import type { DecisionRecord } from "../../types/governance";
import DecisionModal from "../../components/governance/DecisionModal";

export default function ReviewQueuePage({
  items,
  onOpen,
  onDecisionUpdated,
}: {
  items: Artifact[];
  onOpen: (id: string) => void;
  onDecisionUpdated?: (record: DecisionRecord) => void;
}) {
  const [query, setQuery] = useState("");
  const [filterType, setFilterType] = useState<"ALL" | "FINDINGS" | "QUARANTINED" | "CONDITIONAL">("ALL");
  const [decisionTarget, setDecisionTarget] = useState<Artifact | null>(null);

  const queued = useMemo(() => {
    return items.filter((item) => {
      const isReviewable = ["QUARANTINED", "CONDITIONAL"].includes(item.decision);
      if (!isReviewable) return false;

      if (filterType === "FINDINGS" && item.findings === 0) return false;
      if (filterType === "QUARANTINED" && item.decision !== "QUARANTINED") return false;
      if (filterType === "CONDITIONAL" && item.decision !== "CONDITIONAL") return false;

      const text = `${item.name} ${item.model} ${item.id} ${item.uploadedBy} ${item.format}`.toLowerCase();
      return text.includes(query.toLowerCase());
    });
  }, [items, query, filterType]);

  const awaitingTotal = items.filter((x) =>
    ["QUARANTINED", "CONDITIONAL"].includes(x.decision),
  ).length;
  const withFindingsTotal = items.filter(
    (x) => ["QUARANTINED", "CONDITIONAL"].includes(x.decision) && x.findings > 0,
  ).length;

  return (
    <>
      <div className="page-head">
        <div>
          <div className="kicker">
            <i />
            RELEASE GOVERNANCE
          </div>
          <h1>Review Queue</h1>
          <p>
            Evaluate quarantined intake models and conditional releases against security policies.
          </p>
        </div>
      </div>

      <div className="registry-summary">
        <b>
          {awaitingTotal.toString().padStart(2, "0")} <small>awaiting review</small>
        </b>
        <i />
        <b className="amber-text">
          {withFindingsTotal.toString().padStart(2, "0")} <small>with findings</small>
        </b>
        <span>● Active queue</span>
      </div>

      <section className="list-card">
        <div className="toolbar" style={{ flexWrap: "wrap", gap: 12 }}>
          <label style={{ flex: 1, minWidth: 240 }}>
            <Search size={15} />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search by artifact, model, format, or owner..."
            />
          </label>

          <div style={{ display: "flex", gap: 6 }}>
            <button
              className={`btn outline ${filterType === "ALL" ? "primary" : ""}`}
              onClick={() => setFilterType("ALL")}
              style={{ padding: "6px 12px", fontSize: 12 }}
            >
              All ({awaitingTotal})
            </button>
            <button
              className={`btn outline ${filterType === "FINDINGS" ? "primary" : ""}`}
              onClick={() => setFilterType("FINDINGS")}
              style={{ padding: "6px 12px", fontSize: 12 }}
            >
              With Findings ({withFindingsTotal})
            </button>
            <button
              className={`btn outline ${filterType === "CONDITIONAL" ? "primary" : ""}`}
              onClick={() => setFilterType("CONDITIONAL")}
              style={{ padding: "6px 12px", fontSize: 12 }}
            >
              Conditional
            </button>
          </div>
        </div>

        <div className="table-scroll">
          <table className="artifact-table">
            <thead>
              <tr>
                <th>ARTIFACT</th>
                <th>DECISION STATE</th>
                <th>SECURITY FINDINGS</th>
                <th>SUBMITTER</th>
                <th>INTAKE DATE</th>
                <th style={{ textAlign: "right" }}>ACTIONS</th>
              </tr>
            </thead>
            <tbody>
              {queued.map((item) => (
                <tr key={item.id}>
                  <td onClick={() => onOpen(item.id)} style={{ cursor: "pointer" }}>
                    <div className="artifact-cell">
                      <span className={"file-tile " + item.format.toLowerCase()}>
                        <FileCode2 size={17} />
                      </span>
                      <span>
                        <b>{item.name}</b>
                        <small>
                          {item.id} • {item.format}
                        </small>
                      </span>
                    </div>
                  </td>
                  <td>
                    <span className={"status " + item.decision.toLowerCase()}>
                      <Clock3 size={13} />
                      {item.decision === "QUARANTINED" ? "Quarantined" : "Conditional"}
                    </span>
                  </td>
                  <td>
                    {item.findings > 0 ? (
                      <span className="has-findings">
                        <ShieldAlert size={13} />
                        {item.findings} findings
                      </span>
                    ) : (
                      <span style={{ color: "#168b64", fontSize: 12, fontWeight: 600 }}>
                        <ShieldCheck size={13} style={{ display: "inline", verticalAlign: "middle", marginRight: 4 }} />
                        Clean (0 findings)
                      </span>
                    )}
                  </td>
                  <td>{item.uploadedBy}</td>
                  <td className="muted">{item.uploadedAt}</td>
                  <td style={{ textAlign: "right" }}>
                    <div style={{ display: "inline-flex", gap: 8 }}>
                      <button
                        className="btn outline"
                        style={{ padding: "4px 10px", fontSize: 11 }}
                        onClick={(e) => {
                          e.stopPropagation();
                          setDecisionTarget(item);
                        }}
                      >
                        Decide
                      </button>
                      <button
                        className="btn primary"
                        style={{ padding: "4px 10px", fontSize: 11 }}
                        onClick={() => onOpen(item.id)}
                      >
                        Inspect <ArrowRight size={12} style={{ display: "inline", verticalAlign: "middle" }} />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {!queued.length && (
            <div className="empty">
              <Search size={22} />
              <b>{query || filterType !== "ALL" ? "No matching reviews found" : "Review queue is clear"}</b>
              <span>
                {query || filterType !== "ALL"
                  ? "Try clearing the search or changing the filter."
                  : "All submitted models have been reviewed or approved."}
              </span>
            </div>
          )}
        </div>
      </section>

      {decisionTarget && (
        <DecisionModal
          artifact={decisionTarget}
          onClose={() => setDecisionTarget(null)}
          onSuccess={(record) => {
            if (onDecisionUpdated) onDecisionUpdated(record);
            setDecisionTarget(null);
          }}
        />
      )}
    </>
  );
}
