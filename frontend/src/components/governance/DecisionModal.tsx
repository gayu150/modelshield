import { useEffect, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import type { Artifact, Decision } from "../../types/artifact";
import type { DecisionRecord } from "../../types/governance";
import { useAuth } from "../../context/AuthContext";
import { DEMO_MODE } from "../../config";
import {
  evaluateArtifactAgainstPolicy,
  standardPolicies,
} from "../../data/governance";
import { submitDecision, evaluateArtifactPolicy } from "../../services/api/governance";
import type { PolicyEvaluation } from "../../types/governance";
import { safeMessage } from "../../services/api/client";
import { example } from "../../data/security";

const COMMON_CONDITIONS = [
  "Restricted to internal staging/sandbox environment",
  "Requires continuous drift and anomaly monitoring",
  "Daily audit logging of all inference queries",
  "Manual secondary approval required for production promotion",
];
export default function DecisionModal({
  artifact,
  onClose,
  onSuccess,
}: {
  artifact: Artifact;
  onClose: () => void;
  onSuccess: (record: DecisionRecord) => void;
}) {
  const { user } = useAuth();
  const [selectedDecision, setSelectedDecision] = useState<Decision>(
    artifact.decision === "QUARANTINED" ? "QUARANTINED" : artifact.decision,
  );
  const [rationale, setRationale] = useState("");
  const [selectedConditions, setSelectedConditions] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [evaluation, setEvaluation] = useState<PolicyEvaluation>();
  const [evaluationError, setEvaluationError] = useState("");
  const [evaluationLoading, setEvaluationLoading] = useState(true);
  const [evaluationAttempt, setEvaluationAttempt] = useState(0);

  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    const timeout = AbortSignal.timeout(15000);
    const signal = AbortSignal.any([controller.signal, timeout]);
    setEvaluation(undefined);
    setEvaluationError("");
    setEvaluationLoading(true);
    if (DEMO_MODE) {
      setEvaluation(evaluateArtifactAgainstPolicy(artifact, standardPolicies[0], example(artifact).findings, artifact.provenance?.observedHash));
      setEvaluationLoading(false);
    } else {
      evaluateArtifactPolicy(artifact.id, undefined, signal)
        .then((result) => { if (active) setEvaluation(result); })
        .catch((err) => {
          if (!active) return;
          setEvaluationError(timeout.aborted
            ? "Policy evaluation timed out. Check that the ModelShield API server is running, then retry."
            : safeMessage(err));
        })
        .finally(() => { if (active) setEvaluationLoading(false); });
    }
    return () => { active = false; controller.abort(); };
  }, [artifact.id, evaluationAttempt]);

  const policyOutcome = evaluation?.overallOutcome || artifact.policyOutcome || "";
  const isApprovalRestricted = ["BLOCK", "BLOCKED", "QUARANTINED", "CONDITIONAL"].includes(policyOutcome);
  const isApprovingBlocked = selectedDecision === "APPROVED" && isApprovalRestricted;

  function toggleCondition(cond: string) {
    setSelectedConditions((prev) =>
      prev.includes(cond) ? prev.filter((c) => c !== cond) : [...prev, cond],
    );
  }

  async function handleConfirm() {
    if (!rationale.trim() || rationale.trim().length < 5) {
      setError("Please provide a substantive rationale for this release decision.");
      return;
    }
    setError("");
    setLoading(true);

    try {
      if (DEMO_MODE) {
        const mockRecord: DecisionRecord = {
          id: "DEC-" + crypto.randomUUID().slice(0, 8).toUpperCase(),
          artifactId: artifact.id,
          decision: selectedDecision,
          rationale: rationale.trim(),
          conditions: selectedConditions,
          reviewerId: user?.id || "USR-DEMO",
          reviewerName: user?.name || "Demo Reviewer",
          reviewerRole: user?.role || "Security Reviewer",
          createdAt: new Date().toISOString(),
          signature: "0x" + Array.from(crypto.getRandomValues(new Uint8Array(16)))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(""),
        };
        onSuccess(mockRecord);
      } else {
        const record = await submitDecision(
          artifact.id,
          selectedDecision,
          rationale.trim(),
          selectedConditions,
        );
        onSuccess(record);
      }
      onClose();
    } catch (err) {
      setError(safeMessage(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="modal-title">
      <div className="modal-dialog">
        <div className="modal-head">
          <div>
            <span className="kicker">GOVERNANCE ENGINE</span>
            <h2 id="modal-title">Record Release Decision</h2>
          </div>
          <button className="btn outline" onClick={onClose} aria-label="Close modal">
            <X size={16} />
          </button>
        </div>

        <div className="modal-content">
          {error && (
            <div className="form-error" role="alert">
              <AlertTriangle size={15} />
              {error}
            </div>
          )}

          {/* Policy Compliance Evaluation Preview */}
          <div className="policy-compliance-preview">
            <div className="section-head" style={{ marginBottom: 4 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: "#64748b" }}>
                ACTIVE RELEASE POLICY: {evaluation?.policyCode || standardPolicies[0].code} ({evaluation?.policyName || standardPolicies[0].name})
              </span>
            </div>

            <div
              className={`compliance-status-banner ${(evaluation?.overallOutcome || artifact.policyOutcome || "pending").toLowerCase()}`}
            >
              {evaluationLoading && <span>Loading active policy evaluation…</span>}
              {evaluationError && (
                <span className="evaluation-error">
                  {evaluationError}
                  <button type="button" className="link-button" onClick={() => setEvaluationAttempt((attempt) => attempt + 1)}>
                    Retry evaluation
                  </button>
                </span>
              )}
              {(evaluation?.overallOutcome === "PASS" || evaluation?.overallOutcome === "APPROVED") && (
                <>
                  <CheckCircle2 size={16} />
                  <span>Policy Compliance: APPROVED — All mandatory checks passed.</span>
                </>
              )}
              {evaluation?.overallOutcome === "CONDITIONAL" && (
                <>
                  <AlertTriangle size={16} />
                  <span>
                    Policy Compliance: CONDITIONAL — High findings or caveats detected.
                  </span>
                </>
              )}
              {(evaluation?.overallOutcome === "BLOCK" || evaluation?.overallOutcome === "BLOCKED") && (
                <>
                  <ShieldAlert size={16} />
                  <span>
                    Policy Compliance: BLOCKED — A mandatory rule prevents release.
                  </span>
                </>
              )}
              {evaluation?.overallOutcome === "QUARANTINED" && (
                <>
                  <AlertTriangle size={16} />
                  <span>Policy Compliance: QUARANTINED — Required evidence or review is incomplete.</span>
                </>
              )}
            </div>

            <div style={{ fontSize: 11, color: "#64748b" }}>
              {(evaluation?.ruleEvaluations || []).map((r) => (
                <div
                  key={r.ruleCode}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    padding: "3px 0",
                    borderBottom: "1px dashed #e2e8f0",
                  }}
                >
                  <span>
                    {r.passed ? "✓" : "✗"} <b>{r.ruleCode}</b>: {r.ruleTitle}
                  </span>
                  <span style={{ color: r.passed ? "#166534" : "#991b1b", fontWeight: 600 }}>
                    {r.passed ? "Passed" : r.action}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Target Decision State Selector */}
          <div>
            <label style={{ display: "block", fontSize: 12, fontWeight: 700, marginBottom: 8 }}>
              SELECT GOVERNANCE DECISION
            </label>
            <div className="decision-options-grid">
              <div
                className={`decision-radio-card approved ${
                  selectedDecision === "APPROVED" ? "selected" : ""
                }`}
                onClick={() => setSelectedDecision("APPROVED")}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <ShieldCheck size={16} color="#10b981" />
                  <b>Approved</b>
                </div>
                <span>Certified for unrestricted production deployment.</span>
              </div>

              <div
                className={`decision-radio-card conditional ${
                  selectedDecision === "CONDITIONAL" ? "selected" : ""
                }`}
                onClick={() => setSelectedDecision("CONDITIONAL")}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <Clock size={16} color="#f59e0b" />
                  <b>Conditional</b>
                </div>
                <span>Approved with explicit caveats or sandboxing.</span>
              </div>

              <div
                className={`decision-radio-card ${
                  selectedDecision === "QUARANTINED" ? "selected" : ""
                }`}
                onClick={() => setSelectedDecision("QUARANTINED")}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <AlertTriangle size={16} color="#64748b" />
                  <b>Quarantined</b>
                </div>
                <span>Held in quarantine pending additional remediation.</span>
              </div>

              <div
                className={`decision-radio-card blocked ${
                  selectedDecision === "BLOCKED" ? "selected" : ""
                }`}
                onClick={() => setSelectedDecision("BLOCKED")}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <ShieldAlert size={16} color="#ef4444" />
                  <b>Blocked</b>
                </div>
                <span>Strictly prohibited from release or distribution.</span>
              </div>
            </div>
          </div>

          {isApprovingBlocked && (
            <div className="form-error" style={{ background: "#fff1f1", borderColor: "#fca5a5" }}>
              <ShieldAlert size={16} color="#dc2626" />
              <span>
                <strong>Approval unavailable:</strong> The current policy outcome is {policyOutcome}.
                Resolve its requirements and reevaluate before approval.
              </span>
            </div>
          )}

          {/* Rationale Input */}
          <div>
            <label
              htmlFor="rationale-input"
              style={{ display: "block", fontSize: 12, fontWeight: 700, marginBottom: 6 }}
            >
              JUSTIFICATION & RATIONALE <span style={{ color: "#ef4444" }}>*</span>
            </label>
            <textarea
              id="rationale-input"
              className="search-box"
              style={{ width: "100%", minHeight: 75, padding: 10, fontSize: 12 }}
              placeholder="Document the technical justification, mitigation measures, or validation details for this decision..."
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
            />
          </div>

          {/* Conditional Caveats */}
          {selectedDecision === "CONDITIONAL" && (
            <div>
              <label style={{ display: "block", fontSize: 12, fontWeight: 700, marginBottom: 6 }}>
                OPERATIONAL CAVEATS & CONDITIONS
              </label>
              <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                {COMMON_CONDITIONS.map((cond) => (
                  <label
                    key={cond}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 8,
                      fontSize: 12,
                      cursor: "pointer",
                    }}
                  >
                    <input
                      type="checkbox"
                      checked={selectedConditions.includes(cond)}
                      onChange={() => toggleCondition(cond)}
                    />
                    <span>{cond}</span>
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Reviewer line */}
          <div style={{ fontSize: 11, color: "#64748b", borderTop: "1px solid #edf0f5", paddingTop: 10 }}>
            Sign-off Reviewer: <b>{user?.name}</b> ({user?.role})
          </div>
        </div>

        <div className="modal-foot">
          <button className="btn outline" onClick={onClose} disabled={loading}>
            Cancel
          </button>
          <button
            className="btn primary"
            onClick={handleConfirm}
            disabled={loading || !rationale.trim() || isApprovingBlocked}
          >
            {loading ? "Recording Decision..." : "Commit Decision"}
          </button>
        </div>
      </div>
    </div>
  );
}
