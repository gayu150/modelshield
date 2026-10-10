import { useState } from "react";
import {
  Award,
  ChevronLeft,
  FileCode2,
  FileText,
  Fingerprint,
  RotateCcw,
  Trash2,
} from "lucide-react";
import type { Artifact } from "../../types/artifact";
import type { SecurityPassport } from "../../types/governance";
import { artifactUrl, go, type SecurityTab } from "../../routes";
import { Heading, Status } from "../../components/common/Registry";
import SecurityAnalysis from "../security/SecurityAnalysis";
import ScanControl from "../../components/artifacts/ScanControl";
import PassportView from "../../components/governance/PassportView";
import { useResource } from "../../hooks/useResource";
import { DEMO_MODE } from "../../config";
import { generateMockPassport } from "../../data/governance";
import { getSecurityPassport, replayArtifactDecision } from "../../services/api/governance";
import { evaluateArtifactAgainstPolicy, standardPolicies } from "../../data/governance";
import { example } from "../../data/security";
import type { PolicyEvaluation } from "../../types/governance";
import { safeMessage } from "../../services/api/client";
import { EmptyState, ErrorState, Loading } from "../../components/common/Feedback";
import "./workflow.css";

export default function DetailPage({
  item,
  tab,
  revision,
  onRefresh,
  onDelete,
}: {
  item: Artifact;
  tab?: SecurityTab;
  revision: number;
  onRefresh: () => void;
  onDelete: () => Promise<void>;
}) {
  const [copied, setCopied] = useState("");
  const [replay, setReplay] = useState<{ id: string; original: string; evaluation: PolicyEvaluation }>();
  const [replayError, setReplayError] = useState("");
  const [replayBusy, setReplayBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const passportResource = useResource<SecurityPassport | undefined>(
    (signal) =>
      tab === "passport"
        ? DEMO_MODE
          ? Promise.resolve(
              generateMockPassport(item, {
                id: "DEC-DEMO",
                artifactId: item.id,
                decision: item.decision,
                rationale: "Automated baseline governance attestation for demonstration workspace.",
                reviewerId: "USR-01",
                reviewerName: "Priya Sharma",
                reviewerRole: "Security Reviewer",
                createdAt: item.uploadedAt,
              }),
            )
          : getSecurityPassport(item.id, signal)
        : Promise.resolve(undefined),
    [item.id, tab, revision],
  );

  async function copy() {
    try {
      await navigator.clipboard.writeText(item.hash);
      setCopied("Hash copied.");
    } catch {
      setCopied("Clipboard unavailable. Select and copy the hash below.");
    }
  }

  async function runReplay() {
    setReplayBusy(true);
    setReplayError("");
    try {
      if (DEMO_MODE) {
        setReplay({
          id: "RPL-DEMO-" + crypto.randomUUID().slice(0, 8).toUpperCase(),
          original: item.decision,
          evaluation: evaluateArtifactAgainstPolicy(item, standardPolicies[0], example(item).findings, item.provenance?.observedHash),
        });
      } else {
        const result = await replayArtifactDecision(item.id);
        setReplay({ id: result.replayId, original: result.originalDecision, evaluation: result.evaluation });
      }
    } catch (error) {
      setReplayError(safeMessage(error));
    } finally {
      setReplayBusy(false);
    }
  }

  async function removeArtifact() {
    if (!window.confirm(`Delete “${item.name}” and its scan, findings, evidence, and decisions? This cannot be undone.`)) return;
    setDeleting(true);
    setDeleteError("");
    try {
      await onDelete();
    } catch (error) {
      setDeleteError(safeMessage(error));
    } finally {
      setDeleting(false);
    }
  }

  if (tab === "passport") {
    if (passportResource.loading) return <Loading>Loading Model Passport...</Loading>;
    if (passportResource.error)
      return (
        <ErrorState
          message={passportResource.error}
          onRetry={passportResource.reload}
        />
      );
    if (passportResource.data) {
      return (
        <PassportView
          passport={passportResource.data}
          onBack={() => go(artifactUrl(item.id, "findings"))}
        />
      );
    }
    return (
      <EmptyState title="Passport unavailable">
        <a href={"#" + artifactUrl(item.id, "findings")}>Back to security findings</a>
      </EmptyState>
    );
  }

  return (
    <>
      <button className="back-link" onClick={() => go("/artifacts")}>
        <ChevronLeft size={15} />
        Back to artifacts
      </button>

      <Heading
        tag="ARTIFACT OVERVIEW"
        title={item.model}
        desc={"Version " + item.version + " - Added " + item.uploadedAt}
        action={
          <div style={{ display: "flex", gap: 8 }}>
            <a
              className="btn outline"
              href={"#" + artifactUrl(item.id, "passport")}
            >
              <Award size={14} />
              Security Passport
            </a>
            <button className="btn outline" onClick={() => window.print()}>
              <FileText size={14} />
              Print record
            </button>
            <button className="btn outline" onClick={runReplay} disabled={replayBusy || item.scanStatus !== "COMPLETED"}>
              <RotateCcw size={14} />
              {replayBusy ? "Replaying..." : "Replay decision"}
            </button>
            <button className="btn outline" onClick={removeArtifact} disabled={deleting} style={{ color: "#b42318", borderColor: "#f0b6b2" }}>
              <Trash2 size={14} />
              {deleting ? "Deleting..." : "Delete artifact"}
            </button>
          </div>
        }
      />
      {deleteError && <p className="form-error" role="alert">{deleteError}</p>}

      <section className="detail-banner">
        <div className="artifact-cell">
          <span className={"file-tile " + item.format.toLowerCase()}>
            <FileCode2 size={18} />
          </span>
          <span>
            <b>{item.name}</b>
            <small>
              {item.id} | {item.format}
            </small>
          </span>
        </div>
        <Status value={item.decision} />
        <span className="hash">
          <Fingerprint size={16} />
          <small>
            SHA-256 <b>{item.hash}</b>
          </small>
        </span>
        <button
          className="btn outline"
          disabled={!/^[a-f0-9]{64}$/i.test(item.hash)}
          onClick={copy}
        >
          Copy hash
        </button>
        {copied && <span role="status">{copied}</span>}
      </section>

      {item.decision === "QUARANTINED" && (
        <p className="quarantine-explanation" role="status">
          {item.reviewRequired
            ? `The policy assessment proposed ${item.policyOutcome || "a non-pass outcome"}. This artifact remains quarantined until a reviewer records an authorized decision.`
            : item.scanStatus === "COMPLETED"
              ? "The scan is complete. The artifact remains quarantined because it requires an explicit governance disposition."
              : "Quarantined on upload. Run the security scan to collect integrity, provenance, and finding evidence before policy evaluation."}
        </p>
      )}

      <section className="detail-card">
        <h2>Artifact details & policy evaluation</h2>
        <div className="overview">
          <span>
            MODEL VERSION<b>{item.version}</b>
          </span>
          <span>
            OWNER<b>{item.uploadedBy}</b>
          </span>
          <span>
            FILE FORMAT<b>{item.format}</b>
          </span>
          <span>
            RECORDED FINDINGS<b>{item.findings}</b>
          </span>
        </div>

        <p>
          Review scan evidence and policy results. Policy-passing artifacts may be approved automatically; other outcomes remain restricted for human review.
        </p>

        <div className="security-links">
          {(["findings", "evidence", "graph", "provenance", "passport"] as const).map(
            (t) => (
              <a
                key={t}
                className={`btn outline ${tab === t ? "primary" : ""}`}
                href={"#" + artifactUrl(item.id, t)}
              >
                {t === "graph"
                  ? "Evidence graph"
                  : t === "passport"
                  ? "Security Passport"
                  : t[0].toUpperCase() + t.slice(1)}
              </a>
            ),
          )}
        </div>
      </section>

      <ScanControl key={item.id} artifactId={item.id} onCompleted={onRefresh} />

      {(replay || replayError || item.scanStatus !== "COMPLETED") && (
        <section className="detail-card decision-replay">
          <h2>Decision replay</h2>
          <p>Re-evaluate the stored scan evidence against the active policy. Replay is recorded separately and does not change the original decision.</p>
          {item.scanStatus !== "COMPLETED" && <p>Complete a scan before replaying a decision.</p>}
          {replayError && <p className="form-error" role="alert">{replayError}</p>}
          {replay && <>
            <div className="overview">
              <span>REPLAY ID<b>{replay.id}</b></span>
              <span>ORIGINAL DECISION<b>{replay.original}</b></span>
              <span>POLICY VERSION<b>{replay.evaluation.policyCode} · {replay.evaluation.policyVersion}</b></span>
              <span>REPLAY OUTCOME<b>{replay.evaluation.overallOutcome}</b></span>
            </div>
            <ul>{replay.evaluation.ruleEvaluations.map((rule) => <li key={rule.ruleCode}>{rule.passed ? "Passed" : rule.action}: {rule.ruleTitle} — {rule.reason}</li>)}</ul>
          </>}
        </section>
      )}

      <SecurityAnalysis
        key={item.id + ":" + revision}
        artifact={item}
        tab={tab || "findings"}
      />

    </>
  );
}
