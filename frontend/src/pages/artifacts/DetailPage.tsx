import { useState } from "react";
import {
  Award,
  ChevronLeft,
  FileCheck,
  FileCode2,
  FileText,
  Fingerprint,
} from "lucide-react";
import type { Artifact } from "../../types/artifact";
import type { SecurityPassport } from "../../types/governance";
import { artifactUrl, go, type SecurityTab } from "../../routes";
import { Heading, Status } from "../../components/common/Registry";
import SecurityAnalysis from "../security/SecurityAnalysis";
import ScanControl from "../../components/artifacts/ScanControl";
import DecisionModal from "../../components/governance/DecisionModal";
import PassportView from "../../components/governance/PassportView";
import { useResource } from "../../hooks/useResource";
import { DEMO_MODE } from "../../config";
import { generateMockPassport } from "../../data/governance";
import { getSecurityPassport } from "../../services/api/governance";
import { EmptyState, ErrorState, Loading } from "../../components/common/Feedback";
import "./workflow.css";

export default function DetailPage({
  item,
  tab,
  revision,
  onRefresh,
}: {
  item: Artifact;
  tab?: SecurityTab;
  revision: number;
  onRefresh: () => void;
}) {
  const [copied, setCopied] = useState("");
  const [showDecisionModal, setShowDecisionModal] = useState(tab === "decision");

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
            <button
              className="btn primary"
              onClick={() => setShowDecisionModal(true)}
            >
              <FileCheck size={14} />
              Record Decision
            </button>
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
          </div>
        }
      />

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
          Automatically marked QUARANTINED on upload. Review security evidence and evaluate against release policies to record an authorized approval decision.
        </p>
      )}

      <section className="detail-card">
        <h2>Artifact information & Governance</h2>
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
          Inspect scanner evidence, evaluated policies, and generate an official security passport.
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

      <SecurityAnalysis
        key={item.id + ":" + revision}
        artifact={item}
        tab={tab === "decision" ? "findings" : tab || "findings"}
      />

      {showDecisionModal && (
        <DecisionModal
          artifact={item}
          onClose={() => setShowDecisionModal(false)}
          onSuccess={() => {
            setShowDecisionModal(false);
            onRefresh();
          }}
        />
      )}
    </>
  );
}
