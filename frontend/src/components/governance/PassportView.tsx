import { useState } from "react";
import {
  Award,
  CheckCircle2,
  ChevronLeft,
  Download,
  FileCheck,
  Fingerprint,
  Printer,
  Shield,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { SecurityPassport } from "../../types/governance";

export default function PassportView({
  passport,
  onBack,
}: {
  passport: SecurityPassport;
  onBack?: () => void;
}) {
  const [copied, setCopied] = useState(false);

  function handleExportJson() {
    const dataStr =
      "data:text/json;charset=utf-8," +
      encodeURIComponent(JSON.stringify(passport, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute(
      "download",
      `model-passport-${passport.passportNumber}.json`,
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  }

  function handleCopySignature() {
    navigator.clipboard.writeText(passport.verificationSeal.signature);
    setCopied(true);
    setTimeout(() => setCopied(false), 3000);
  }

  const isApproved = passport.decision.decision === "APPROVED";
  const isBlocked = passport.decision.decision === "BLOCKED";
  const isConditional = passport.decision.decision === "CONDITIONAL";

  return (
    <div>
      {onBack && (
        <button className="back-link" onClick={onBack}>
          <ChevronLeft size={15} />
          Back to artifact
        </button>
      )}

      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <div className="section-head" style={{ margin: 0 }}>
          <div className="kicker"><i />RELEASE ATTESTATION</div>
          <h2>Model Security Passport</h2>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button className="btn outline" onClick={handleExportJson}>
            <Download size={14} />
            Export JSON
          </button>
          <button className="btn outline" onClick={() => window.print()}>
            <Printer size={14} />
            Print Certificate
          </button>
        </div>
      </div>

      <div className="passport-container">
        {/* Top Header */}
        <div className="passport-topbar">
          <div className="passport-brand-group">
            <div className="passport-shield-icon">
              <Shield size={26} />
            </div>
            <div>
              <span style={{ fontSize: 11, letterSpacing: 1.5, opacity: 0.8, fontWeight: 700 }}>
                MODELSHIELD SECURITY PASSPORT
              </span>
              <h1 style={{ fontSize: 24, margin: "2px 0 0", color: "#ffffff", fontWeight: 700 }}>
                {passport.artifact.model}
              </h1>
              <span style={{ fontSize: 12, opacity: 0.9 }}>
                Version {passport.artifact.version} • {passport.artifact.format}
              </span>
            </div>
          </div>

          <div style={{ textAlign: "right" }}>
            <span
              className={`policy-tag ${passport.status === "VALID" ? "active" : "deprecated"}`}
              style={{ fontSize: 13, padding: "5px 12px" }}
            >
              {passport.status === "VALID" ? (
                <>
                  <ShieldCheck size={14} /> PASSPORT VALID
                </>
              ) : (
                <>
                  <ShieldAlert size={14} /> REVOKED
                </>
              )}
            </span>
            <div style={{ marginTop: 6, fontSize: 12, opacity: 0.8 }}>
              Passport No: <b>{passport.passportNumber}</b>
            </div>
            <div style={{ fontSize: 11, opacity: 0.7 }}>
              Issued: {new Date(passport.issuedAt).toLocaleDateString()}
            </div>
          </div>
        </div>

        {/* Identity & Digest Meta Grid */}
        <div className="passport-meta-grid">
          <div className="passport-field">
            <label>Artifact Identifier</label>
            <span>{passport.artifact.id}</span>
          </div>
          <div className="passport-field">
            <label>File Name</label>
            <span>{passport.artifact.name}</span>
          </div>
          <div className="passport-field">
            <label>Integrity Digest (SHA-256)</label>
            <span style={{ fontFamily: "monospace", fontSize: 11 }}>
              {passport.artifact.sha256.slice(0, 20)}...
            </span>
          </div>
          <div className="passport-field">
            <label>Hash Match Status</label>
            <span style={{ color: passport.integrity.hashMatches ? "#168b64" : "#c74752" }}>
              {passport.integrity.hashMatches ? "✓ Verified Match" : "✗ Hash Mismatch"}
            </span>
          </div>
        </div>

        {/* Passport Body Sections */}
        <div className="passport-sections">
          {/* Section 1: Governance Release Decision */}
          <div
            className={`decision-card ${passport.decision.decision.toLowerCase()}`}
            style={{ margin: 0 }}
          >
            <small>AUTHORIZED GOVERNANCE DECISION</small>
            <div style={{ display: "flex", alignItems: "center", gap: 10, margin: "8px 0" }}>
              {isApproved && <ShieldCheck size={28} color="#10b981" />}
              {isConditional && <Award size={28} color="#f59e0b" />}
              {isBlocked && <ShieldAlert size={28} color="#ef4444" />}
              <div>
                <h2 style={{ fontSize: 20 }}>{passport.decision.decision}</h2>
                <span style={{ fontSize: 12 }}>
                  Sign-off by <b>{passport.decision.reviewerName}</b> ({passport.decision.reviewerRole}) on{" "}
                  {new Date(passport.decision.createdAt).toLocaleString()}
                </span>
              </div>
            </div>
            <p style={{ marginTop: 8 }}>
              <b>Rationale:</b> {passport.decision.rationale}
            </p>
            {passport.decision.conditions && passport.decision.conditions.length > 0 && (
              <div style={{ marginTop: 10, fontSize: 11 }}>
                <b>Operational Conditions:</b>
                <ul style={{ margin: "4px 0 0 16px", padding: 0 }}>
                  {passport.decision.conditions.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          {/* Section 2: Security & Scanner Breakdown */}
          <div className="passport-section-card">
            <div className="passport-section-title">
              <Fingerprint size={16} />
              Security Verification & Findings
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 12 }}>
              <div style={{ background: "#f8fafc", padding: 10, borderRadius: 8 }}>
                <span style={{ fontSize: 11, color: "#64748b" }}>Critical Findings</span>
                <b style={{ display: "block", fontSize: 18, color: passport.scanSummary.criticalCount ? "#dc2626" : "#10b981" }}>
                  {passport.scanSummary.criticalCount}
                </b>
              </div>
              <div style={{ background: "#f8fafc", padding: 10, borderRadius: 8 }}>
                <span style={{ fontSize: 11, color: "#64748b" }}>High Findings</span>
                <b style={{ display: "block", fontSize: 18, color: passport.scanSummary.highCount ? "#f59e0b" : "#10b981" }}>
                  {passport.scanSummary.highCount}
                </b>
              </div>
              <div style={{ background: "#f8fafc", padding: 10, borderRadius: 8 }}>
                <span style={{ fontSize: 11, color: "#64748b" }}>Medium Findings</span>
                <b style={{ display: "block", fontSize: 18, color: "#475569" }}>
                  {passport.scanSummary.mediumCount}
                </b>
              </div>
              <div style={{ background: "#f8fafc", padding: 10, borderRadius: 8 }}>
                <span style={{ fontSize: 11, color: "#64748b" }}>Total Findings</span>
                <b style={{ display: "block", fontSize: 18, color: "#1e293b" }}>
                  {passport.scanSummary.totalFindings}
                </b>
              </div>
            </div>
            <div style={{ marginTop: 10, fontSize: 11, color: "#64748b" }}>
              Scanner Engine: <b>{passport.scanSummary.scanner}</b> • Scanned:{" "}
              {passport.scanSummary.scannedAt ? new Date(passport.scanSummary.scannedAt).toLocaleString() : "Pre-release"}
            </div>
          </div>

          {/* Section 3: Policy Compliance Evaluation */}
          <div className="passport-section-card">
            <div className="passport-section-title">
              <FileCheck size={16} />
              Release Policy Evaluation: {passport.policyEvaluation.policyCode} (v{passport.policyEvaluation.policyVersion})
            </div>
            <div
              className={`compliance-status-banner ${passport.policyEvaluation.overallOutcome.toLowerCase()}`}
              style={{ marginBottom: 12 }}
            >
              <CheckCircle2 size={16} />
              <span>Overall Compliance: {passport.policyEvaluation.overallOutcome}</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 6, fontSize: 12 }}>
              {passport.policyEvaluation.ruleEvaluations.map((r) => (
                <div
                  key={r.ruleCode}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    padding: "6px 8px",
                    background: "#f8fafc",
                    borderRadius: 6,
                  }}
                >
                  <span>
                    <b>{r.ruleCode}</b>: {r.ruleTitle}
                  </span>
                  <span style={{ color: r.passed ? "#166534" : "#991b1b", fontWeight: 600 }}>
                    {r.passed ? "✓ Passed" : `✗ Action: ${r.action}`}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Section 4: Provenance Claim */}
          <div className="passport-section-card">
            <div className="passport-section-title">
              <Award size={16} />
              Supply Chain Provenance Assertion
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: 12, fontSize: 12 }}>
              <div>Source: <b>{passport.provenance.source || "None declared"}</b></div>
              <div>Publisher: <b>{passport.provenance.publisher || "None declared"}</b></div>
              <div>Repository: <b>{passport.provenance.repository || "None declared"}</b></div>
              <div>Verification: <b>{passport.provenance.verificationStatus}</b></div>
            </div>
          </div>
        </div>

        {/* Cryptographic Verification Seal Footer */}
        <div className="passport-seal-footer">
          <div className="seal-info">
            <span>ISSUED BY: {passport.verificationSeal.issuer}</span>
            <span>ALGORITHM: {passport.verificationSeal.algorithm}</span>
            <span style={{ wordBreak: "break-all" }}>
              SIGNATURE SEAL: <b>{passport.verificationSeal.signature}</b>
            </span>
          </div>
          <div>
            <button className="btn outline" onClick={handleCopySignature}>
              {copied ? "Copied Seal" : "Copy Signature Seal"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
