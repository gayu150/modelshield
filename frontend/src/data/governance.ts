import type { Artifact } from "../types/artifact";
import type { Finding } from "../types/security";
import type {
  AuditEntry,
  DecisionRecord,
  PolicyEvaluation,
  ReleasePolicy,
  RuleEvaluation,
  SecurityPassport,
} from "../types/governance";

export const standardPolicies: ReleasePolicy[] = [
  {
    id: "POL-PROD-004",
    code: "PROD-SEC-004",
    name: "Production Model Security",
    version: "2.0",
    description:
      "Enterprise release standard for customer-facing and production inference pipelines. Blocks release on critical findings or hash mismatches.",
    status: "ACTIVE",
    targetFormats: ["ONNX", "PKL", "PT", "SAFETENSORS", "H5"],
    updatedAt: "2026-10-01T08:00:00Z",
    rules: [
      {
        id: "R-01",
        code: "RULE-CRIT-FAIL",
        title: "Zero Tolerance Critical Findings",
        description: "Release blocked if any CRITICAL severity finding is detected in static or structural analysis.",
        trigger: "CRITICAL",
        action: "BLOCK",
        enabled: true,
      },
      {
        id: "R-02",
        code: "RULE-HIGH-REVIEW",
        title: "High Severity Triage Requirement",
        description: "Artifacts with HIGH severity findings require conditional sign-off with documented mitigation.",
        trigger: "HIGH",
        action: "WARN",
        enabled: true,
      },
      {
        id: "R-03",
        code: "RULE-HASH-INTEGRITY",
        title: "Cryptographic Digest Match",
        description: "Observed file hash during scan must match the uploader SHA-256 fingerprint exactly.",
        trigger: "HASH_MISMATCH",
        action: "BLOCK",
        enabled: true,
      },
      {
        id: "R-04",
        code: "RULE-PROV-CHECK",
        title: "Supply Chain Provenance Verification",
        description: "Artifact source and repository claims must be specified and reviewed.",
        trigger: "UNVERIFIED_PROVENANCE",
        action: "WARN",
        enabled: true,
      },
    ],
  },
  {
    id: "POL-SANDBOX-001",
    code: "DEV-SANDBOX-001",
    name: "Development Sandbox Policy",
    version: "1.1",
    description:
      "Permissive governance tier for internal research and scratchpad experimentation. Warns on vulnerabilities without halting evaluation.",
    status: "ACTIVE",
    targetFormats: ["ONNX", "PKL", "PT", "SAFETENSORS", "H5", "BIN"],
    updatedAt: "2026-09-15T12:00:00Z",
    rules: [
      {
        id: "R-05",
        code: "RULE-HASH-BASIC",
        title: "Digest Sanity Check",
        description: "Blocks corrupted transfers if bytes fail fingerprinting.",
        trigger: "HASH_MISMATCH",
        action: "BLOCK",
        enabled: true,
      },
      {
        id: "R-06",
        code: "RULE-CRIT-WARN",
        title: "Advisory Critical Alert",
        description: "Flags critical issues for developer remediation before staging promotion.",
        trigger: "CRITICAL",
        action: "WARN",
        enabled: true,
      },
    ],
  },
  {
    id: "POL-FIN-009",
    code: "FIN-COMPLY-009",
    name: "Regulated Financial AI Standard",
    version: "3.0",
    description:
      "Strict compliance policy for banking, fraud detection, and credit scoring models under regulatory scrutiny.",
    status: "ACTIVE",
    targetFormats: ["ONNX", "SAFETENSORS"],
    updatedAt: "2026-10-05T09:30:00Z",
    rules: [
      {
        id: "R-07",
        code: "RULE-STRICT-CRIT",
        title: "Critical Security Zero-Tolerance",
        description: "Immediate release veto on any discovered code execution or serialization risk.",
        trigger: "CRITICAL",
        action: "BLOCK",
        enabled: true,
      },
      {
        id: "R-08",
        code: "RULE-STRICT-HIGH",
        title: "High Severity Zero-Tolerance",
        description: "High severity findings unconditionally block release in regulated tiers.",
        trigger: "HIGH",
        action: "BLOCK",
        enabled: true,
      },
      {
        id: "R-09",
        code: "RULE-PROV-MANDATORY",
        title: "Verified Publisher Identity",
        description: "Unverified provenance claims immediately block release.",
        trigger: "UNVERIFIED_PROVENANCE",
        action: "BLOCK",
        enabled: true,
      },
    ],
  },
];

export function evaluateArtifactAgainstPolicy(
  artifact: Artifact,
  policy: ReleasePolicy,
  findings: Finding[] = [],
  observedHash?: string,
): PolicyEvaluation {
  const ruleEvaluations: RuleEvaluation[] = [];
  let overallOutcome: "PASS" | "CONDITIONAL" | "BLOCK" = "PASS";

  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const mediumCount = findings.filter((f) => f.severity === "MEDIUM").length;

  const hashMismatch =
    Boolean(observedHash) &&
    Boolean(artifact.hash) &&
    artifact.hash.toLowerCase() !== (observedHash || "").toLowerCase();

  const unverifiedProv =
    !artifact.provenance ||
    artifact.provenance.verificationStatus === "UNVERIFIED" ||
    artifact.provenance.verificationStatus === "MISSING";

  for (const rule of policy.rules) {
    if (!rule.enabled) continue;
    let failed = false;
    let reason = "Evaluation passed without violations.";

    switch (rule.trigger) {
      case "CRITICAL":
        if (criticalCount > 0) {
          failed = true;
          reason = `Detected ${criticalCount} CRITICAL severity findings in artifact.`;
        }
        break;
      case "HIGH":
        if (highCount > 0) {
          failed = true;
          reason = `Detected ${highCount} HIGH severity findings requiring governance review.`;
        }
        break;
      case "MEDIUM":
        if (mediumCount > 0) {
          failed = true;
          reason = `Detected ${mediumCount} MEDIUM severity findings.`;
        }
        break;
      case "ANY_FINDING":
        if (findings.length > 0) {
          failed = true;
          reason = `Artifact has ${findings.length} total scanner findings.`;
        }
        break;
      case "HASH_MISMATCH":
        if (hashMismatch) {
          failed = true;
          reason = "Observed scan byte digest does not match declared SHA-256.";
        }
        break;
      case "UNVERIFIED_PROVENANCE":
        if (unverifiedProv) {
          failed = true;
          reason = "Uploader provenance origin has not been independently verified.";
        }
        break;
      default:
        break;
    }

    if (failed) {
      if (rule.action === "BLOCK") {
        overallOutcome = "BLOCK";
      } else if (rule.action === "WARN" && overallOutcome !== "BLOCK") {
        overallOutcome = "CONDITIONAL";
      }
    }

    ruleEvaluations.push({
      ruleCode: rule.code,
      ruleTitle: rule.title,
      passed: !failed,
      action: rule.action,
      reason,
    });
  }

  return {
    policyId: policy.id,
    policyCode: policy.code,
    policyName: policy.name,
    policyVersion: policy.version,
    overallOutcome,
    ruleEvaluations,
    evaluatedAt: new Date().toISOString(),
  };
}

export function generateMockPassport(
  artifact: Artifact,
  decision: DecisionRecord,
  policy: ReleasePolicy = standardPolicies[0],
  findings: Finding[] = [],
  observedHash?: string,
): SecurityPassport {
  const evaluation = evaluateArtifactAgainstPolicy(artifact, policy, findings, observedHash);
  const hashMatches = !observedHash || observedHash.toLowerCase() === artifact.hash.toLowerCase();

  const sealDigest = Array.from(crypto.getRandomValues(new Uint8Array(20)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return {
    passportId: "PSP-" + artifact.id.slice(-8).toUpperCase(),
    passportNumber: "MSP-2026-" + Math.floor(100000 + Math.random() * 900000),
    issuedAt: decision.createdAt || new Date().toISOString(),
    status: decision.decision === "BLOCKED" ? "REVOKED" : "VALID",
    artifact: {
      id: artifact.id,
      name: artifact.name,
      model: artifact.model,
      version: artifact.version,
      format: artifact.format,
      sha256: artifact.hash,
      uploadedBy: artifact.uploadedBy,
      uploadedAt: artifact.uploadedAt,
    },
    integrity: {
      hashMatches,
      observedHash: observedHash || artifact.hash,
      expectedHash: artifact.hash,
    },
    provenance: {
      source: artifact.provenance?.source || "Internal Workspace Intake",
      publisher: artifact.provenance?.publisher || artifact.uploadedBy,
      repository: artifact.provenance?.repository || "git://modelshield/registry",
      revision: artifact.provenance?.revision || "v" + artifact.version,
      origin: artifact.provenance?.origin || "Local Intake",
      verificationStatus: artifact.provenance?.verificationStatus || "UNVERIFIED",
    },
    scanSummary: {
      scanner: "ModelAudit 0.2.52 & Structural Engine",
      scannedAt: new Date().toISOString(),
      totalFindings: findings.length,
      criticalCount: findings.filter((f) => f.severity === "CRITICAL").length,
      highCount: findings.filter((f) => f.severity === "HIGH").length,
      mediumCount: findings.filter((f) => f.severity === "MEDIUM").length,
      lowCount: findings.filter((f) => f.severity === "LOW").length,
    },
    policyEvaluation: evaluation,
    decision,
    verificationSeal: {
      algorithm: "SHA256-RSA-MODELSHIELD-SIGN",
      signature: "0x" + sealDigest + "...",
      issuer: "ModelShield Release Governance Authority",
    },
  };
}

export const sampleAuditTrail: AuditEntry[] = [
  {
    id: "AUD-1001",
    timestamp: "2026-10-08T11:30:00Z",
    eventType: "DECISION_RECORDED",
    actor: { id: "USR-01", name: "Priya Sharma", role: "Security Reviewer" },
    targetId: "fraud-detection-v3.pkl",
    targetName: "Fraud Detector v3",
    description: "Recorded conditional release decision pending runtime monitoring.",
    status: "WARNING",
    details: {
      decision: "CONDITIONAL",
      rationale: "Model contains 1 pickle opcode warning; sandbox execution restricted to fraud cluster.",
      conditions: ["Runtime syscall auditing", "30-day review cycle"],
    },
  },
  {
    id: "AUD-1002",
    timestamp: "2026-10-08T10:45:00Z",
    eventType: "POLICY_EVALUATION",
    actor: { id: "SYS-01", name: "Policy Engine", role: "Automated Governance" },
    targetId: "MOD-44",
    targetName: "customer-churn.onnx",
    description: "Evaluated artifact against PROD-SEC-004. Result: PASS (0 blocking rules violated).",
    status: "SUCCESS",
    details: { policy: "PROD-SEC-004", outcome: "PASS" },
  },
  {
    id: "AUD-1003",
    timestamp: "2026-10-08T09:14:00Z",
    eventType: "PASSPORT_GENERATED",
    actor: { id: "USR-01", name: "Priya Sharma", role: "Security Reviewer" },
    targetId: "MOD-44",
    targetName: "customer-churn.onnx",
    description: "Issued Model Security Passport MSP-2026-881902 for production deployment.",
    status: "SUCCESS",
    details: { passportNumber: "MSP-2026-881902", status: "VALID" },
  },
  {
    id: "AUD-1004",
    timestamp: "2026-10-08T08:20:00Z",
    eventType: "SCAN_COMPLETED",
    actor: { id: "SYS-02", name: "ModelAudit Worker", role: "Scanner Engine" },
    targetId: "MOD-43",
    targetName: "resnet50-v2.onnx",
    description: "Scan finished with 0 critical, 0 high findings. Integrity verified.",
    status: "SUCCESS",
    details: { findingsCount: 0, durationMs: 1420 },
  },
  {
    id: "AUD-1005",
    timestamp: "2026-10-08T07:12:00Z",
    eventType: "ARTIFACT_UPLOAD",
    actor: { id: "USR-02", name: "Arjun Mehta", role: "ML Engineer" },
    targetId: "MOD-43",
    targetName: "resnet50-v2.onnx",
    description: "Uploaded model artifact. Automatically placed in QUARANTINED state.",
    status: "SUCCESS",
    details: { format: "ONNX", size: "98.4 MB" },
  },
];
