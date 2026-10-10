import type { Artifact, Decision } from "./artifact";

export type RuleSeverity = "BLOCK" | "QUARANTINE" | "WARN" | "CONDITIONAL" | "ALLOW";

export type PolicyRuleTrigger =
  | "CRITICAL"
  | "HIGH"
  | "MEDIUM"
  | "LOW"
  | "INFO"
  | "ANY_FINDING"
  | "HASH_MISMATCH"
  | "UNVERIFIED_PROVENANCE"
  | "UNVERIFIED_SIGNATURE"
  | "INVALID_SIGNATURE"
  | "CONFIRMED_MALICIOUS"
  | "SCAN_FAILED"
  | "SCAN_INCOMPLETE"
  | "UNSUPPORTED_FORMAT";

export type PolicyRule = {
  id: string;
  code: string;
  title: string;
  description: string;
  trigger: PolicyRuleTrigger;
  action: RuleSeverity;
  enabled: boolean;
};

export type ReleasePolicy = {
  id: string;
  code: string;
  name: string;
  version: string;
  description: string;
  status: "ACTIVE" | "DRAFT" | "DEPRECATED";
  rules: PolicyRule[];
  targetFormats: string[];
  updatedAt: string;
};

export type RuleEvaluation = {
  ruleCode: string;
  ruleTitle: string;
  passed: boolean;
  action: RuleSeverity;
  reason: string;
};

export type PolicyEvaluation = {
  evaluationId?: string;
  artifactId?: string;
  policyId: string;
  policyCode: string;
  policyName: string;
  policyVersion: string;
  overallOutcome: "APPROVED" | "CONDITIONAL" | "QUARANTINED" | "BLOCKED" | "PASS" | "BLOCK";
  ruleEvaluations: RuleEvaluation[];
  evaluatedAt: string;
  unknownSignals?: string[];
  requiresHumanReview?: boolean;
  evidenceReferences?: string[];
};

export type DecisionRecord = {
  id: string;
  artifactId: string;
  decision: Decision;
  rationale: string;
  conditions?: string[];
  reviewerId: string;
  reviewerName: string;
  reviewerRole: string;
  validUntil?: string;
  createdAt: string;
  signature?: string;
};

export type SecurityPassport = {
  passportId: string;
  passportNumber: string;
  issuedAt: string;
  status: "VALID" | "CONDITIONAL" | "PENDING" | "REVOKED" | "EXPIRED";
  artifact: {
    id: string;
    name: string;
    model: string;
    version: string;
    format: string;
    sha256: string;
    uploadedBy: string;
    uploadedAt: string;
  };
  integrity: {
    hashMatches: boolean;
    observedHash: string;
    expectedHash: string;
  };
  provenance: {
    source?: string;
    publisher?: string;
    repository?: string;
    revision?: string;
    origin?: string;
    verificationStatus: string;
  };
  scanSummary: {
    scanner: string;
    scannedAt?: string;
    totalFindings: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
  };
  policyEvaluation: PolicyEvaluation;
  decision: DecisionRecord;
  verificationSeal: {
    algorithm: string;
    signature: string;
    issuer: string;
  };
};

export type AuditEventType =
  | "ARTIFACT_UPLOAD"
  | "ARTIFACT_DELETED"
  | "SCAN_STARTED"
  | "SCAN_COMPLETED"
  | "POLICY_EVALUATION"
  | "DECISION_RECORDED"
  | "DECISION_REPLAY"
  | "PASSPORT_GENERATED"
  | "USER_LOGIN"
  | "USER_LOGOUT";

export type AuditEntry = {
  id: string;
  timestamp: string;
  eventType: AuditEventType;
  actor: {
    id: string;
    name: string;
    role: string;
  };
  targetId?: string;
  targetName?: string;
  description: string;
  details?: Record<string, unknown>;
  status: "SUCCESS" | "WARNING" | "FAILURE";
};
