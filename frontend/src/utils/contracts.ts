import type { Artifact } from "../types/artifact";
import type { User } from "../types/auth";
import type {
  Evidence,
  EvidenceGraph,
  Finding,
  Provenance,
  RiskSummary,
} from "../types/security";
import type {
  AuditEntry,
  DecisionRecord,
  PolicyEvaluation,
  PolicyRule,
  ReleasePolicy,
  RuleEvaluation,
  SecurityPassport,
} from "../types/governance";

export function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Invalid API response.");
  return value as Record<string, unknown>;
}
export function text(value: unknown): string {
  if (typeof value !== "string") throw new Error("Invalid API response.");
  return value;
}
export function identifier(value: unknown): string {
  const result = text(value);
  if (!result.trim()) throw new Error("Invalid response identifier.");
  return result;
}
export function enumValue<T extends string>(
  value: unknown,
  choices: readonly T[],
): T {
  if (!choices.includes(value as T)) throw new Error("Invalid API response.");
  return value as T;
}
export function array<T>(value: unknown, parse: (item: unknown) => T): T[] {
  if (!Array.isArray(value)) throw new Error("Invalid API response.");
  return value.map(parse);
}
function identifiers<T extends { id: string }>(items: T[]): T[] {
  if (
    items.some((x) => !x.id) ||
    new Set(items.map((x) => x.id)).size !== items.length
  )
    throw new Error("Invalid or duplicate response identifiers.");
  return items;
}
export function parseUser(value: unknown): User {
  const v = record(value);
  return {
    id: identifier(v.id),
    email: text(v.email),
    name: text(v.name),
    role: text(v.role),
  };
}
export function parseProvenance(value: unknown): Provenance {
  if (value === undefined || value === null) return {};
  const v = record(value);
  const result: Provenance = {};
  for (const key of [
    "source",
    "publisher",
    "repository",
    "revision",
    "origin",
    "expectedHash",
    "observedHash",
  ] as const)
    if (v[key] != null) result[key] = text(v[key]);
  if (v.signatureStatus != null)
    result.signatureStatus = enumValue(v.signatureStatus, [
      "VERIFIED",
      "INVALID",
      "MISSING",
      "UNKNOWN",
    ] as const);
  if (v.verificationStatus != null)
    result.verificationStatus = enumValue(v.verificationStatus, [
      "UNVERIFIED", "MISSING", "VERIFIED", "CONFLICTING", "UNKNOWN",
    ] as const);
  return result;
}
export function parseArtifact(value: unknown): Artifact {
  const v = record(value);
  if (
    typeof v.findings !== "number" ||
    !Number.isInteger(v.findings) ||
    v.findings < 0
  )
    throw new Error("Invalid API response.");
  return {
    id: identifier(v.id),
    name: text(v.name),
    model: text(v.model),
    version: text(v.version),
    format: text(v.format),
    uploadedBy: text(v.uploadedBy),
    uploadedAt: text(v.uploadedAt),
    hash: text(v.hash),
    decision: enumValue(v.decision, [
      "APPROVED",
      "CONDITIONAL",
      "QUARANTINED",
      "BLOCKED",
    ]),
    findings: v.findings,
    provenance: parseProvenance(v.provenance),
    ...(v.scanStatus === undefined ? {} : { scanStatus: enumValue(v.scanStatus, ["NOT_SCANNED", "QUEUED", "RUNNING", "COMPLETED", "FAILED"] as const) }),
    ...(v.policyOutcome === undefined || v.policyOutcome === null ? {} : { policyOutcome: enumValue(v.policyOutcome, ["APPROVED", "CONDITIONAL", "QUARANTINED", "BLOCKED", "PASS", "BLOCK"] as const) }),
    ...(v.reviewRequired === undefined ? {} : { reviewRequired: v.reviewRequired === true }),
  };
}
export const parseArtifacts = (value: unknown) =>
  identifiers(array(value, parseArtifact));
export function parseFinding(value: unknown): Finding {
  const v = record(value);
  return {
    id: identifier(v.id),
    title: text(v.title),
    description: text(v.description),
    severity: enumValue(v.severity, [
      "CRITICAL",
      "HIGH",
      "MEDIUM",
      "LOW",
      "INFO",
    ]),
    scanner: text(v.scanner),
    scannerVersion: text(v.scannerVersion),
    evidenceIds: array(v.evidenceIds, text),
    recommendation: text(v.recommendation),
  };
}
export const parseFindings = (value: unknown) =>
  identifiers(array(value, parseFinding));
export function parseEvidence(value: unknown): Evidence[] {
  return identifiers(
    array(value, (item) => {
      const v = record(item);
      const timestamp = text(v.timestamp);
      if (!Number.isFinite(Date.parse(timestamp)))
        throw new Error("Invalid evidence timestamp.");
      const evidence: Evidence = {
        id: identifier(v.id),
        title: text(v.title),
        kind: text(v.kind),
        timestamp,
        summary: text(v.summary),
        content: text(v.content),
        scanner: text(v.scanner),
      };
      for (const key of ["artifactId", "scanId", "source", "findingType", "location"] as const)
        if (v[key] != null) evidence[key] = text(v[key]);
      if (v.severity != null) evidence.severity = enumValue(v.severity, ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const);
      if (v.verificationStatus != null) evidence.verificationStatus = enumValue(v.verificationStatus, ["OBSERVED", "UNVERIFIED"] as const);
      return evidence;
    }),
  );
}
export function parseGraph(value: unknown): EvidenceGraph {
  const v = record(value);
  const nodes = identifiers(
    array(v.nodes, (item) => {
      const n = record(item);
      return { id: identifier(n.id), label: text(n.label), kind: text(n.kind) };
    }),
  );
  const ids = new Set(nodes.map((x) => x.id));
  const edges = array(v.edges, (item) => {
    const e = record(item);
    const source = text(e.source),
      target = text(e.target);
    if (!ids.has(source) || !ids.has(target))
      throw new Error("Graph references an unknown node.");
    return { source, target, label: text(e.label) };
  });
  return { nodes, edges };
}
export function parseRisk(value: unknown): RiskSummary {
  const v = record(value);
  const counts = record(v.findingCounts);
  const findingCounts = {} as RiskSummary["findingCounts"];
  for (const level of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const) {
    const count = counts[level];
    if (typeof count !== "number" || !Number.isInteger(count) || count < 0)
      throw new Error("Invalid risk count.");
    findingCounts[level] = count;
  }
  return {
    state: enumValue(v.state, ["INVESTIGATE", "INCOMPLETE"] as const),
    reasons: array(v.reasons, text), findingCounts,
    integrity: enumValue(v.integrity, ["MATCH", "MISMATCH", "UNKNOWN"] as const),
    provenance: enumValue(v.provenance, ["UNVERIFIED", "MISSING"] as const),
    signature: enumValue(v.signature, ["UNKNOWN"] as const),
    scanStatus: enumValue(v.scanStatus, ["NOT_SCANNED", "QUEUED", "RUNNING", "COMPLETED", "FAILED"] as const),
  };
}
export type Scan = {
  id: string;
  status: "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  progress?: number;
  error?: string;
  modelAuditStatus?: "UNKNOWN" | "RUNNING" | "COMPLETED" | "FAILED";
  modelAuditError?: string;
};
export function parseScan(value: unknown): Scan {
  const v = record(value);
  const result: Scan = {
    id: identifier(v.id),
    status: enumValue(v.status, ["QUEUED", "RUNNING", "COMPLETED", "FAILED"]),
  };
  if (v.progress !== undefined) {
    if (
      typeof v.progress !== "number" ||
      !Number.isFinite(v.progress) ||
      v.progress < 0 ||
      v.progress > 100
    )
      throw new Error("Invalid scan progress.");
    result.progress = v.progress;
  }
  if (v.error != null) result.error = text(v.error);
  if (v.modelAuditStatus != null) result.modelAuditStatus = enumValue(v.modelAuditStatus, ["UNKNOWN", "RUNNING", "COMPLETED", "FAILED"] as const);
  if (v.modelAuditError != null) result.modelAuditError = text(v.modelAuditError);
  return result;
}

export function parsePolicyRule(value: unknown): PolicyRule {
  const v = record(value);
  return {
    id: identifier(v.id),
    code: text(v.code),
    title: text(v.title),
    description: text(v.description),
    trigger: enumValue(v.trigger, [
      "CRITICAL",
      "HIGH",
      "MEDIUM",
      "LOW",
      "INFO",
      "ANY_FINDING",
      "HASH_MISMATCH",
      "UNVERIFIED_PROVENANCE",
      "UNVERIFIED_SIGNATURE",
      "INVALID_SIGNATURE",
      "CONFIRMED_MALICIOUS",
      "SCAN_FAILED",
      "SCAN_INCOMPLETE",
      "UNSUPPORTED_FORMAT",
    ]),
    action: enumValue(v.action, ["BLOCK", "QUARANTINE", "WARN", "CONDITIONAL", "ALLOW"]),
    enabled: typeof v.enabled === "boolean" ? v.enabled : true,
  };
}

export function parsePolicy(value: unknown): ReleasePolicy {
  const v = record(value);
  return {
    id: identifier(v.id),
    code: text(v.code),
    name: text(v.name),
    version: text(v.version),
    description: text(v.description),
    status: enumValue(v.status, ["ACTIVE", "DRAFT", "DEPRECATED"]),
    rules: array(v.rules, parsePolicyRule),
    targetFormats: array(v.targetFormats, text),
    updatedAt: text(v.updatedAt),
  };
}

export const parsePolicies = (value: unknown) =>
  identifiers(array(value, parsePolicy));

export function parseRuleEvaluation(value: unknown): RuleEvaluation {
  const v = record(value);
  return {
    ruleCode: text(v.ruleCode),
    ruleTitle: text(v.ruleTitle),
    passed: Boolean(v.passed),
    action: enumValue(v.action, ["BLOCK", "QUARANTINE", "WARN", "CONDITIONAL", "ALLOW"]),
    reason: text(v.reason),
  };
}

export function parsePolicyEvaluation(value: unknown): PolicyEvaluation {
  const v = record(value);
  return {
    ...(v.evaluationId == null ? {} : { evaluationId: identifier(v.evaluationId) }),
    ...(v.artifactId == null ? {} : { artifactId: identifier(v.artifactId) }),
    policyId: identifier(v.policyId),
    policyCode: text(v.policyCode),
    policyName: text(v.policyName),
    policyVersion: text(v.policyVersion),
    overallOutcome: enumValue(v.overallOutcome, [
      "APPROVED",
      "QUARANTINED",
      "BLOCKED",
      "PASS",
      "CONDITIONAL",
      "BLOCK",
    ]),
    ruleEvaluations: array(v.ruleEvaluations, parseRuleEvaluation),
    evaluatedAt: text(v.evaluatedAt),
    ...(v.unknownSignals == null ? {} : { unknownSignals: array(v.unknownSignals, text) }),
    ...(v.requiresHumanReview == null ? {} : { requiresHumanReview: v.requiresHumanReview === true }),
    ...(v.evidenceReferences == null ? {} : { evidenceReferences: array(v.evidenceReferences, text) }),
  };
}

export function parseDecisionRecord(value: unknown): DecisionRecord {
  const v = record(value);
  const result: DecisionRecord = {
    id: identifier(v.id),
    artifactId: identifier(v.artifactId),
    decision: enumValue(v.decision, [
      "APPROVED",
      "CONDITIONAL",
      "QUARANTINED",
      "BLOCKED",
    ]),
    rationale: text(v.rationale),
    reviewerId: identifier(v.reviewerId),
    reviewerName: text(v.reviewerName),
    reviewerRole: text(v.reviewerRole),
    createdAt: text(v.createdAt),
  };
  if (v.conditions != null) result.conditions = array(v.conditions, text);
  if (v.validUntil != null) result.validUntil = text(v.validUntil);
  if (v.signature != null) result.signature = text(v.signature);
  return result;
}

export const parseDecisionRecords = (value: unknown) =>
  identifiers(array(value, parseDecisionRecord));

export function parseSecurityPassport(value: unknown): SecurityPassport {
  const v = record(value);
  const art = record(v.artifact);
  const integ = record(v.integrity);
  const prov = record(v.provenance);
  const scan = record(v.scanSummary);
  const seal = record(v.verificationSeal);

  return {
    passportId: identifier(v.passportId),
    passportNumber: text(v.passportNumber),
    issuedAt: text(v.issuedAt),
    status: enumValue(v.status, ["VALID", "CONDITIONAL", "PENDING", "REVOKED", "EXPIRED"]),
    artifact: {
      id: identifier(art.id),
      name: text(art.name),
      model: text(art.model),
      version: text(art.version),
      format: text(art.format),
      sha256: text(art.sha256),
      uploadedBy: text(art.uploadedBy),
      uploadedAt: text(art.uploadedAt),
    },
    integrity: {
      hashMatches: Boolean(integ.hashMatches),
      observedHash: text(integ.observedHash),
      expectedHash: text(integ.expectedHash),
    },
    provenance: {
      source: prov.source != null ? text(prov.source) : undefined,
      publisher: prov.publisher != null ? text(prov.publisher) : undefined,
      repository: prov.repository != null ? text(prov.repository) : undefined,
      revision: prov.revision != null ? text(prov.revision) : undefined,
      origin: prov.origin != null ? text(prov.origin) : undefined,
      verificationStatus: text(prov.verificationStatus),
    },
    scanSummary: {
      scanner: text(scan.scanner),
      scannedAt: scan.scannedAt != null ? text(scan.scannedAt) : undefined,
      totalFindings: Number(scan.totalFindings) || 0,
      criticalCount: Number(scan.criticalCount) || 0,
      highCount: Number(scan.highCount) || 0,
      mediumCount: Number(scan.mediumCount) || 0,
      lowCount: Number(scan.lowCount) || 0,
    },
    policyEvaluation: parsePolicyEvaluation(v.policyEvaluation),
    decision: parseDecisionRecord(v.decision),
    verificationSeal: {
      algorithm: text(seal.algorithm),
      signature: text(seal.signature),
      issuer: text(seal.issuer),
    },
  };
}

export function parseAuditEntry(value: unknown): AuditEntry {
  const v = record(value);
  const actor = record(v.actor);
  const timestamp = text(v.timestamp);
  if (!Number.isFinite(Date.parse(timestamp))) {
    throw new Error("Invalid audit timestamp.");
  }
  const result: AuditEntry = {
    id: identifier(v.id),
    timestamp,
    eventType: enumValue(v.eventType, [
      "ARTIFACT_UPLOAD",
      "ARTIFACT_DELETED",
      "SCAN_STARTED",
      "SCAN_COMPLETED",
      "POLICY_EVALUATION",
      "DECISION_RECORDED",
      "DECISION_REPLAY",
      "PASSPORT_GENERATED",
      "USER_LOGIN",
      "USER_LOGOUT",
    ]),
    actor: {
      id: identifier(actor.id),
      name: text(actor.name),
      role: text(actor.role),
    },
    description: text(v.description),
    status: enumValue(v.status, ["SUCCESS", "WARNING", "FAILURE"]),
  };
  if (v.targetId != null) result.targetId = text(v.targetId);
  if (v.targetName != null) result.targetName = text(v.targetName);
  if (v.details != null && typeof v.details === "object") {
    result.details = v.details as Record<string, unknown>;
  }
  return result;
}

export const parseAuditTrail = (value: unknown) =>
  identifiers(array(value, parseAuditEntry));

