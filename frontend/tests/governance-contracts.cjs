const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  parsePolicy,
  parsePolicies,
  parsePolicyEvaluation,
  parseDecisionRecord,
  parseDecisionRecords,
  parseSecurityPassport,
  parseAuditEntry,
  parseAuditTrail,
} = require("../src/utils/contracts.ts");
const {
  standardPolicies,
  evaluateArtifactAgainstPolicy,
  generateMockPassport,
} = require("../src/data/governance.ts");

const mockPolicy = {
  id: "POL-01",
  code: "POL-TEST-001",
  name: "Test Policy",
  version: "1.0",
  description: "Test description",
  status: "ACTIVE",
  targetFormats: ["ONNX"],
  updatedAt: "2026-10-01T00:00:00Z",
  rules: [
    {
      id: "R-1",
      code: "RULE-CRIT",
      title: "Block Critical",
      description: "Blocks on critical",
      trigger: "CRITICAL",
      action: "BLOCK",
      enabled: true,
    },
  ],
};

const mockDecision = {
  id: "DEC-1",
  artifactId: "ART-1",
  decision: "APPROVED",
  rationale: "Model passed all integrity and security checks.",
  reviewerId: "USR-1",
  reviewerName: "Priya Sharma",
  reviewerRole: "Security Reviewer",
  createdAt: "2026-10-08T10:00:00Z",
};

test("policy contracts validate rule structures and reject duplicate policy IDs", () => {
  const parsed = parsePolicy(mockPolicy);
  assert.equal(parsed.code, "POL-TEST-001");
  assert.equal(parsed.rules.length, 1);
  assert.equal(parsed.rules[0].action, "BLOCK");

  assert.throws(() => parsePolicy({ ...mockPolicy, status: "INVALID_STATUS" }));
  assert.throws(() =>
    parsePolicy({
      ...mockPolicy,
      rules: [{ ...mockPolicy.rules[0], trigger: "UNKNOWN_TRIGGER" }],
    }),
  );
  assert.throws(() => parsePolicies([mockPolicy, mockPolicy]));
});

test("decision contracts validate state transitions and reviewer identities", () => {
  const parsed = parseDecisionRecord(mockDecision);
  assert.equal(parsed.decision, "APPROVED");
  assert.equal(parsed.reviewerName, "Priya Sharma");

  assert.throws(() =>
    parseDecisionRecord({ ...mockDecision, decision: "INVALID_DECISION" }),
  );
  assert.throws(() =>
    parseDecisionRecord({ ...mockDecision, reviewerId: "" }),
  );
  assert.throws(() => parseDecisionRecords([mockDecision, mockDecision]));
});

test("passport contracts require complete integrity, scan, and seal details", () => {
  const mockPassport = {
    passportId: "PSP-100",
    passportNumber: "MSP-2026-123456",
    issuedAt: "2026-10-08T10:00:00Z",
    status: "VALID",
    artifact: {
      id: "ART-1",
      name: "model.onnx",
      model: "Model",
      version: "1.0",
      format: "ONNX",
      sha256: "a".repeat(64),
      uploadedBy: "Tester",
      uploadedAt: "2026-10-01T00:00:00Z",
    },
    integrity: {
      hashMatches: true,
      observedHash: "a".repeat(64),
      expectedHash: "a".repeat(64),
    },
    provenance: {
      verificationStatus: "VERIFIED",
    },
    scanSummary: {
      scanner: "ModelAudit",
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
    },
    policyEvaluation: {
      policyId: "POL-01",
      policyCode: "POL-TEST-001",
      policyName: "Test Policy",
      policyVersion: "1.0",
      overallOutcome: "PASS",
      ruleEvaluations: [],
      evaluatedAt: "2026-10-08T10:00:00Z",
    },
    decision: mockDecision,
    verificationSeal: {
      algorithm: "SHA256-RSA",
      signature: "0x1234abcd",
      issuer: "ModelShield Release Authority",
    },
  };

  const parsed = parseSecurityPassport(mockPassport);
  assert.equal(parsed.passportNumber, "MSP-2026-123456");
  assert.equal(parsed.integrity.hashMatches, true);
  assert.equal(parsed.decision.decision, "APPROVED");

  assert.throws(() =>
    parseSecurityPassport({ ...mockPassport, status: "INVALID_STATUS" }),
  );
  assert.throws(() =>
    parseSecurityPassport({
      ...mockPassport,
      integrity: { ...mockPassport.integrity, observedHash: 123 },
    }),
  );
});

test("audit contracts reject invalid timestamps and unclassified event types", () => {
  const mockAudit = {
    id: "AUD-1",
    timestamp: "2026-10-08T10:00:00Z",
    eventType: "DECISION_RECORDED",
    actor: { id: "USR-1", name: "Priya", role: "Reviewer" },
    description: "Approved model",
    status: "SUCCESS",
  };

  assert.equal(parseAuditEntry(mockAudit).eventType, "DECISION_RECORDED");
  assert.throws(() =>
    parseAuditEntry({ ...mockAudit, eventType: "UNRECOGNIZED_EVENT" }),
  );
  assert.throws(() =>
    parseAuditEntry({ ...mockAudit, timestamp: "not-a-timestamp" }),
  );
  assert.throws(() => parseAuditTrail([mockAudit, mockAudit]));
});

test("policy evaluation engine enforces zero-tolerance on critical findings and hash mismatches", () => {
  const artifact = {
    id: "ART-TEST",
    name: "model.onnx",
    model: "Detector",
    version: "1.0",
    format: "ONNX",
    uploadedBy: "Tester",
    uploadedAt: "2026-10-01T00:00:00Z",
    decision: "QUARANTINED",
    findings: 1,
    hash: "a".repeat(64),
  };

  const cleanArtifact = {
    ...artifact,
    provenance: { verificationStatus: "VERIFIED", source: "HuggingFace" },
  };
  const cleanEval = evaluateArtifactAgainstPolicy(cleanArtifact, standardPolicies[0], []);
  assert.equal(cleanEval.overallOutcome, "PASS");

  const unverifiedEval = evaluateArtifactAgainstPolicy(artifact, standardPolicies[0], []);
  assert.equal(unverifiedEval.overallOutcome, "CONDITIONAL");

  const criticalFinding = {
    id: "F1",
    title: "Arbitrary Code Execution",
    description: "Dangerous opcode",
    severity: "CRITICAL",
    scanner: "ModelAudit",
    scannerVersion: "0.2.52",
    evidenceIds: [],
    recommendation: "Remediate",
  };
  const critEval = evaluateArtifactAgainstPolicy(artifact, standardPolicies[0], [criticalFinding]);
  assert.equal(critEval.overallOutcome, "BLOCK");

  const mismatchEval = evaluateArtifactAgainstPolicy(
    artifact,
    standardPolicies[0],
    [],
    "b".repeat(64),
  );
  assert.equal(mismatchEval.overallOutcome, "BLOCK");
});
