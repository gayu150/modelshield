const { test } = require("node:test");
const assert = require("node:assert/strict");
const {
  parseArtifacts,
  parseFinding,
  parseFindings,
  parseEvidence,
  parseGraph,
  parseProvenance,
  parseScan,
} = require("../src/utils/contracts.ts");
const { parseRoute, artifactUrl } = require("../src/routes/index.ts");
const { example } = require("../src/data/security.ts");
const { sample } = require("../src/data/artifacts.ts");
const artifact = {
  id: "A1",
  name: "model.onnx",
  model: "Model",
  version: "1",
  format: "ONNX",
  uploadedBy: "Tester",
  uploadedAt: "2026-10-01T10:00:00Z",
  decision: "QUARANTINED",
  findings: 0,
  hash: "a".repeat(64),
};
const finding = {
  id: "F1",
  title: "Test",
  description: "<script>alert(1)</script>",
  severity: "HIGH",
  scanner: "Scanner",
  scannerVersion: "1",
  evidenceIds: ["E1"],
  recommendation: "Inspect",
};
test("artifact contracts reject invalid status, negative counts and duplicate identities", () => {
  assert.equal(parseArtifacts([artifact])[0].id, "A1");
  for (const payload of [
    [{ ...artifact, decision: "SAFE" }],
    [{ ...artifact, findings: -1 }],
    [artifact, artifact],
    {},
  ])
    assert.throws(() => parseArtifacts(payload));
});
test("finding contracts reject unknown severity and malformed evidence references", () => {
  assert.equal(parseFinding(finding).description, finding.description);
  assert.throws(() => parseFinding({ ...finding, severity: "SAFE" }));
  assert.throws(() => parseFinding({ ...finding, evidenceIds: "E1" }));
  assert.throws(() => parseFindings([finding, finding]));
});
test("evidence contracts validate timestamps without interpreting content", () => {
  const evidence = {
    id: "E1",
    title: "Evidence",
    kind: "STATIC",
    timestamp: "2026-10-01T10:00:00Z",
    summary: "Report",
    content: "<img src=x onerror=alert(1)>",
    scanner: "Scanner",
  };
  assert.equal(parseEvidence([evidence])[0].content, evidence.content);
  assert.throws(() => parseEvidence([{ ...evidence, timestamp: "yesterday" }]));
});
test("graph contracts reject dangling edges and duplicate nodes", () => {
  const node = { id: "A", label: "Artifact", kind: "Artifact" };
  assert.equal(parseGraph({ nodes: [node], edges: [] }).nodes.length, 1);
  assert.throws(() => parseGraph({ nodes: [node, node], edges: [] }));
  assert.throws(() =>
    parseGraph({
      nodes: [node],
      edges: [{ source: "A", target: "missing", label: "contains" }],
    }),
  );
});
test("missing provenance stays unknown and invalid signatures are rejected", () => {
  assert.deepEqual(parseProvenance(undefined), {});
  assert.equal(
    parseProvenance({ signatureStatus: "UNKNOWN" }).signatureStatus,
    "UNKNOWN",
  );
  assert.throws(() => parseProvenance({ signatureStatus: "SAFE" }));
});
test("scan contracts reject unsupported states and invalid progress", () => {
  assert.equal(
    parseScan({ id: "S1", status: "COMPLETED", progress: 100 }).status,
    "COMPLETED",
  );
  for (const value of [-1, 101, NaN, "50"])
    assert.throws(() =>
      parseScan({ id: "S1", status: "RUNNING", progress: value }),
    );
  assert.throws(() => parseScan({ id: "S1", status: "SAFE" }));
});
test("routes preserve encoded artifact identifiers and direct security sections", () => {
  for (const id of ["A/B", "hello world", "模型", "A?B", "new"]) {
    for (const tab of ["findings", "evidence", "graph", "provenance"])
      assert.deepEqual(parseRoute("#" + artifactUrl(id, tab)), {
        page: "security",
        id,
        tab,
      });
  }
  assert.deepEqual(parseRoute("#/artifacts/new"), { page: "upload" });
  assert.equal(parseRoute("#/artifacts/%broken").page, "not-found");
  assert.equal(parseRoute("#/artifacts/A/unsupported").page, "not-found");
  assert.equal(parseRoute("#/missing").page, "not-found");
});
test("demo fixtures are internally consistent and uploads never invent evidence", () => {
  for (const artifact of sample) {
    const data = example(artifact);
    assert.equal(data.findings.length, artifact.findings);
    assert.doesNotThrow(() => parseFindings(data.findings));
    assert.doesNotThrow(() => parseEvidence(data.evidence));
    assert.doesNotThrow(() => parseGraph(data.graph));
    assert.equal(data.provenance.signatureStatus, "UNKNOWN");
  }
  const data = example({
    ...artifact,
    id: "DEMO-upload",
    provenance: { source: "Test registry" },
  });
  assert.deepEqual(data.findings, []);
  assert.deepEqual(data.evidence, []);
  assert.deepEqual(data.graph, { nodes: [], edges: [] });
  assert.equal(data.provenance.source, "Test registry");
});
