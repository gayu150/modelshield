import React from "react";
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import EvidenceGraph from "../src/components/security/EvidenceGraph";
import { Rows } from "../src/components/common/Registry";
import { Pagination } from "../src/components/common/Feedback";

test("graph labels and relationship content are escaped during rendering", () => {
  const html = renderToStaticMarkup(
    <EvidenceGraph
      graph={{
        nodes: [
          { id: "A", label: "<script>alert(1)</script>", kind: "Artifact" },
        ],
        edges: [
          { source: "A", target: "A", label: "<img src=x onerror=alert(1)>" },
        ],
      }}
    />,
  );
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("<img src=x"));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(html.includes('aria-pressed="false"'));
});
test("empty graphs and registries communicate their state", () => {
  assert.ok(
    renderToStaticMarkup(
      <EvidenceGraph graph={{ nodes: [], edges: [] }} />,
    ).includes("No evidence graph recorded"),
  );
  assert.ok(
    renderToStaticMarkup(<Rows items={[]} onOpen={() => {}} />).includes(
      "No artifacts found",
    ),
  );
});
test("pagination clamps an obsolete page and disables the next button", () => {
  const html = renderToStaticMarkup(
    <Pagination page={7} total={3} onChange={() => {}} />,
  );
  assert.ok(html.includes("Page 1 of 1"));
  assert.equal((html.match(/disabled=""/g) || []).length, 2);
});

test("passport view renders and escapes hostile model names and justification strings", async () => {
  const { default: PassportView } = await import(
    "../src/components/governance/PassportView.tsx"
  );
  const hostilePassport = {
    passportId: "PSP-TEST",
    passportNumber: "MSP-2026-999999",
    issuedAt: "2026-10-08T10:00:00Z",
    status: "VALID" as const,
    artifact: {
      id: "A1",
      name: "model.onnx",
      model: "<script>alert('xss')</script>",
      version: "1.0",
      format: "ONNX",
      sha256: "e".repeat(64),
      uploadedBy: "Tester",
      uploadedAt: "2026-10-08T10:00:00Z",
    },
    integrity: {
      hashMatches: true,
      observedHash: "e".repeat(64),
      expectedHash: "e".repeat(64),
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
      policyId: "POL-1",
      policyCode: "PROD-SEC-004",
      policyName: "Production Model Security",
      policyVersion: "2.0",
      overallOutcome: "PASS" as const,
      ruleEvaluations: [],
      evaluatedAt: "2026-10-08T10:00:00Z",
    },
    decision: {
      id: "DEC-1",
      artifactId: "A1",
      decision: "APPROVED" as const,
      rationale: "<img src=x onerror=alert(1)>",
      reviewerId: "USR-1",
      reviewerName: "Priya Sharma",
      reviewerRole: "Security Reviewer",
      createdAt: "2026-10-08T10:00:00Z",
    },
    verificationSeal: {
      algorithm: "SHA256-RSA",
      signature: "0xabcdef",
      issuer: "ModelShield Release Authority",
    },
  };

  const html = renderToStaticMarkup(<PassportView passport={hostilePassport} />);
  assert.ok(html.includes("MSP-2026-999999"));
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("<img src=x"));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(html.includes("&lt;img src=x"));
});

