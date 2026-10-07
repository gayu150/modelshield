import type { Artifact } from "../types/artifact";
import type {
  Finding,
  Evidence,
  EvidenceGraph,
  Provenance,
} from "../types/security";
export type SecurityData = {
  findings: Finding[];
  evidence: Evidence[];
  graph: EvidenceGraph;
  provenance: Provenance;
};
// Fixtures exercise the interface only. They are not scanner results.
export function example(artifact: Artifact): SecurityData {
  const findings: Finding[] = artifact.id.startsWith("DEMO-")
    ? []
    : Array.from({ length: artifact.findings }, (_, index) => ({
        id: "DEMO-" + artifact.id + "-F" + (index + 1),
        title: [
          "Example unsafe deserialization",
          "Example incomplete provenance",
          "Example suspicious dependency",
          "Example unverified integrity",
        ][index % 4],
        severity: (["HIGH", "MEDIUM", "LOW", "CRITICAL"] as const)[index % 4],
        description:
          "Illustrative scanner finding. No model bytes were inspected.",
        scanner: "Example scanner",
        scannerVersion: "fixture-1",
        evidenceIds: ["DEMO-" + artifact.id + "-E" + (index + 1)],
        recommendation:
          "Obtain a real scanner report and review its evidence before making a release decision.",
      }));
  const evidence: Evidence[] = findings.map((f) => ({
    id: f.evidenceIds[0],
    title: "Example evidence for " + f.title,
    kind: "STATIC_ANALYSIS",
    timestamp: "2026-10-01T09:00:00Z",
    summary: "Illustrative evidence; unrelated to uploaded model bytes.",
    content: "Example report content only. This is not an executed inspection.",
    scanner: f.scanner,
  }));
  const graph: EvidenceGraph = {
    nodes: [
      { id: artifact.id, label: artifact.name, kind: "Artifact" },
      ...findings.map((f) => ({ id: f.id, label: f.title, kind: "Finding" })),
      ...evidence.map((e) => ({ id: e.id, label: e.title, kind: "Evidence" })),
    ],
    edges: findings.flatMap((f) => [
      { source: artifact.id, target: f.id, label: "example finding" },
      { source: f.id, target: f.evidenceIds[0], label: "supported by" },
    ]),
  };
  return {
    findings,
    evidence,
    graph: findings.length ? graph : { nodes: [], edges: [] },
    provenance: { ...artifact.provenance, signatureStatus: "UNKNOWN", verificationStatus: artifact.provenance?.source ? "UNVERIFIED" : "MISSING" },
  };
}
