import type { Artifact } from "../types/artifact";
import type { User } from "../types/auth";
import type {
  Evidence,
  EvidenceGraph,
  Finding,
  Provenance,
  RiskSummary,
} from "../types/security";

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
  return result;
}
