export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Finding = {
  id: string;
  title: string;
  severity: Severity;
  description: string;
  scanner: string;
  scannerVersion: string;
  evidenceIds: string[];
  recommendation: string;
};
export type Evidence = {
  id: string;
  title: string;
  kind: string;
  timestamp: string;
  summary: string;
  content: string;
  scanner: string;
  artifactId?: string;
  scanId?: string;
  source?: string;
  findingType?: string;
  severity?: Severity;
  location?: string;
  verificationStatus?: "OBSERVED" | "UNVERIFIED";
};
export type EvidenceGraph = {
  nodes: { id: string; label: string; kind: string }[];
  edges: { source: string; target: string; label: string }[];
};
export type RiskSummary = {
  state: "INVESTIGATE" | "INCOMPLETE";
  reasons: string[];
  findingCounts: Record<Severity, number>;
  integrity: "MATCH" | "MISMATCH" | "UNKNOWN";
  provenance: "UNVERIFIED" | "MISSING";
  signature: "UNKNOWN";
  scanStatus: "NOT_SCANNED" | "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
};
export type Provenance = {
  source?: string;
  publisher?: string;
  repository?: string;
  revision?: string;
  origin?: string;
  verificationStatus?: "UNVERIFIED" | "MISSING" | "VERIFIED" | "CONFLICTING" | "UNKNOWN";
  signatureStatus?: "VERIFIED" | "INVALID" | "MISSING" | "UNKNOWN";
  expectedHash?: string;
  observedHash?: string;
};
