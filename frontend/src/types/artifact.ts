export type Decision = "APPROVED" | "CONDITIONAL" | "QUARANTINED" | "BLOCKED";
export type Artifact = {
  id: string;
  name: string;
  model: string;
  version: string;
  format: string;
  uploadedBy: string;
  uploadedAt: string;
  decision: Decision;
  findings: number;
  hash: string;
  scanStatus?: "NOT_SCANNED" | "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED";
  policyOutcome?: "APPROVED" | "CONDITIONAL" | "QUARANTINED" | "BLOCKED" | "PASS" | "BLOCK";
  reviewRequired?: boolean;
  provenance?: import("./security").Provenance;
};
