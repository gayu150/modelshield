import { api } from "./client";
import type { Decision } from "../../types/artifact";
import type {
  AuditEntry,
  DecisionRecord,
  PolicyEvaluation,
  ReleasePolicy,
  SecurityPassport,
} from "../../types/governance";
import {
  parseAuditTrail,
  parseDecisionRecord,
  parseDecisionRecords,
  parsePolicies,
  parsePolicy,
  parsePolicyEvaluation,
  parseSecurityPassport,
} from "../../utils/contracts";

const artifactPath = (id: string) => "/artifacts/" + encodeURIComponent(id);

export async function listPolicies(signal?: AbortSignal): Promise<ReleasePolicy[]> {
  return parsePolicies(await api("/policies", { signal }));
}

export async function getPolicy(id: string, signal?: AbortSignal): Promise<ReleasePolicy> {
  return parsePolicy(await api("/policies/" + encodeURIComponent(id), { signal }));
}

export async function evaluateArtifactPolicy(
  artifactId: string,
  policyId?: string,
  signal?: AbortSignal,
): Promise<PolicyEvaluation> {
  const query = policyId ? `?policy_id=${encodeURIComponent(policyId)}` : "";
  return parsePolicyEvaluation(
    await api(artifactPath(artifactId) + "/evaluate" + query, {
      method: "POST",
      signal,
    }),
  );
}

export async function replayArtifactDecision(artifactId: string): Promise<{
  replayId: string;
  originalDecision: Decision;
  originalDecisionAt?: string;
  evaluation: PolicyEvaluation;
}> {
  const value = await api<Record<string, unknown>>(artifactPath(artifactId) + "/replay", { method: "POST" });
  const originalDecision = value.originalDecision;
  if (!["APPROVED", "CONDITIONAL", "QUARANTINED", "BLOCKED"].includes(String(originalDecision)))
    throw new Error("Invalid replay decision response.");
  return {
    replayId: String(value.replayId),
    originalDecision: originalDecision as Decision,
    ...(typeof value.originalDecisionAt === "string" ? { originalDecisionAt: value.originalDecisionAt } : {}),
    evaluation: parsePolicyEvaluation(value.evaluation),
  };
}

export async function submitDecision(
  artifactId: string,
  decision: Decision,
  rationale: string,
  conditions?: string[],
): Promise<DecisionRecord> {
  return parseDecisionRecord(
    await api(artifactPath(artifactId) + "/decision", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        decision,
        rationale,
        conditions: conditions || [],
      }),
    }),
  );
}

export async function getArtifactDecisions(
  artifactId: string,
  signal?: AbortSignal,
): Promise<DecisionRecord[]> {
  return parseDecisionRecords(
    await api(artifactPath(artifactId) + "/decisions", { signal }),
  );
}

export async function getSecurityPassport(
  artifactId: string,
  signal?: AbortSignal,
): Promise<SecurityPassport> {
  return parseSecurityPassport(
    await api(artifactPath(artifactId) + "/passport", { signal }),
  );
}

export async function getAuditTrail(
  filter?: { eventType?: string; targetId?: string },
  signal?: AbortSignal,
): Promise<AuditEntry[]> {
  const params = new URLSearchParams();
  if (filter?.eventType) params.set("event_type", filter.eventType);
  if (filter?.targetId) params.set("target_id", filter.targetId);
  const query = params.toString() ? `?${params.toString()}` : "";
  return parseAuditTrail(await api("/audit" + query, { signal }));
}
