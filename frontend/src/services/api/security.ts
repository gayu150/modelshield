import { api } from "./client";
import {
  parseEvidence,
  parseFinding,
  parseFindings,
  parseGraph,
  parseRisk,
} from "../../utils/contracts";
const path = (id: string) => "/artifacts/" + encodeURIComponent(id);
export async function getFindings(id: string, signal?: AbortSignal) {
  return parseFindings(await api(path(id) + "/findings", { signal }));
}
export async function getFinding(id: string, signal?: AbortSignal) {
  const finding = parseFinding(
    await api("/findings/" + encodeURIComponent(id), { signal }),
  );
  if (finding.id !== id) throw new Error("Unexpected finding response.");
  return finding;
}
export async function getEvidence(id: string, signal?: AbortSignal) {
  return parseEvidence(await api(path(id) + "/evidence", { signal }));
}
export async function getGraph(id: string, signal?: AbortSignal) {
  return parseGraph(await api(path(id) + "/graph", { signal }));
}
export async function getRisk(id: string, signal?: AbortSignal) {
  return parseRisk(await api(path(id) + "/risk", { signal }));
}
