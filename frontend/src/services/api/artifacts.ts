import { api } from "./client";
import {
  parseArtifact,
  parseArtifacts,
  parseScan,
  record,
  identifier,
} from "../../utils/contracts";
export type ArtifactUpload = {
  file: File;
  modelName: string;
  version: string;
  source?: string;
  publisher?: string;
  repository?: string;
  revision?: string;
  origin?: string;
};
const path = (id: string) => "/artifacts/" + encodeURIComponent(id);
export async function listArtifacts(signal?: AbortSignal) {
  return parseArtifacts(await api("/artifacts", { signal }));
}
export async function getArtifact(id: string, signal?: AbortSignal) {
  const item = parseArtifact(await api(path(id), { signal }));
  if (item.id !== id) throw new Error("Unexpected artifact response.");
  return item;
}
export async function uploadArtifact(input: ArtifactUpload) {
  const body = new FormData();
  body.append("file", input.file);
  body.append("model_name", input.modelName);
  body.append("version", input.version);
  if (input.source) body.append("source", input.source);
  if (input.publisher) body.append("publisher", input.publisher);
  if (input.repository) body.append("repository", input.repository);
  if (input.revision) body.append("revision", input.revision);
  if (input.origin) body.append("origin", input.origin);
  return parseArtifact(await api("/artifacts", { method: "POST", body }));
}
export async function startArtifactScan(id: string) {
  const response = record(await api(path(id) + "/scan", { method: "POST" }));
  return { scan_id: identifier(response.scan_id) };
}
export async function getScan(id: string, signal?: AbortSignal) {
  const scan = parseScan(
    await api("/scans/" + encodeURIComponent(id), { signal }),
  );
  if (scan.id !== id) throw new Error("Unexpected scan response.");
  return scan;
}
