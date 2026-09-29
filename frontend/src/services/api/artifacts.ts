import { api } from './client';
import type { Artifact } from '../../types/artifact';

export type ArtifactUpload = {
  file: File;
  modelName?: string;
  version?: string;
  source?: string;
};

export function listArtifacts(): Promise<Artifact[]> {
  return api<Artifact[]>('/artifacts');
}

export function getArtifact(id: string): Promise<Artifact> {
  return api<Artifact>(`/artifacts/${encodeURIComponent(id)}`);
}

export function uploadArtifact(input: ArtifactUpload): Promise<Artifact> {
  const body = new FormData();
  body.append('file', input.file);
  if (input.modelName) body.append('model_name', input.modelName);
  if (input.version) body.append('version', input.version);
  if (input.source) body.append('source', input.source);
  return api<Artifact>('/artifacts', { method: 'POST', body });
}

export function startArtifactScan(id: string): Promise<{ scan_id: string }> {
  return api<{ scan_id: string }>(`/artifacts/${encodeURIComponent(id)}/scan`, { method: 'POST' });
}
