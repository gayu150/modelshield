const API_BASE = import.meta.env.VITE_API_BASE_URL ?? '/api';

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers: { ...(init?.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }), ...init?.headers },
  });
  if (!response.ok) throw new Error(`Request failed (${response.status})`);
  return response.status === 204 ? undefined as T : response.json() as Promise<T>;
}
