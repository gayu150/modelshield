import { request, ApiError } from "../../utils/request";
export { ApiError };
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";
export function safeMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof DOMException && error.name === "TimeoutError")
    return "The request timed out. Check the registry before retrying an upload.";
  return "The request could not be completed. Check the API connection and response contract.";
}
export function api<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  return request<T>(API_BASE, path, init, {
    csrfToken: document.querySelector<HTMLMetaElement>(
      'meta[name="csrf-token"]',
    )?.content,
    onUnauthorized: () => window.dispatchEvent(new Event("session-expired")),
  });
}
