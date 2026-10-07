export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}
export async function request<T = unknown>(
  base: string,
  path: string,
  init: RequestInit = {},
  options: { csrfToken?: string; onUnauthorized?: () => void } = {},
): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !(init.body instanceof FormData))
    headers.set("Content-Type", "application/json");
  if (options.csrfToken && init.method && init.method !== "GET")
    headers.set("X-CSRF-Token", options.csrfToken);
  const timeout = AbortSignal.timeout(
    init.body instanceof FormData ? 300_000 : 30_000,
  );
  const signal = init.signal
    ? AbortSignal.any([init.signal, timeout])
    : timeout;
  const response = await fetch(base.replace(/\/$/, "") + path, {
    ...init,
    credentials: "include",
    headers,
    signal,
  });
  if (!response.ok) {
    if (response.status === 401 && path !== '/auth/login') options.onUnauthorized?.();
    const messages: Record<number, string> = {
      401: "Your session has expired. Sign in again.",
      403: "You do not have permission to access this resource.",
      404: "The requested resource was not found.",
      409: "The request conflicts with an existing operation. Refresh and try again.",
      413: "The file exceeds the server upload limit.",
      422: "The server rejected the submitted data.",
      429: "Too many requests. Wait before trying again.",
    };
    throw new ApiError(
      response.status,
      messages[response.status] ||
        "The server could not complete the request. Try again.",
    );
  }
  if (response.status === 204) return undefined as T;
  const body = await response.text();
  if (!body) return undefined as T;
  try {
    return JSON.parse(body) as T;
  } catch {
    throw new ApiError(502, "The server returned an invalid response.");
  }
}
