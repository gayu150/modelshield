import { api } from "./client";
import { parseUser } from "../../utils/contracts";
export async function currentUser(signal?: AbortSignal) {
  const response = await api<Record<string, unknown>>("/auth/me", { signal });
  if (typeof response.csrfToken !== "string" || !response.csrfToken) {
    throw new Error("Missing CSRF token in session response.");
  }
  let meta = document.querySelector<HTMLMetaElement>('meta[name="csrf-token"]');
  if (!meta) {
    meta = document.createElement("meta");
    meta.name = "csrf-token";
    document.head.append(meta);
  }
  meta.content = response.csrfToken;
  return parseUser(response);
}
export async function login(email: string, password: string) {
  await api("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  return currentUser();
}
export async function logout() {
  await api("/auth/logout", { method: "POST" });
  document.querySelector('meta[name="csrf-token"]')?.remove();
}
