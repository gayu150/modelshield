export type SecurityTab = "findings" | "evidence" | "graph" | "provenance";
export type Route = {
  page:
    | "dashboard"
    | "artifacts"
    | "upload"
    | "detail"
    | "security"
    | "login"
    | "review-queue"
    | "governance"
    | "policies"
    | "audit-trail"
    | "not-found";
  id?: string;
  tab?: SecurityTab;
};
export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (!parts.length) return { page: "dashboard" };
  const [page, encodedId, tab] = parts;
  if (page === "artifacts") {
    if (parts.length === 1) return { page: "artifacts" };
    if (encodedId === "new" && parts.length === 2) return { page: "upload" };
    let id: string;
    try {
      id = decodeURIComponent(encodedId);
    } catch {
      return { page: "not-found" };
    }
    if (!id) return { page: "not-found" };
    if (parts.length === 2) return { page: "detail", id };
    if (
      parts.length === 3 &&
      ["findings", "evidence", "graph", "provenance"].includes(tab)
    )
      return { page: "security", id, tab: tab as SecurityTab };
    return { page: "not-found" };
  }
  if (
    parts.length === 1 &&
    [
      "dashboard",
      "login",
      "review-queue",
      "governance",
      "policies",
      "audit-trail",
    ].includes(page)
  )
    return { page: page as Route["page"] };
  return { page: "not-found" };
}
export const readRoute = () => parseRoute(location.hash);
export const go = (path: string) => {
  location.hash = path;
};
export const artifactUrl = (id: string, tab?: SecurityTab) =>
  "/artifacts/" +
  (id === "new" ? "%6Eew" : encodeURIComponent(id)) +
  (tab ? "/" + tab : "");
