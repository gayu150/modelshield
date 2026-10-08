import { useEffect, useState } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Layout from "./components/common/Layout";
import { Loading, ErrorState, EmptyState } from "./components/common/Feedback";
import { DEMO_MODE } from "./config";
import { sample } from "./data/artifacts";
import { useResource } from "./hooks/useResource";
import { artifactUrl, go, readRoute, type Route } from "./routes";
import {
  getArtifact,
  listArtifacts,
  uploadArtifact,
  type ArtifactUpload,
} from "./services/api/artifacts";
import type { Artifact } from "./types/artifact";
import LoginPage from "./pages/auth/LoginPage";
import Dashboard from "./pages/dashboard/Dashboard";
import ArtifactPage from "./pages/artifacts/ArtifactPage";
import UploadPage from "./pages/artifacts/UploadPage";
import DetailPage from "./pages/artifacts/DetailPage";
import ReviewQueuePage from "./pages/governance/ReviewQueuePage";
import GovernancePage from "./pages/governance/GovernancePage";

function ArtifactRecord({
  route,
  items,
  onRefresh,
}: {
  route: Route;
  items: Artifact[];
  onRefresh: () => void;
}) {
  const [revision, setRevision] = useState(0);
  const resource = useResource(
    (signal) =>
      DEMO_MODE
        ? Promise.resolve(items.find((x) => x.id === route.id))
        : getArtifact(route.id!, signal),
    [route.id, revision],
  );
  if (resource.loading) return <Loading>Loading artifact...</Loading>;
  if (resource.error)
    return <ErrorState message={resource.error} onRetry={resource.reload} />;
  if (!resource.data)
    return (
      <EmptyState title="Artifact not found">
        <a href="#/artifacts">Back to artifacts</a>
      </EmptyState>
    );
  return (
    <DetailPage
      key={route.id}
      item={resource.data}
      tab={route.tab}
      revision={revision}
      onRefresh={() => {
        setRevision((x) => x + 1);
        onRefresh();
      }}
    />
  );
}
function Workspace() {
  const { user } = useAuth();
  const [route, setRoute] = useState<Route>(readRoute);
  const [demoItems, setDemoItems] = useState<Artifact[]>(sample);
  const [notice, setNotice] = useState("");
  const [revision, setRevision] = useState(0);
  const registry = useResource(
    (signal) =>
      DEMO_MODE ? Promise.resolve(demoItems) : listArtifacts(signal),
    [user?.id, revision, demoItems],
  );
  useEffect(() => {
    const change = () => {
      setRoute(readRoute());
      window.scrollTo(0, 0);
    };
    addEventListener("hashchange", change);
    return () => removeEventListener("hashchange", change);
  }, []);
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(""), 6000);
    return () => clearTimeout(timer);
  }, [notice]);
  useEffect(() => {
    if (route.page === "login") go("/dashboard");
  }, [route.page]);
  const items = registry.data || [];
  async function upload(input: ArtifactUpload) {
    const item = DEMO_MODE
      ? {
          id: "DEMO-" + crypto.randomUUID(),
          name: input.file.name,
          model: input.modelName,
          version: input.version,
          format: input.file.name.split(".").pop()!.toUpperCase(),
          uploadedBy: user!.name,
          uploadedAt: new Date().toISOString(),
          decision: "QUARANTINED" as const,
          findings: 0,
          hash: "Pending verification",
          provenance: { source: input.source },
        }
      : await uploadArtifact(input);
    if (DEMO_MODE) setDemoItems((previous) => [item, ...previous]);
    else setRevision((x) => x + 1);
    setNotice(
      DEMO_MODE
        ? "Demo quarantine record created. No model bytes were uploaded."
        : "Upload complete. The model is automatically marked QUARANTINED and hashed. Choose Start scan to generate security evidence.",
    );
    go(artifactUrl(item.id));
  }
  const registryPage = ["dashboard", "artifacts"].includes(route.page);
  return (
    <Layout route={route} count={items.length}>
      {notice && (
        <div className="feedback" role="status">
          {notice}
          <button className="link-button" onClick={() => setNotice("")}>
            Dismiss
          </button>
        </div>
      )}
      {registryPage && registry.loading ? (
        <Loading>Loading artifact registry...</Loading>
      ) : registryPage && registry.error ? (
        <ErrorState message={registry.error} onRetry={registry.reload} />
      ) : (
        <>
          {(route.page === "dashboard" || route.page === "login") && (
            <Dashboard items={items} />
          )}
          {route.page === "artifacts" && <ArtifactPage items={items} />}
        </>
      )}
      {route.page === "upload" && <UploadPage onUpload={upload} />}
      {(route.page === "detail" || route.page === "security") && (
        <ArtifactRecord
          key={route.id}
          route={route}
          items={items.length ? items : demoItems}
          onRefresh={() => setRevision((x) => x + 1)}
        />
      )}
      {route.page === "review-queue" && (
        <ReviewQueuePage
          items={items.length ? items : demoItems}
          onOpen={(id) => go(artifactUrl(id))}
          onDecisionUpdated={(rec) => {
            if (DEMO_MODE) {
              setDemoItems((prev) =>
                prev.map((it) =>
                  it.id === rec.artifactId ? { ...it, decision: rec.decision } : it,
                ),
              );
            } else {
              setRevision((x) => x + 1);
            }
            setNotice(`Decision recorded: ${rec.decision} for artifact.`);
          }}
        />
      )}
      {["governance", "policies", "audit-trail"].includes(route.page) && (
        <GovernancePage
          section={
            route.page === "policies"
              ? "policies"
              : route.page === "audit-trail"
              ? "audit"
              : "all"
          }
        />
      )}
      {route.page === "not-found" && (
        <EmptyState title="Page not found">
          <a href="#/artifacts">Back to artifacts</a>
        </EmptyState>
      )}
    </Layout>
  );
}
function Session() {
  const auth = useAuth();
  if (auth.loading) return <Loading>Checking your session...</Loading>;
  if (auth.error)
    return <ErrorState message={auth.error} onRetry={auth.retry} />;
  if (!auth.user) return <LoginPage onLogin={auth.signIn} />;
  return <Workspace key={auth.user.id} />;
}
export default function App() {
  return (
    <AuthProvider>
      <Session />
    </AuthProvider>
  );
}
