import { useEffect, useState } from "react";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Layout from "./components/common/Layout";
import { Loading, ErrorState, EmptyState } from "./components/common/Feedback";
import { DEMO_MODE } from "./config";
import { example } from "./data/security";
import { sample } from "./data/artifacts";
import { evaluateArtifactAgainstPolicy, standardPolicies } from "./data/governance";
import { useResource } from "./hooks/useResource";
import { artifactUrl, go, readRoute, type Route } from "./routes";
import {
  getArtifact,
  listArtifacts,
  uploadArtifact,
  deleteArtifact,
  type ArtifactUpload,
} from "./services/api/artifacts";
import type { Artifact } from "./types/artifact";
import type { DecisionRecord } from "./types/governance";
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
  onDelete,
}: {
  route: Route;
  items: Artifact[];
  onRefresh: () => void;
  onDelete: (id: string) => Promise<void>;
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
      onDelete={() => onDelete(route.id!)}
    />
  );
}

function demoPolicyOutcomes(items: Artifact[]): Artifact[] {
  return items.map((item) => {
    const evaluation = evaluateArtifactAgainstPolicy(
      item,
      standardPolicies[0],
      example(item).findings,
      item.provenance?.observedHash,
    );
    const decision: Artifact["decision"] = ["PASS", "APPROVED"].includes(evaluation.overallOutcome)
      ? "APPROVED"
      : ["BLOCK", "BLOCKED"].includes(evaluation.overallOutcome) ? "BLOCKED"
        : evaluation.overallOutcome === "CONDITIONAL" ? "CONDITIONAL" : "QUARANTINED";
    return {
      ...item,
      decision,
      scanStatus: "COMPLETED",
      policyOutcome: evaluation.overallOutcome,
      reviewRequired: !["PASS", "APPROVED"].includes(evaluation.overallOutcome),
    };
  });
}

function Workspace() {
  const { user } = useAuth();
  const [route, setRoute] = useState<Route>(readRoute);
  const [demoItems, setDemoItems] = useState<Artifact[]>(() => demoPolicyOutcomes(sample));
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
          scanStatus: "NOT_SCANNED" as const,
          reviewRequired: false,
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
        : "Upload complete. The model is hashed and quarantined. Policy passing may auto-approve it; flagged outcomes remain quarantined for reviewer disposition.",
    );
    go(artifactUrl(item.id));
  }
  async function removeArtifact(id: string) {
    if (DEMO_MODE) setDemoItems((previous) => previous.filter((item) => item.id !== id));
    else {
      await deleteArtifact(id);
      setRevision((x) => x + 1);
    }
    setNotice("Artifact and its scan records were deleted. The audit event was retained.");
    go("/artifacts");
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
          onDelete={removeArtifact}
        />
      )}
      {route.page === "review-queue" && (
        <ReviewQueuePage
          items={DEMO_MODE ? demoItems : items}
          onOpen={(id) => go(artifactUrl(id))}
          onDecision={(id, record: DecisionRecord) => {
            if (DEMO_MODE) {
              setDemoItems((previous) => previous.map((item) => item.id === id
                ? { ...item, decision: record.decision, reviewRequired: false }
                : item));
            } else {
              setRevision((x) => x + 1);
            }
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
  if (!auth.user) return <LoginPage onLogin={auth.signIn} onSignUp={auth.signUp} />;
  return <Workspace key={auth.user.id} />;
}
export default function App() {
  return (
    <AuthProvider>
      <Session />
    </AuthProvider>
  );
}
