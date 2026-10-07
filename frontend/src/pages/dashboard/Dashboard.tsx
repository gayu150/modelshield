import {
  ArrowRight,
  Box,
  Clock3,
  Fingerprint,
  Plus,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { Artifact } from "../../types/artifact";
import { artifactUrl, go } from "../../routes";
import { Heading, Rows } from "../../components/common/Registry";
export default function Dashboard({ items }: { items: Artifact[] }) {
  const metrics = [
    { label: "Artifacts monitored", value: items.length, Icon: Box },
    {
      label: "Approved",
      value: items.filter((x) => x.decision === "APPROVED").length,
      Icon: ShieldCheck,
    },
    {
      label: "Quarantined or conditional",
      value: items.filter((x) =>
        ["QUARANTINED", "CONDITIONAL"].includes(x.decision),
      ).length,
      Icon: Clock3,
    },
    {
      label: "Blocked",
      value: items.filter((x) => x.decision === "BLOCKED").length,
      Icon: ShieldAlert,
    },
  ];
  return (
    <>
      <Heading
        tag="SECURITY OVERVIEW"
        title="Model security overview"
        desc="Artifact inventory and recorded security decisions."
        action={
          <button className="btn primary" onClick={() => go("/artifacts/new")}>
            <Plus size={16} />
            Upload artifact
          </button>
        }
      />
      <div className="metrics">
        {metrics.map(({ label, value, Icon }) => (
          <div key={label}>
            <span>{label}</span>
            <Icon />
            <b>{value}</b>
            <small>In the current registry</small>
          </div>
        ))}
      </div>
      <section className="pipeline-card">
        <span className="pipeline-icon">
          <Fingerprint />
        </span>
        <div>
          <small>SECURITY WORKFLOW</small>
          <b>Upload → automatic quarantine → start scan → review evidence</b>
          <p>
            Upload records the file and hash. Starting a scan is a separate action;
            a completed scan does not approve the model.
          </p>
        </div>
      </section>
      <section className="content-section">
        <div className="section-head">
          <div>
            <h2>
              Recent artifacts <small>{items.length}</small>
            </h2>
            <p>Latest records returned by the registry</p>
          </div>
          <button className="link-button" onClick={() => go("/artifacts")}>
            View all
            <ArrowRight size={14} />
          </button>
        </div>
        <Rows items={items.slice(0, 5)} onOpen={(id) => go(artifactUrl(id))} />
      </section>
    </>
  );
}
