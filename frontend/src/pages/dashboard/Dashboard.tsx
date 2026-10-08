import {
  ArrowRight,
  Box,
  Clock3,
  FileKey2,
  Fingerprint,
  Plus,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { Artifact } from "../../types/artifact";
import { artifactUrl, go } from "../../routes";
import { Heading, Rows } from "../../components/common/Registry";

export default function Dashboard({ items }: { items: Artifact[] }) {
  const awaitingReviewCount = items.filter((x) =>
    ["QUARANTINED", "CONDITIONAL"].includes(x.decision),
  ).length;

  const metrics = [
    {
      label: "Artifacts monitored",
      value: items.length,
      Icon: Box,
      action: () => go("/artifacts"),
    },
    {
      label: "Approved",
      value: items.filter((x) => x.decision === "APPROVED").length,
      Icon: ShieldCheck,
      action: () => go("/artifacts"),
    },
    {
      label: "Quarantined or conditional",
      value: awaitingReviewCount,
      Icon: Clock3,
      action: () => go("/review-queue"),
    },
    {
      label: "Blocked",
      value: items.filter((x) => x.decision === "BLOCKED").length,
      Icon: ShieldAlert,
      action: () => go("/artifacts"),
    },
  ];

  return (
    <>
      <Heading
        tag="SECURITY & GOVERNANCE"
        title="ModelShield Dashboard"
        desc="Artifact inventory, security analysis, release policies, and governance decisions."
        action={
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn outline" onClick={() => go("/review-queue")}>
              <Clock3 size={15} />
              Review queue ({awaitingReviewCount})
            </button>
            <button className="btn primary" onClick={() => go("/artifacts/new")}>
              <Plus size={16} />
              Upload artifact
            </button>
          </div>
        }
      />

      <div className="metrics">
        {metrics.map(({ label, value, Icon, action }) => (
          <div
            key={label}
            onClick={action}
            style={{ cursor: "pointer" }}
            title={`View ${label}`}
          >
            <span>{label}</span>
            <Icon />
            <b>{value}</b>
            <small>Click to view in registry</small>
          </div>
        ))}
      </div>

      <section className="pipeline-card">
        <span className="pipeline-icon">
          <Fingerprint />
        </span>
        <div>
          <small>INTEGRATED MODELSHIELD WORKFLOW</small>
          <b>
            Upload → Automatic quarantine → Security scan → Evidence → Policy evaluation → Governance decision → Security Passport
          </b>
          <p>
            Upload records the model and hash. Scanners produce verifiable evidence. Member 3 governance evaluates release policies and certifies authorized release passports.
          </p>
        </div>
      </section>

      <div className="lower-grid governance-grid" style={{ marginBottom: 20 }}>
        <section className="event-card" onClick={() => go("/policies")} style={{ cursor: "pointer" }}>
          <div className="policy-top">
            <FileKey2 />
            <span>ACTIVE POLICIES</span>
          </div>
          <h2>Release policies</h2>
          <p>Versioned rules that determine whether model artifacts can ship.</p>
          <div className="event">
            <ShieldCheck />
            <span>
              <b>Production Model Security</b>
              <small>PROD-SEC-004 • Version 2.0</small>
            </span>
            <time>Active</time>
          </div>
          <div className="rule">
            Critical finding <strong>Block release</strong>
          </div>
        </section>

        <section className="event-card" onClick={() => go("/audit-trail")} style={{ cursor: "pointer" }}>
          <div className="policy-top">
            <Clock3 />
            <span>AUDIT TRAIL</span>
          </div>
          <h2>Governance decisions</h2>
          <p>Traceable release decisions, signed attestations, and compliance events.</p>
          <div className="event">
            <ShieldCheck />
            <span>
              <b>Review queue triage</b>
              <small>{awaitingReviewCount} models awaiting governance sign-off</small>
            </span>
            <time>Open</time>
          </div>
          <div className="rule">
            Release gate: <strong>Strict auditability</strong>
          </div>
        </section>
      </div>

      <section className="content-section">
        <div className="section-head">
          <div>
            <h2>
              Recent artifacts <small>{items.length}</small>
            </h2>
            <p>Latest models registered in this workspace</p>
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
