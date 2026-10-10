import {
  ArrowRight,
  ArrowUpRight,
  Box,
  Clock3,
  FileKey2,
  Plus,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { Artifact } from "../../types/artifact";
import { artifactUrl, go } from "../../routes";
import { Heading, Rows } from "../../components/common/Registry";

export default function Dashboard({ items }: { items: Artifact[] }) {
  const awaitingReviewCount = items.filter((x) => x.reviewRequired).length;

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
      label: "Needs human review",
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
            onKeyDown={(event) => {
              if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                action();
              }
            }}
            role="link"
            tabIndex={0}
            aria-label={`${label}: ${value}. Open related records`}
            style={{ cursor: "pointer" }}
            title={`View ${label}`}
          >
            <span>{label}</span>
            <Icon />
            <b>{value}</b>
            <small>Explore records <ArrowRight size={12} /></small>
          </div>
        ))}
      </div>

      <section className="pipeline-card">
        <div className="workflow-copy">
          <span className="workflow-eyebrow">
            <i /> MODEL TRUST PIPELINE
          </span>
          <h2>From upload to trusted release</h2>
          <p>
            Every artifact moves through a clear chain of custody, security
            evidence, and policy review.
          </p>
          <div className="workflow-steps" role="list" aria-label="Model release workflow">
            {["Intake", "Scan", "Evidence", "Policy", "Review", "Decision", "Passport"].map(
              (step, index) => (
                <div className="workflow-step" role="listitem" key={step}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <b>{step}</b>
                </div>
              ),
            )}
          </div>
        </div>
        <div className="workflow-art" aria-hidden="true">
          <svg viewBox="0 0 190 170" role="presentation">
            <circle className="workflow-ring ring-outer" cx="95" cy="84" r="66" />
            <circle className="workflow-ring ring-middle" cx="95" cy="84" r="49" />
            <circle className="workflow-ring ring-inner" cx="95" cy="84" r="34" />
            <path
              className="workflow-orbit-line"
              d="M35 54 67 73m58 0 29-25M48 118l32-20m35 1 29 23"
            />
            <circle className="workflow-node node-green" cx="35" cy="54" r="5" />
            <circle className="workflow-node node-lime" cx="154" cy="48" r="4" />
            <circle className="workflow-node node-white" cx="48" cy="118" r="4" />
            <circle className="workflow-node node-lime" cx="164" cy="122" r="5" />
            <path
              className="workflow-shield"
              d="M95 57 119 66v18c0 17-10 28-24 36-14-8-24-19-24-36V66l24-9Z"
            />
            <path className="workflow-check" d="m84 83 8 8 15-17" />
          </svg>
          <span>VERIFIED FLOW</span>
        </div>
      </section>
      <div className="lower-grid governance-grid" style={{ marginBottom: 20 }}>
        <section
          className="event-card"
          onClick={() => go("/policies")}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              go("/policies");
            }
          }}
          role="link"
          tabIndex={0}
          aria-label="Open release policies"
          style={{ cursor: "pointer" }}
        >
          <div className="policy-top">
            <FileKey2 />
            <span>ACTIVE POLICIES</span>
            <ArrowUpRight className="card-corner" size={16} />
          </div>
          <h2>Release policies</h2>
          <p>Versioned rules that determine whether model artifacts can ship.</p>
          <div className="event">
            <ShieldCheck />
            <span>
              <b>Production Model Security</b>
              <small>PROD-SEC-004 · Version 2.0</small>
            </span>
            <time>Active</time>
          </div>
          <div className="rule">
            Critical finding <strong>Block release</strong>
          </div>
        </section>

        <section
          className="event-card"
          onClick={() => go("/audit-trail")}
          onKeyDown={(event) => {
            if (event.key === "Enter" || event.key === " ") {
              event.preventDefault();
              go("/audit-trail");
            }
          }}
          role="link"
          tabIndex={0}
          aria-label="Open audit trail"
          style={{ cursor: "pointer" }}
        >
          <div className="policy-top">
            <Clock3 />
            <span>AUDIT TRAIL</span>
            <ArrowUpRight className="card-corner" size={16} />
          </div>
          <h2>Governance decisions</h2>
          <p>Traceable release decisions, signed attestations, and compliance events.</p>
          <div className="event">
            <ShieldCheck />
            <span>
              <b>Review queue triage</b>
              <small>Automatic policy outcomes and traceable release events</small>
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
