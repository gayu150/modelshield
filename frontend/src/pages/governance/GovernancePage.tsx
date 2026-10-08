import { useState } from "react";
import {
  Activity,
  Check,
  ChevronDown,
  ChevronUp,
  Clock,
  FileCheck,
  FileKey2,
  Filter,
  Layers,
  Shield,
  ShieldAlert,
  ShieldCheck,
  User,
} from "lucide-react";
import { DEMO_MODE } from "../../config";
import { useResource } from "../../hooks/useResource";
import { go } from "../../routes";
import { sampleAuditTrail, standardPolicies } from "../../data/governance";
import { getAuditTrail, listPolicies } from "../../services/api/governance";
import type { AuditEntry, ReleasePolicy } from "../../types/governance";
import { EmptyState, ErrorState, Loading } from "../../components/common/Feedback";
import "./governance.css";

export default function GovernancePage({
  section = "all",
}: {
  section?: "all" | "policies" | "audit";
}) {
  const [activeTab, setActiveTab] = useState<"all" | "policies" | "audit">(section);
  const [expandedPolicyId, setExpandedPolicyId] = useState<string>("POL-PROD-004");
  const [auditFilter, setAuditFilter] = useState<string>("ALL");
  const [selectedAuditItem, setSelectedAuditItem] = useState<string | null>(null);

  const policiesResource = useResource<ReleasePolicy[]>(
    (signal) =>
      DEMO_MODE ? Promise.resolve(standardPolicies) : listPolicies(signal),
    [],
  );

  const auditResource = useResource<AuditEntry[]>(
    (signal) =>
      DEMO_MODE
        ? Promise.resolve(sampleAuditTrail)
        : getAuditTrail(auditFilter !== "ALL" ? { eventType: auditFilter } : undefined, signal),
    [auditFilter],
  );

  const policies = policiesResource.data || standardPolicies;
  const auditEntries = auditResource.data || sampleAuditTrail;

  const filteredAudit = auditEntries.filter((entry) => {
    if (auditFilter === "ALL") return true;
    return entry.eventType === auditFilter;
  });

  return (
    <>
      <div className="governance-hero">
        <div>
          <div className="kicker">
            <i />
            CONTROL CENTER
          </div>
          <h1 style={{ fontSize: 24, fontWeight: 700, margin: "2px 0 6px" }}>
            {activeTab === "policies"
              ? "Release Policies"
              : activeTab === "audit"
              ? "Audit Trail"
              : "Release Governance"}
          </h1>
          <p style={{ color: "#556579", fontSize: 13, margin: 0 }}>
            {activeTab === "policies"
              ? "Configured security evaluation rules determining model promotion and release eligibility."
              : activeTab === "audit"
              ? "Cryptographically traceable timeline of all uploads, scans, evaluations, and decisions."
              : "Enterprise release policy control center, approval gatekeeping, and immutable audit logs."}
          </p>
        </div>

        <div className="governance-tabs">
          <button
            className={`gov-tab-btn ${activeTab === "all" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("all");
              go("/governance");
            }}
          >
            <Layers size={14} />
            Overview
          </button>
          <button
            className={`gov-tab-btn ${activeTab === "policies" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("policies");
              go("/policies");
            }}
          >
            <FileKey2 size={14} />
            Policies
          </button>
          <button
            className={`gov-tab-btn ${activeTab === "audit" ? "active" : ""}`}
            onClick={() => {
              setActiveTab("audit");
              go("/audit-trail");
            }}
          >
            <Activity size={14} />
            Audit Trail
          </button>
        </div>
      </div>

      {policiesResource.loading && activeTab === "policies" && (
        <Loading>Loading release policies...</Loading>
      )}
      {policiesResource.error && activeTab === "policies" && (
        <ErrorState message={policiesResource.error} onRetry={policiesResource.reload} />
      )}

      {/* SECTION: POLICIES */}
      {(activeTab === "all" || activeTab === "policies") && (
        <section className="content-section" style={{ marginBottom: 30 }}>
          <div className="section-head">
            <div>
              <h2>
                Release Policies <small>{policies.length} configured</small>
              </h2>
              <p>Active rule standards evaluated against model findings and integrity checks.</p>
            </div>
            {activeTab === "all" && (
              <button
                className="link-button"
                onClick={() => {
                  setActiveTab("policies");
                  go("/policies");
                }}
              >
                View all policies →
              </button>
            )}
          </div>

          <div className="policy-list-grid">
            {policies.map((p) => {
              const isExpanded = expandedPolicyId === p.id || activeTab === "policies";
              return (
                <div key={p.id} className="policy-card-full">
                  <div className="policy-card-header">
                    <div>
                      <span className={`policy-tag ${p.status.toLowerCase()}`}>
                        {p.status === "ACTIVE" && <ShieldCheck size={12} />}
                        {p.status}
                      </span>
                      <div className="policy-card-title">{p.name}</div>
                      <div className="policy-code-badge">
                        {p.code} • Version {p.version}
                      </div>
                    </div>
                    {activeTab !== "policies" && (
                      <button
                        className="btn outline"
                        style={{ padding: 4 }}
                        onClick={() =>
                          setExpandedPolicyId(isExpanded ? "" : p.id)
                        }
                        aria-label="Toggle rules"
                      >
                        {isExpanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    )}
                  </div>

                  <p className="policy-card-desc">{p.description}</p>

                  <div style={{ fontSize: 11, color: "#64748b" }}>
                    <b>Target formats:</b> {p.targetFormats.join(", ")}
                  </div>

                  {isExpanded && (
                    <div className="rules-container">
                      <span style={{ fontSize: 11, fontWeight: 700, color: "#475569" }}>
                        ENFORCED RULES ({p.rules.length})
                      </span>
                      {p.rules.map((rule) => (
                        <div key={rule.id} className="rule-row-item">
                          <div className="rule-left">
                            <b>
                              {rule.code}: {rule.title}
                            </b>
                            <small>{rule.description}</small>
                          </div>
                          <span className={`rule-action-badge ${rule.action.toLowerCase()}`}>
                            {rule.action}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* SECTION: AUDIT TRAIL */}
      {(activeTab === "all" || activeTab === "audit") && (
        <section className="content-section">
          <div className="section-head">
            <div>
              <h2>
                Audit Trail <small>{filteredAudit.length} events</small>
              </h2>
              <p>Tamper-evident record of all intake, evaluation, decisions, and passport generation.</p>
            </div>
            {activeTab === "all" && (
              <button
                className="link-button"
                onClick={() => {
                  setActiveTab("audit");
                  go("/audit-trail");
                }}
              >
                View full audit trail →
              </button>
            )}
          </div>

          {activeTab === "audit" && (
            <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
              <span style={{ fontSize: 12, fontWeight: 600, display: "flex", alignItems: "center", gap: 4 }}>
                <Filter size={13} /> Filter:
              </span>
              {[
                { label: "All Events", value: "ALL" },
                { label: "Decisions", value: "DECISION_RECORDED" },
                { label: "Policy Checks", value: "POLICY_EVALUATION" },
                { label: "Passports", value: "PASSPORT_GENERATED" },
                { label: "Scans", value: "SCAN_COMPLETED" },
                { label: "Uploads", value: "ARTIFACT_UPLOAD" },
              ].map((f) => (
                <button
                  key={f.value}
                  className={`btn outline ${auditFilter === f.value ? "primary" : ""}`}
                  style={{ padding: "4px 10px", fontSize: 11 }}
                  onClick={() => setAuditFilter(f.value)}
                >
                  {f.label}
                </button>
              ))}
            </div>
          )}

          <div className="audit-timeline">
            {filteredAudit.map((entry) => {
              const isSelected = selectedAuditItem === entry.id;
              const dotClass = entry.status.toLowerCase();

              return (
                <div key={entry.id} className="audit-item">
                  <div className={`audit-node-dot ${dotClass}`} />
                  <div className="audit-header">
                    <span className="audit-type-pill">{entry.eventType.replace(/_/g, " ")}</span>
                    <span className="audit-time">
                      <Clock size={11} style={{ display: "inline", verticalAlign: "middle", marginRight: 4 }} />
                      {new Date(entry.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <div className="audit-desc">{entry.description}</div>

                  <div className="audit-actor-row">
                    <User size={13} />
                    <span>
                      Actor: <b>{entry.actor.name}</b> ({entry.actor.role})
                    </span>
                    {entry.targetName && (
                      <span style={{ marginLeft: "auto" }}>
                        Target: <b>{entry.targetName}</b>
                      </span>
                    )}
                  </div>

                  {entry.details && Object.keys(entry.details).length > 0 && (
                    <div style={{ marginTop: 8 }}>
                      <button
                        className="link-button"
                        style={{ fontSize: 11 }}
                        onClick={() => setSelectedAuditItem(isSelected ? null : entry.id)}
                      >
                        {isSelected ? "Hide technical details ▲" : "Inspect event payload ▼"}
                      </button>
                      {isSelected && (
                        <div className="audit-details-box">
                          <pre style={{ margin: 0 }}>{JSON.stringify(entry.details, null, 2)}</pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}

            {!filteredAudit.length && (
              <EmptyState title="No audit events found">
                <button className="btn outline" onClick={() => setAuditFilter("ALL")}>
                  Clear filter
                </button>
              </EmptyState>
            )}
          </div>
        </section>
      )}
    </>
  );
}
