import { useState } from "react";
import { ChevronLeft, FileCode2, FileText, Fingerprint } from "lucide-react";
import type { Artifact } from "../../types/artifact";
import { artifactUrl, go, type SecurityTab } from "../../routes";
import { Heading, Status } from "../../components/common/Registry";
import SecurityAnalysis from "../security/SecurityAnalysis";
import ScanControl from "../../components/artifacts/ScanControl";
import "./workflow.css";
export default function DetailPage({
  item,
  tab,
  revision,
  onRefresh,
}: {
  item: Artifact;
  tab?: SecurityTab;
  revision: number;
  onRefresh: () => void;
}) {
  const [copied, setCopied] = useState("");
  async function copy() {
    try {
      await navigator.clipboard.writeText(item.hash);
      setCopied("Hash copied.");
    } catch {
      setCopied("Clipboard unavailable. Select and copy the hash below.");
    }
  }
  return (
    <>
      <button className="back-link" onClick={() => go("/artifacts")}>
        <ChevronLeft size={15} />
        Back to artifacts
      </button>
      <Heading
        tag="ARTIFACT OVERVIEW"
        title={item.model}
        desc={"Version " + item.version + " - Added " + item.uploadedAt}
        action={
          <button className="btn outline" onClick={() => window.print()}>
            <FileText size={14} />
            Print record
          </button>
        }
      />
      <section className="detail-banner">
        <div className="artifact-cell">
          <span className={"file-tile " + item.format.toLowerCase()}>
            <FileCode2 size={18} />
          </span>
          <span>
            <b>{item.name}</b>
            <small>
              {item.id} | {item.format}
            </small>
          </span>
        </div>
        <Status value={item.decision} />
        <span className="hash">
          <Fingerprint size={16} />
          <small>
            SHA-256 <b>{item.hash}</b>
          </small>
        </span>
        <button
          className="btn outline"
          disabled={!/^[a-f0-9]{64}$/i.test(item.hash)}
          onClick={copy}
        >
          Copy hash
        </button>
        {copied && <span role="status">{copied}</span>}
      </section>
      {item.decision === "QUARANTINED" && (
        <p className="quarantine-explanation" role="status">
          Automatically marked QUARANTINED on upload. No separate quarantine action is needed.
          Scanning adds evidence; it does not approve or release this file.
        </p>
      )}
      <section className="detail-card">
        <h2>Artifact information</h2>
        <div className="overview">
          <span>
            MODEL VERSION<b>{item.version}</b>
          </span>
          <span>
            OWNER<b>{item.uploadedBy}</b>
          </span>
          <span>
            FILE FORMAT<b>{item.format}</b>
          </span>
          <span>
            RECORDED FINDINGS<b>{item.findings}</b>
          </span>
        </div>
        <p>Review the hash and scan evidence below. Release decisions are outside this module.</p>
        <div className="security-links">
          {(["findings", "evidence", "graph", "provenance"] as const).map(
            (t) => (
              <a
                key={t}
                className="btn outline"
                href={"#" + artifactUrl(item.id, t)}
              >
                {t === "graph"
                  ? "Evidence graph"
                  : t[0].toUpperCase() + t.slice(1)}
              </a>
            ),
          )}
        </div>
      </section>
      <ScanControl key={item.id} artifactId={item.id} onCompleted={onRefresh} />
      <SecurityAnalysis
        key={item.id + ":" + revision}
        artifact={item}
        tab={tab || "findings"}
      />
    </>
  );
}
