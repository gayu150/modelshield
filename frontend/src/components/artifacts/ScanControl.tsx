import { useEffect, useRef, useState } from "react";
import { DEMO_MODE } from "../../config";
import {
  getLatestArtifactScan,
  getScan,
  startArtifactScan,
} from "../../services/api/artifacts";
import { ApiError, safeMessage } from "../../services/api/client";
import type { Scan } from "../../utils/contracts";
import { ErrorState } from "../common/Feedback";
export default function ScanControl({
  artifactId,
  onCompleted,
}: {
  artifactId: string;
  onCompleted: () => void;
}) {
  const [scan, setScan] = useState<Scan>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  const lock = useRef(false);
  const completed = useRef(false);
  useEffect(() => {
    if (DEMO_MODE) return;
    const controller = new AbortController();
    let active = true;
    getLatestArtifactScan(artifactId, controller.signal)
      .then((latest) => {
        if (!active) return;
        if (!latest) {
          void start();
          return;
        }
        setScan(latest);
      })
      .catch((cause) => {
        if (active && !controller.signal.aborted) setError(safeMessage(cause));
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [artifactId]);
  useEffect(() => {
    if (!scan || !["QUEUED", "RUNNING"].includes(scan.status) || error) return;
    const controller = new AbortController();
    const timer = setTimeout(() => {
      getScan(scan.id, controller.signal)
        .then((next) => {
          if (controller.signal.aborted) return;
          setScan(next);
          if (next.status === "COMPLETED" && !completed.current) {
            completed.current = true;
            onCompleted();
          }
        })
        .catch((e) => {
          if (!controller.signal.aborted) setError(safeMessage(e));
        });
    }, 2000);
    return () => {
      controller.abort();
      clearTimeout(timer);
    };
  }, [scan, retry, error]);
  async function start() {
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setError("");
    completed.current = false;
    try {
      const result = await startArtifactScan(artifactId);
      setScan({ id: result.scan_id, status: "QUEUED" });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        try {
          const latest = await getLatestArtifactScan(artifactId);
          if (latest) setScan(latest);
          else setError(safeMessage(e));
        } catch (refreshError) {
          setError(safeMessage(refreshError));
        }
      } else {
        setError(safeMessage(e));
      }
    } finally {
      setBusy(false);
      lock.current = false;
    }
  }
  const running = !!scan && ["QUEUED", "RUNNING"].includes(scan.status);
  return (
    <section className="detail-card">
      <h2>Security scan</h2>
      <p>
        {DEMO_MODE
          ? "Demo mode uses sample data only. No model bytes are scanned."
          : "ModelShield scans artifacts automatically and applies the active policy decision when the scan finishes."}
      </p>
      {!scan && !DEMO_MODE && <p>Scan status: Preparing automatic scan...</p>}
      {scan?.status === "FAILED" && (
        <button className="btn outline" disabled={busy} onClick={start}>
          {busy ? "Starting..." : "Retry scan"}
        </button>
      )}
      {scan?.status === "COMPLETED" && !DEMO_MODE && (
        <button className="btn outline" disabled={busy} onClick={start}>
          {busy ? "Starting..." : "Run scan again"}
        </button>
      )}
      {scan && (
        <div role="status">
            <p>Scan status: {scan.status === "COMPLETED" ? scan.modelAuditStatus === "FAILED" ? "Completed with limited scanner coverage" : "Completed — review Findings and Evidence below" : scan.status === "FAILED" ? "Failed — review the error and try again" : scan.status === "RUNNING" ? "Running" : "Queued"}</p>
          {scan.progress !== undefined && (
            <>
              <progress
                max={100}
                value={scan.progress}
                aria-label="Scan progress"
              />
              <span> {scan.progress}%</span>
            </>
          )}
          {scan.status === "FAILED" && (
            <p>
              {scan.error || "The scan failed."} No safety conclusion can be made from this run.
            </p>
          )}
          {scan.status === "COMPLETED" && scan.modelAuditStatus === "FAILED" && (
            <p className="scan-warning" role="alert">
              ModelAudit could not provide a bounded report: {scan.modelAuditError || "scanner unavailable"}. Structural findings were preserved, and the policy quarantined this artifact because scanner coverage is incomplete.
            </p>
          )}
        </div>
      )}
      {error && (
        <ErrorState
          message={error}
          onRetry={() => {
            setError("");
            if (running) setRetry((x) => x + 1);
            else void start();
          }}
        />
      )}
    </section>
  );
}
