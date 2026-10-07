import { useEffect, useRef, useState } from "react";
import { DEMO_MODE } from "../../config";
import { getScan, startArtifactScan } from "../../services/api/artifacts";
import { safeMessage } from "../../services/api/client";
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
      setError(safeMessage(e));
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
          ? "No scan runs in demo mode."
          : "The file is already quarantined. Start a scan to generate findings and evidence; its quarantine status stays the same."}
      </p>
      {!scan && !DEMO_MODE && <p>Scan status: Not started</p>}
      <button
        className="btn outline"
        disabled={DEMO_MODE || busy || running}
        onClick={start}
      >
        {busy
          ? "Starting..."
          : scan?.status === "FAILED"
            ? "Start another scan"
            : "Start scan"}
      </button>
      {scan && (
        <div role="status">
          <p>Scan status: {scan.status === "COMPLETED" ? "Completed — review Findings and Evidence below" : scan.status === "FAILED" ? "Failed — review the error and try again" : scan.status === "RUNNING" ? "Running" : "Queued"}</p>
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
