import { useEffect, useRef } from "react";
import type { Finding } from "../../types/security";
import { DEMO_MODE } from "../../config";
import { getFinding } from "../../services/api/security";
import { useResource } from "../../hooks/useResource";
import { ErrorState, Loading } from "../common/Feedback";
export default function FindingDetails({
  finding,
  onClose,
  onEvidence,
}: {
  finding: Finding;
  onClose: () => void;
  onEvidence: (id: string) => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const resource = useResource(
    (signal) =>
      DEMO_MODE ? Promise.resolve(finding) : getFinding(finding.id, signal),
    [finding.id],
  );
  useEffect(() => {
    const element = dialog.current;
    if (element && !element.open) element.showModal();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="finding-dialog"
      aria-labelledby="finding-title"
      onCancel={onClose}
    >
      <div className="section-head">
        <h2 id="finding-title">{finding.title}</h2>
        <button className="btn outline" autoFocus onClick={onClose}>
          Close
        </button>
      </div>
      {resource.loading ? (
        <Loading>Loading finding details...</Loading>
      ) : resource.error ? (
        <ErrorState message={resource.error} onRetry={resource.reload} />
      ) : (
        resource.data && (
          <>
            <p>
              <span
                className={
                  "severity severity-" + resource.data.severity.toLowerCase()
                }
              >
                {resource.data.severity}
              </span>{" "}
              | {resource.data.id}
            </p>
            <h3>Scanner</h3>
            <p>
              {resource.data.scanner} - version {resource.data.scannerVersion}
            </p>
            <h3>Description</h3>
            <p>{resource.data.description}</p>
            <h3>Recommendation</h3>
            <p>{resource.data.recommendation}</p>
            <h3>Supporting evidence</h3>
            {resource.data.evidenceIds.length ? (
              <ul>
                {resource.data.evidenceIds.map((id) => (
                  <li key={id}>
                    <button
                      className="link-button"
                      onClick={() => onEvidence(id)}
                    >
                      {id}
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p>No evidence references recorded.</p>
            )}
          </>
        )
      )}
    </dialog>
  );
}
