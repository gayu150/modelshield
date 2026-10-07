import { useRef, useState, type FormEvent } from "react";
import { ChevronLeft, LockKeyhole, UploadCloud } from "lucide-react";
import { validateUpload } from "../../utils/security";
import { safeMessage } from "../../services/api/client";
import type { ArtifactUpload } from "../../services/api/artifacts";
import { DEMO_MODE } from "../../config";
import { go } from "../../routes";
import { Heading } from "../../components/common/Registry";
import "./workflow.css";
export default function UploadPage({
  onUpload,
}: {
  onUpload: (input: ArtifactUpload) => Promise<void>;
}) {
  const [file, setFile] = useState<File>();
  const [name, setName] = useState("");
  const [version, setVersion] = useState("1.0.0");
  const [source, setSource] = useState("");
  const [publisher, setPublisher] = useState("");
  const [repository, setRepository] = useState("");
  const [revision, setRevision] = useState("");
  const [origin, setOrigin] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const lock = useRef(false);
  function select(files: File[]) {
    if (files.length !== 1) {
      setError("Select exactly one model file.");
      return;
    }
    const validation = validateUpload(files[0]);
    if (validation) {
      setFile(undefined);
      setError(validation);
      return;
    }
    setError("");
    setFile(files[0]);
    if (!name)
      setName(files[0].name.replace(/\.[^.]+$/, "").replace(/[-_]/g, " "));
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (lock.current) return;
    if (!file) {
      setError("Choose a model file to continue.");
      return;
    }
    const validation = validateUpload(file);
    if (validation) {
      setError(validation);
      return;
    }
    if (!name.trim() || !version.trim()) {
      setError("Enter a model name and version.");
      return;
    }
    lock.current = true;
    setBusy(true);
    setError("");
    try {
      await onUpload({
        file,
        modelName: name.trim(),
        version: version.trim(),
        source: source.trim() || undefined,
        publisher: publisher.trim() || undefined,
        repository: repository.trim() || undefined,
        revision: revision.trim() || undefined,
        origin: origin.trim() || undefined,
      });
    } catch (error) {
      setError(safeMessage(error));
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }
  return (
    <>
      <button
        className="back-link"
        disabled={busy}
        onClick={() => go("/artifacts")}
      >
        <ChevronLeft size={15} />
        Back to artifacts
      </button>
      <Heading
        tag="ARTIFACT INTAKE"
        title="Upload a model"
        desc="Upload a model file. ModelShield automatically marks it QUARANTINED and records its SHA-256 hash. You can start a scan on the next page."
      />
      <form className="upload-grid" onSubmit={submit}>
        <section className="upload-form">
          <fieldset disabled={busy} className="plain-fieldset">
            <div className="form-title">
              <i>01</i>
              <span>
                <b>Artifact file</b>
                <small>Select the exact bytes to review.</small>
              </span>
            </div>
            <label
              className="dropzone"
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                if (!busy) select(Array.from(e.dataTransfer.files));
              }}
            >
              <input
                aria-label="Model artifact file"
                type="file"
                accept=".pkl,.pickle,.pth,.pt,.h5,.hdf5,.onnx,.safetensors,.zip,.tar,.gz"
                onChange={(e) => {
                  select(Array.from(e.target.files || []));
                  e.target.value = "";
                }}
              />
              <UploadCloud size={26} />
              <b>{file ? file.name : "Drop a model file or browse"}</b>
              <span>
                {file
                  ? (file.size / 1048576).toFixed(2) + " MB"
                  : "One model file, up to 2 GB"}
              </span>
              <small>
                PKL, PICKLE, PT, PTH, H5, HDF5, ONNX, SAFETENSORS, ZIP, TAR, GZ
              </small>
            </label>
            <div className="form-title">
              <i>02</i>
              <span>
                <b>Model information</b>
                <small>Identify the artifact version and source.</small>
              </span>
            </div>
            <div className="fields">
              <label>
                Model name
                <input
                  required
                  maxLength={200}
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
              <label>
                Version
                <input
                  required
                  maxLength={100}
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                />
              </label>
              <label className="wide">
                Source or registry (optional)
                <input
                  maxLength={1000}
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="Publisher or registry reference"
                />
              </label>
              <label>Publisher (optional)<input maxLength={1000} value={publisher} onChange={(e) => setPublisher(e.target.value)} /></label>
              <label>Repository (optional)<input maxLength={1000} value={repository} onChange={(e) => setRepository(e.target.value)} /></label>
              <label>Revision or commit (optional)<input maxLength={1000} value={revision} onChange={(e) => setRevision(e.target.value)} /></label>
              <label>Origin (optional)<input maxLength={1000} value={origin} onChange={(e) => setOrigin(e.target.value)} /></label>
              <p className="wide">These fields are supplied by the uploader and have not been independently verified.</p>
            </div>
          </fieldset>
          {error && (
            <div className="form-error" role="alert">
              {error}
            </div>
          )}
          {busy && (
            <p role="status">
              Uploading... Keep this page open until the server confirms intake.
            </p>
          )}
          <div className="form-actions">
            <button
              className="btn outline"
              type="button"
              disabled={busy}
              onClick={() => go("/artifacts")}
            >
              Cancel
            </button>
            <button className="btn primary" disabled={busy}>
              {busy
                ? "Uploading..."
                : DEMO_MODE
                  ? "Create demo record"
                  : "Upload model"}
            </button>
          </div>
        </section>
        <aside className="quarantine-info">
          <LockKeyhole size={22} />
          <small>WHAT HAPPENS NEXT</small>
          <h2>Quarantine is automatic.</h2>
          <p>
            {DEMO_MODE
              ? "A temporary demo record is created. No file bytes leave your computer and no scan runs."
              : "After upload, the file is saved with QUARANTINED status and its SHA-256 hash is recorded. There is no separate quarantine step."}
          </p>
          <ol className="intake-steps">
            <li>Upload the model file.</li>
            <li>Check its quarantined status and hash.</li>
            <li>Choose Start scan to generate findings and evidence.</li>
          </ol>
        </aside>
      </form>
    </>
  );
}
