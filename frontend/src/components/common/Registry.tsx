import type { ReactNode } from "react";
import {
  Check,
  Clock3,
  FileCode2,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import type { Artifact, Decision } from "../../types/artifact";
export function Status({ value }: { value: Decision }) {
  const I =
    value === "APPROVED"
      ? ShieldCheck
      : value === "BLOCKED"
        ? ShieldAlert
        : Clock3;
  return (
    <span className={"status " + value.toLowerCase()}>
      <I size={13} />
      {value[0] + value.slice(1).toLowerCase()}
    </span>
  );
}
export function Heading({
  tag,
  title,
  desc,
  action,
}: {
  tag: string;
  title: string;
  desc: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-head">
      <div>
        <div className="kicker">
          <i />
          {tag}
        </div>
        <h1>{title}</h1>
        <p>{desc}</p>
      </div>
      {action}
    </div>
  );
}
export function Rows({
  items,
  onOpen,
}: {
  items: Artifact[];
  onOpen: (id: string) => void;
}) {
  return (
    <div className="table-scroll">
      <table className="artifact-table">
        <thead>
          <tr>
            <th scope="col">ARTIFACT</th>
            <th scope="col">STATUS</th>
            <th scope="col">FINDINGS</th>
            <th scope="col">OWNER</th>
            <th scope="col">UPDATED</th>
            <th aria-label="Actions" />
          </tr>
        </thead>
        <tbody>
          {items.map((x) => (
            <tr
              key={x.id}
              onClick={() => onOpen(x.id)}
              onKeyDown={(event) => {
                if (event.target !== event.currentTarget) return;
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onOpen(x.id);
                }
              }}
              tabIndex={0}
              role="link"
              aria-label={`Open artifact ${x.name}`}
            >
              <td>
                <div className="artifact-cell">
                  <span className={"file-tile " + x.format.toLowerCase()}>
                    <FileCode2 size={17} />
                  </span>
                  <span>
                    <button
                      className="link-button"
                      onClick={(e) => {
                        e.stopPropagation();
                        onOpen(x.id);
                      }}
                    >
                      {x.name}
                    </button>
                    <small>
                      {x.id} <i /> {x.format}
                    </small>
                  </span>
                </div>
              </td>
              <td>
                <Status value={x.decision} />
              </td>
              <td>
                {x.findings ? (
                  <span className="has-findings">
                    <ShieldAlert size={13} />
                    {x.findings} findings
                  </span>
                ) : (
                  <span className="no-findings">
                    <Check size={13} />
                    No recorded findings
                  </span>
                )}
              </td>
              <td>{x.uploadedBy}</td>
              <td className="muted">{x.uploadedAt}</td>
              <td>
                <span aria-hidden="true">&rarr;</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!items.length && (
        <div className="empty">
          <Search size={20} />
          <b>No artifacts found</b>
          <span>Try another search or status.</span>
        </div>
      )}
    </div>
  );
}
