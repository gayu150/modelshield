import { useMemo, useState } from "react";
import { Plus, Search } from "lucide-react";
import type { Artifact } from "../../types/artifact";
import { artifactUrl, go } from "../../routes";
import { Heading, Rows } from "../../components/common/Registry";
import { Pagination } from "../../components/common/Feedback";
export default function ArtifactPage({ items }: { items: Artifact[] }) {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("ALL");
  const found = useMemo(
    () =>
      items.filter(
        (a) =>
          (filter === "ALL" || a.decision === filter) &&
          (a.name + " " + a.model + " " + a.id + " " + a.uploadedBy)
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [items, search, filter],
  );
  const current = Math.min(page, Math.max(1, Math.ceil(found.length / 10)));
  return (
    <>
      <Heading
        tag="MODEL REGISTRY"
        title="Artifacts"
        desc="Search uploaded model files and inspect their quarantine status, scans, and evidence."
        action={
          <button className="btn primary" onClick={() => go("/artifacts/new")}>
            <Plus size={16} />
            Upload artifact
          </button>
        }
      />
      <section className="list-card">
        <div className="toolbar">
          <label>
            <Search size={16} />
            <input
              aria-label="Search artifacts"
              placeholder="Search name, ID, model or owner"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(1);
              }}
            />
          </label>
          <select
            aria-label="Filter by status"
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
              setPage(1);
            }}
          >
            <option value="ALL">All statuses</option>
            {["APPROVED", "CONDITIONAL", "QUARANTINED", "BLOCKED"].map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
          <button
            className="btn outline"
            onClick={() => {
              setSearch("");
              setFilter("ALL");
              setPage(1);
            }}
          >
            Reset
          </button>
        </div>
        <Rows
          items={found.slice((current - 1) * 10, current * 10)}
          onOpen={(id) => go(artifactUrl(id))}
        />
        <Pagination page={current} total={found.length} onChange={setPage} />
      </section>
    </>
  );
}
