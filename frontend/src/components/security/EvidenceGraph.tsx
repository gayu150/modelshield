import { useId, useMemo, useState } from "react";
import type { EvidenceGraph as Graph } from "../../types/security";
import { EmptyState } from "../common/Feedback";
export default function EvidenceGraph({
  graph,
  onInspect,
}: {
  graph: Graph;
  onInspect?: (id: string, kind: string) => void;
}) {
  const [selected, setSelected] = useState("");
  const [search, setSearch] = useState("");
  const [zoom, setZoom] = useState(1);
  const marker = useId().replace(/:/g, "");
  const positions = useMemo(
    () =>
      new Map(
        graph.nodes.map((n, i) => [
          n.id,
          { x: 140 + (i % 3) * 270, y: 75 + Math.floor(i / 3) * 115 },
        ]),
      ),
    [graph],
  );
  if (!graph.nodes.length)
    return <EmptyState title="No evidence graph recorded" />;
  const map = new Map(graph.nodes.map((x) => [x.id, x]));
  const height = Math.max(170, Math.ceil(graph.nodes.length / 3) * 115 + 40);
  const connections = graph.edges.filter(
    (e) => !selected || e.source === selected || e.target === selected,
  );
  return (
    <section className="evidence-graph">
      <p>
        Arrows show recorded relationships. Select a node to inspect its
        connections.
      </p>
      <div className="toolbar">
        <input
          aria-label="Find graph node"
          placeholder="Find a node"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <button
          className="btn outline"
          disabled={zoom <= 0.5}
          onClick={() => setZoom((x) => x - 0.25)}
        >
          Zoom out
        </button>
        <button
          className="btn outline"
          disabled={zoom >= 2}
          onClick={() => setZoom((x) => x + 0.25)}
        >
          Zoom in
        </button>
        <button
          className="btn outline"
          onClick={() => {
            setSelected("");
            setSearch("");
            setZoom(1);
          }}
        >
          Reset
        </button>
      </div>
      {graph.nodes.length <= 150 ? (
        <div className="graph-canvas">
          <svg
            role="img"
            aria-label="Recorded evidence relationship graph; accessible node controls and connections follow"
            viewBox={"0 0 820 " + height}
            style={{ width: 820 * zoom, height: height * zoom }}
          >
            <defs>
              <marker
                id={marker}
                markerWidth="10"
                markerHeight="10"
                refX="9"
                refY="3"
                orient="auto"
              >
                <path d="M0,0 L0,6 L9,3 z" fill="#648674" />
              </marker>
            </defs>
            {graph.edges.map((edge, i) => {
              const a = positions.get(edge.source)!,
                b = positions.get(edge.target)!;
              const enabled =
                !selected ||
                edge.source === selected ||
                edge.target === selected;
              return (
                <g key={i} opacity={enabled ? 1 : 0.15}>
                  <path
                    d={
                      "M" +
                      a.x +
                      " " +
                      (a.y + 27) +
                      " Q" +
                      ((a.x + b.x) / 2 + 30) +
                      " " +
                      ((a.y + b.y) / 2 - 35) +
                      " " +
                      b.x +
                      " " +
                      (b.y - 29)
                    }
                    fill="none"
                    stroke="#648674"
                    strokeWidth="2"
                    markerEnd={"url(#" + marker + ")"}
                  />
                </g>
              );
            })}
            {graph.nodes.map((node) => {
              const pos = positions.get(node.id)!;
              return (
                <g
                  key={node.id}
                  onClick={() =>
                    setSelected(selected === node.id ? "" : node.id)
                  }
                  style={{ cursor: "pointer" }}
                  transform={
                    "translate(" + (pos.x - 115) + " " + (pos.y - 30) + ")"
                  }
                >
                  <rect
                    width="230"
                    height="60"
                    rx="10"
                    fill={selected === node.id ? "#ddf0df" : "#f8fbf7"}
                    stroke={selected === node.id ? "#21652a" : "#a5b9aa"}
                    strokeWidth="2"
                  />
                  <text
                    x="115"
                    y="20"
                    textAnchor="middle"
                    fontSize="11"
                    fill="#5c7062"
                  >
                    {node.kind}
                  </text>
                  <text
                    x="115"
                    y="41"
                    textAnchor="middle"
                    fontSize="12"
                    fill="#1c3725"
                  >
                    {node.label.length > 28
                      ? node.label.slice(0, 27) + "..."
                      : node.label}
                  </text>
                  <title>{node.label + " (" + node.id + ")"}</title>
                </g>
              );
            })}
          </svg>
        </div>
      ) : (
        <p>
          Large graph: use the searchable node controls and relationship list
          below.
        </p>
      )}
      <div className="graph-nodes">
        {graph.nodes
          .filter((n) =>
            (n.label + " " + n.id + " " + n.kind)
              .toLowerCase()
              .includes(search.toLowerCase()),
          )
          .map((n) => (
            <button
              key={n.id}
              className="btn outline"
              aria-pressed={selected === n.id}
              onClick={() => setSelected(selected === n.id ? "" : n.id)}
            >
              {n.kind}: {n.label}
            </button>
          ))}
      </div>
      {selected && (
        <div className="evidence-card">
          <h3>{map.get(selected)?.label}</h3>
          <p>{selected}</p>
          {onInspect && (
            <button
              className="btn outline"
              onClick={() => onInspect(selected, map.get(selected)!.kind)}
            >
              Inspect related record
            </button>
          )}
        </div>
      )}
      <h3>Relationships {selected ? "for selected node" : ""}</h3>
      {!connections.length ? (
        <p>No recorded connections.</p>
      ) : (
        <ul>
          {connections.map((edge, i) => (
            <li key={i}>
              {map.get(edge.source)?.label} → <b>{edge.label}</b> →{" "}
              {map.get(edge.target)?.label}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
