import React from "react";
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import EvidenceGraph from "../src/components/security/EvidenceGraph";
import { Rows } from "../src/components/common/Registry";
import { Pagination } from "../src/components/common/Feedback";

test("graph labels and relationship content are escaped during rendering", () => {
  const html = renderToStaticMarkup(
    <EvidenceGraph
      graph={{
        nodes: [
          { id: "A", label: "<script>alert(1)</script>", kind: "Artifact" },
        ],
        edges: [
          { source: "A", target: "A", label: "<img src=x onerror=alert(1)>" },
        ],
      }}
    />,
  );
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("<img src=x"));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.ok(html.includes('aria-pressed="false"'));
});
test("empty graphs and registries communicate their state", () => {
  assert.ok(
    renderToStaticMarkup(
      <EvidenceGraph graph={{ nodes: [], edges: [] }} />,
    ).includes("No evidence graph recorded"),
  );
  assert.ok(
    renderToStaticMarkup(<Rows items={[]} onOpen={() => {}} />).includes(
      "No artifacts found",
    ),
  );
});
test("pagination clamps an obsolete page and disables the next button", () => {
  const html = renderToStaticMarkup(
    <Pagination page={7} total={3} onChange={() => {}} />,
  );
  assert.ok(html.includes("Page 1 of 1"));
  assert.equal((html.match(/disabled=""/g) || []).length, 2);
});
