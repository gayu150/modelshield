const { test } = require("node:test");
const assert = require("node:assert/strict");
const { compareHashes, validateUpload } = require("../src/utils/security.ts");
test("missing or truncated hashes never establish integrity", () => {
  for (const hash of [
    undefined,
    "Pending verification",
    "a81…123",
    "a".repeat(63),
    "z".repeat(64),
  ])
    assert.equal(compareHashes(hash, hash), "Not verified");
});
test("complete hashes compare without case sensitivity and report mismatches", () => {
  assert.equal(compareHashes("a".repeat(64), "A".repeat(64)), "Hashes match");
  assert.equal(compareHashes("a".repeat(64), "b".repeat(64)), "Hash mismatch");
});
test("uploads reject empty, excessive and disguised files", () => {
  for (const file of [
    { name: "model.onnx", size: 0 },
    { name: "model.pkl", size: 2 * 1024 ** 3 + 1 },
    { name: "model.onnx.exe", size: 42 },
    { name: "model.apk", size: 42 },
  ])
    assert.ok(validateUpload(file));
  assert.equal(validateUpload({ name: "model.ONNX", size: 42 }), undefined);
});
