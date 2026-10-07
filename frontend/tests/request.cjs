const { test } = require("node:test");
const assert = require("node:assert/strict");
const { request, ApiError } = require("../src/utils/request.ts");
test("API requests preserve cookies and JSON and CSRF headers", async (t) => {
  let captured;
  t.mock.method(global, "fetch", async (url, options) => {
    captured = { url, options };
    return new Response('{"id":"A"}', { status: 200 });
  });
  assert.deepEqual(
    await request(
      "/api/",
      "/artifacts",
      { method: "POST", body: "{}", headers: { "X-Custom": "value" } },
      { csrfToken: "test-token" },
    ),
    { id: "A" },
  );
  assert.equal(captured.url, "/api/artifacts");
  assert.equal(captured.options.credentials, "include");
  assert.equal(
    captured.options.headers.get("content-type"),
    "application/json",
  );
  assert.equal(captured.options.headers.get("X-CSRF-Token"), "test-token");
  assert.equal(captured.options.headers.get("X-Custom"), "value");
});
test("multipart uploads leave boundary generation to the browser", async (t) => {
  t.mock.method(global, "fetch", async (_, options) => {
    assert.equal(options.headers.has("content-type"), false);
    return new Response(null, { status: 204 });
  });
  const body = new FormData();
  body.append("file", new Blob(["model"]), "model.onnx");
  assert.equal(
    await request("/api", "/artifacts", { method: "POST", body }),
    undefined,
  );
});
test("unauthorized requests expire sessions and do not expose server details", async (t) => {
  let expired = false;
  t.mock.method(
    global,
    "fetch",
    async () => new Response("secret stack trace", { status: 401 }),
  );
  await assert.rejects(
    request("/api", "/auth/me", {}, { onUnauthorized: () => (expired = true) }),
    (error) =>
      error instanceof ApiError &&
      error.status === 401 &&
      !error.message.includes("secret"),
  );
  assert.equal(expired, true);
});
test("forbidden requests retain sessions and invalid JSON fails safely", async (t) => {
  let expired = false;
  const fetch = t.mock.method(
    global,
    "fetch",
    async () => new Response("internal details", { status: 403 }),
  );
  await assert.rejects(
    request(
      "/api",
      "/artifacts",
      {},
      { onUnauthorized: () => (expired = true) },
    ),
    (error) => error.status === 403,
  );
  assert.equal(expired, false);
  fetch.mock.mockImplementation(
    async () => new Response("<html>error</html>", { status: 200 }),
  );
  await assert.rejects(
    request("/api", "/artifacts"),
    (error) => error.status === 502 && !error.message.includes("<html>"),
  );
});
test("caller cancellation reaches fetch", async (t) => {
  const controller = new AbortController();
  controller.abort();
  t.mock.method(global, "fetch", async (_, options) => {
    assert.equal(options.signal.aborted, true);
    throw options.signal.reason;
  });
  await assert.rejects(
    request("/api", "/artifacts", { signal: controller.signal }),
    { name: "AbortError" },
  );
});
