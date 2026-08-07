import assert from "node:assert/strict";
import test from "node:test";

import worker from "../src/index.js";


const ENV = {
  ALLOWED_HOSTNAMES: "api.example.test",
  TURNSTILE_SITE_KEY: "test-site-key",
};

test("unknown public paths return 404 instead of rendering the allowlist form", async () => {
  for (const pathname of ["/", "/foo", "/allow-ipx", "/allow-ip/unknown"] ) {
    const response = await worker.fetch(
      new Request(`https://api.example.test${pathname}`),
      ENV,
    );

    assert.equal(response.status, 404, pathname);
    assert.equal(await response.text(), "Not found");
  }
});

test("public routes advertise only their supported methods", async () => {
  const allowlistResponse = await worker.fetch(
    new Request("https://api.example.test/allow-ip", { method: "PUT" }),
    ENV,
  );
  assert.equal(allowlistResponse.status, 405);
  assert.equal(allowlistResponse.headers.get("allow"), "GET, POST");

  const loginResponse = await worker.fetch(
    new Request("https://api.example.test/allow-ip/sub2api-login", { method: "POST" }),
    ENV,
  );
  assert.equal(loginResponse.status, 405);
  assert.equal(loginResponse.headers.get("allow"), "GET");
});

test("allowlist POST rejects unsupported media types with a stable 415 response", async () => {
  for (const contentType of ["application/json", "text/plain", "application/octet-stream"]) {
    const response = await worker.fetch(
      new Request("https://api.example.test/allow-ip", {
        method: "POST",
        headers: { "content-type": contentType },
        body: "{}",
      }),
      ENV,
    );

    assert.equal(response.status, 415, contentType);
    assert.match(response.headers.get("content-type") || "", /^text\/html/);
    assert.match(await response.text(), /Unsupported form format/);
  }
});

test("allowlist POST rejects malformed form data with a stable 400 response", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: { "content-type": "multipart/form-data; boundary=broken" },
      body: "not-a-valid-multipart-body",
    }),
    ENV,
  );

  assert.equal(response.status, 400);
  assert.match(await response.text(), /Invalid form submission/);
});

test("allowlist POST rejects unknown actions before performing external work", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ action: "unknown-action" }),
    }),
    ENV,
  );

  assert.equal(response.status, 400);
  assert.match(await response.text(), /Unknown form action/);
});

test("a UUID cookie without a configured session store is expired on the response", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip", {
      headers: { cookie: "sub2api_allow_uuid=orphaned-session" },
    }),
    ENV,
  );

  assert.equal(response.status, 200);
  assert.match(response.headers.get("set-cookie") || "", /sub2api_allow_uuid=;[^\r\n]*Max-Age=0/);
});
