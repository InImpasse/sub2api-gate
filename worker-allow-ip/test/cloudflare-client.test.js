import assert from "node:assert/strict";
import test from "node:test";

import {
  cloudflareApiFetch,
  CLOUDFLARE_RESPONSE_LIMIT_BYTES,
  CLOUDFLARE_TIMEOUT_MS,
  listCloudflareItems,
  MAX_LIST_PAGES,
  readCloudflareJson,
  waitForCloudflareOperation,
} from "../src/cloudflare-client.js";
import {
  assertCloudflareReplacement,
  assertCloudflareListSnapshot,
  buildCloudflareCommentReplacement,
} from "../src/cloudflare-comment-migration.js";

const ENV = { ACCOUNT_ID: "account", IP_LIST_ID: "list", CLOUDFLARE_API_TOKEN: "token" };

test("Cloudflare list lookup follows every cursor page", async () => {
  const originalFetch = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (url) => {
    urls.push(String(url));
    const second = String(url).includes("cursor=next-page");
    return Response.json({
      success: true,
      result: [{ id: second ? "two" : "one", ip: second ? "2001:db8::1/128" : "198.51.100.0/24" }],
      result_info: { cursors: { after: second ? "" : "next-page" } },
    });
  };
  try {
    const result = await listCloudflareItems(ENV);
    assert.deepEqual(result.items.map((item) => item.id), ["one", "two"]);
    assert.equal(urls.length, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare API JSON responses are bounded", async () => {
  const small = await readCloudflareJson(Response.json({ success: true }));
  assert.equal(small.success, true);

  await assert.rejects(
    readCloudflareJson(new Response(JSON.stringify({
      padding: "x".repeat(CLOUDFLARE_RESPONSE_LIMIT_BYTES),
    }))),
    /response_too_large/,
  );
  await assert.rejects(
    readCloudflareJson(Response.json(null)),
    /cloudflare_response_invalid/,
  );
});

test("Cloudflare list lookup requires an explicit success result shape", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ result: [] });
  try {
    const result = await listCloudflareItems(ENV);
    assert.equal(result.ok, false);
    assert.equal(result.status, 502);
    assert.equal(result.errors[0].code, "cloudflare_response_invalid");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare list lookup fails closed on malformed or oversized JSON", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("{" + "x".repeat(CLOUDFLARE_RESPONSE_LIMIT_BYTES));
  try {
    const result = await listCloudflareItems(ENV);
    assert.equal(result.ok, false);
    assert.equal(result.status, 502);
    assert.deepEqual(result.items, []);
    assert.equal(result.errors[0].code, "cloudflare_response_invalid");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare list lookup rejects a repeated cursor", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({
    success: true,
    result: [],
    result_info: { cursors: { after: "same" } },
  });
  try {
    await assert.rejects(listCloudflareItems(ENV), /cursor_repeated/);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(MAX_LIST_PAGES, 50);
});

test("Cloudflare API retries throttling and server errors", async () => {
  const originalFetch = globalThis.fetch;
  const statuses = [429, 503, 200];
  let calls = 0;
  globalThis.fetch = async () => new Response("{}", { status: statuses[calls++] });
  try {
    const response = await cloudflareApiFetch(ENV, "/rules/lists/list/items");
    assert.equal(response.status, 200);
    assert.equal(calls, 3);
    assert.equal(CLOUDFLARE_TIMEOUT_MS, 10_000);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare API never retries an ambiguous mutating request", async () => {
  const originalFetch = globalThis.fetch;
  try {
    for (const method of ["POST", "PUT", "DELETE"]) {
      let calls = 0;
      globalThis.fetch = async () => {
        calls += 1;
        return Response.json({ success: false }, { status: 503 });
      };
      const response = await cloudflareApiFetch(ENV, "/rules/lists/list/items", {
        method,
        body: "{}",
      });
      assert.equal(response.status, 503, method);
      assert.equal(calls, 1, method);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare API rejects absolute URLs before attaching credentials", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    throw new Error("fetch must not run");
  };
  try {
    await assert.rejects(
      cloudflareApiFetch(ENV, "https://attacker.example/collect"),
      /cloudflare_api_path_invalid/,
    );
    await assert.rejects(
      cloudflareApiFetch(ENV, "//attacker.example/collect"),
      /cloudflare_api_path_invalid/,
    );
    await assert.rejects(
      cloudflareApiFetch(ENV, "/rules/lists/../tokens/verify"),
      /cloudflare_api_path_invalid/,
    );
    await assert.rejects(
      cloudflareApiFetch({ ...ENV, ACCOUNT_ID: "account/../user" }, "/rules/lists/list/items"),
      /cloudflare_api_identifier_invalid/,
    );
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare API callers cannot override fixed credential headers", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    assert.equal(init.headers.get("authorization"), "Bearer token");
    assert.equal(init.headers.get("content-type"), "application/json");
    assert.equal(init.headers.get("x-request-id"), "allowed-custom-header");
    assert.equal(init.redirect, "manual");
    return Response.json({ success: true });
  };
  try {
    const response = await cloudflareApiFetch(ENV, "/rules/lists/list/items", {
      headers: {
        Authorization: "Bearer attacker-controlled",
        "Content-Type": "text/plain",
        "x-request-id": "allowed-custom-header",
      },
    });
    assert.equal(response.ok, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare API redirects are never followed and list callers fail closed", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (_url, init) => {
    calls += 1;
    assert.equal(init.redirect, "manual");
    return Response.json({ success: false, errors: [{ code: "redirect_rejected" }] }, {
      status: 302,
      headers: { location: "https://attacker.example/collect" },
    });
  };
  try {
    const result = await listCloudflareItems(ENV);
    assert.equal(result.ok, false);
    assert.equal(result.status, 302);
    assert.deepEqual(result.items, []);
    assert.equal(calls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare list lookup stops at the page safety limit", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => Response.json({
    success: true,
    result: [],
    result_info: { cursors: { after: `cursor-${++calls}` } },
  });
  try {
    await assert.rejects(listCloudflareItems(ENV), /page_limit_exceeded/);
    assert.equal(calls, MAX_LIST_PAGES);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare bulk operations are polled to completion", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ success: true, result: { status: "completed" } });
  try {
    const result = await waitForCloudflareOperation(ENV, { result: { operation_id: "operation" } });
    assert.equal(result.result.status, "completed");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare bulk operation polling fails closed on timeout", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ success: true, result: { status: "pending" } });
  try {
    await assert.rejects(
      waitForCloudflareOperation(ENV, { result: { operation_id: "operation" } }, 2),
      /operation_timeout/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare bulk operation polling rejects missing success markers", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ result: { status: "completed" } });
  try {
    await assert.rejects(
      waitForCloudflareOperation(ENV, { result: { operation_id: "operation" } }),
      /operation_lookup_failed/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("comment migration replaces the complete list and preserves unmanaged items", async () => {
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const source = [
    { id: "legacy", ip: "198.51.100.0/24", comment: `sub2api uuid ${uuid} raw 198.51.100.8` },
    { id: "managed", ip: "2001:db8::1/128", comment: "sub2api ref already-managed" },
    { id: "manual", ip: "203.0.113.0/24", comment: "manual operations entry" },
  ];
  const plan = await buildCloudflareCommentReplacement(
    source,
    "test-only-hmac-key-with-at-least-32-bytes",
  );

  assert.equal(plan.legacyCount, 1);
  assert.equal(plan.items.length, source.length);
  assert.deepEqual(plan.items.map((item) => item.ip), source.map((item) => item.ip));
  assert.equal(plan.items[1].comment, source[1].comment);
  assert.equal(plan.items[2].comment, source[2].comment);
  assert.doesNotMatch(plan.items[0].comment, new RegExp(uuid));
  assert.equal("id" in plan.items[0], false);
});

test("comment migration aborts if the list changes before replacement", () => {
  const source = [{ id: "one", ip: "198.51.100.0/24", comment: "before" }];
  assert.doesNotThrow(() => assertCloudflareListSnapshot(source, structuredClone(source)));
  assert.throws(
    () => assertCloudflareListSnapshot(source, [{ ...source[0], comment: "changed" }]),
    /cloudflare_list_changed/,
  );
  assert.doesNotThrow(() => assertCloudflareReplacement(source, structuredClone(source)));
  assert.throws(
    () => assertCloudflareReplacement(source, [{ ...source[0], comment: "changed" }]),
    /replacement_verification_failed/,
  );
});
