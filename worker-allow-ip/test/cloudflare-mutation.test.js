import assert from "node:assert/strict";
import test from "node:test";

import {
  createManagedCloudflareListItems,
  findCloudflareMutationCandidates,
} from "../src/cloudflare-mutation.js";
import { cloudflareListValueHmac } from "../src/credential-security.js";

const HMAC_KEY = "test-only-hmac-key-with-at-least-32-bytes";
const VALUE = "198.51.100.0/24";

test("async Cloudflare creates re-list exact IDs even when the operation result is empty", async () => {
  const markers = new Map();
  const env = makeEnv(markers);
  const originalFetch = globalThis.fetch;
  let postedComment = "";
  const calls = [];
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input);
    calls.push(`${init.method || "GET"} ${url.pathname}`);
    if (init.method === "POST") {
      const [item] = JSON.parse(init.body);
      postedComment = item.comment;
      return Response.json({ success: true, result: { operation_id: "operation-one" } });
    }
    if (url.pathname.endsWith("/bulk_operations/operation-one")) {
      return Response.json({ success: true, result: { status: "completed" } });
    }
    return Response.json({
      success: true,
      result: [{ id: "created-item", ip: VALUE, comment: postedComment }],
      result_info: { cursors: { after: "" } },
    });
  };

  try {
    const result = await createManagedCloudflareListItems(env, [VALUE], 1_000_000);
    assert.equal(result.items[0].id, "created-item");
    assert.equal(result.items[0].ip, VALUE);
    assert.match(result.comment, /^sub2api ref [a-f0-9]{32}$/);
    const stored = markers.get(result.mutationId);
    assert.deepEqual(stored.itemIds, ["created-item"]);
    assert.deepEqual(Object.keys(stored).sort(), [
      "comment", "createdAt", "expectedValueHashes", "itemIds",
      "leaseUntil", "mutationId", "notBefore",
    ].sort());
    assert.doesNotMatch(JSON.stringify(stored), /198\.51\.100|7c484f74/);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.deepEqual(calls, [
    "POST /client/v4/accounts/account/rules/lists/list/items",
    "GET /client/v4/accounts/account/rules/lists/bulk_operations/operation-one",
    "GET /client/v4/accounts/account/rules/lists/list/items",
  ]);
});

test("mutation candidate lookup requires current ID/value ownership and tolerates comment edits", async () => {
  const env = makeEnv(new Map());
  const marker = {
    comment: `sub2api ref ${"a".repeat(32)}`,
    expectedValueHashes: [await cloudflareListValueHmac(HMAC_KEY, VALUE)],
    itemIds: ["created-item"],
  };
  const candidates = await findCloudflareMutationCandidates(env, marker, [
    { id: "created-item", ip: VALUE, comment: "managed by another service" },
    { id: "created-item", ip: "203.0.113.0/24", comment: marker.comment },
    { id: "other-id", ip: "203.0.113.0/24", comment: marker.comment },
    { id: "exact-id", ip: VALUE, comment: marker.comment },
  ]);
  assert.deepEqual(candidates.map((item) => item.id), ["created-item", "exact-id"]);
});

test("malformed create responses reconcile by re-listing the committed side effect", async () => {
  const markers = new Map();
  const env = makeEnv(markers);
  const originalFetch = globalThis.fetch;
  let created = null;
  globalThis.fetch = async (_input, init = {}) => {
    if (init.method === "POST") {
      const [item] = JSON.parse(init.body);
      created = { id: "created-after-malformed", ip: item.ip, comment: item.comment };
      return new Response("not-json", { status: 502 });
    }
    return Response.json({ success: true, result: created ? [created] : [] });
  };
  try {
    const result = await createManagedCloudflareListItems(env, [VALUE], 2_000_000);
    assert.equal(result.items[0].id, "created-after-malformed");
    assert.deepEqual(markers.get(result.mutationId).itemIds, ["created-after-malformed"]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a failed create with no re-listed item retains its reconciliation marker", async () => {
  const markers = new Map();
  const env = makeEnv(markers);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init = {}) => init.method === "POST"
    ? Response.json({ success: false, errors: [{ code: "rejected" }] }, { status: 400 })
    : Response.json({ success: true, result: [] });
  try {
    await assert.rejects(
      createManagedCloudflareListItems(env, [VALUE], 3_000_000),
      (error) => /^[a-f0-9]{64}$/.test(error.mutationId),
    );
    assert.equal(markers.size, 1);
    assert.deepEqual([...markers.values()][0].itemIds, []);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function makeEnv(markers) {
  const stub = {
    async status() { return { migrated: true }; },
    async registerCloudflareMutation(marker) {
      markers.set(marker.mutationId, structuredClone(marker));
      return { ok: true, created: true };
    },
    async updateCloudflareMutationItems(mutationId, itemIds) {
      const marker = markers.get(mutationId);
      markers.set(mutationId, { ...marker, itemIds: structuredClone(itemIds) });
      return { ok: true, updated: true };
    },
  };
  return {
    AUTH_STATE: { getByName() { return stub; } },
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
    ACCOUNT_ID: "account",
    IP_LIST_ID: "list",
    CLOUDFLARE_API_TOKEN: "token",
  };
}
