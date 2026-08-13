import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { CLOUDFLARE_DELETE_BATCH_SIZE, handleAdmin, __test } from "../src/admin.js";

const SENTINEL = "PRIVATE_CONVERSATION_SENTINEL_7f3b90";
const ADMIN_SOURCE = readFileSync(new URL("../src/admin.js", import.meta.url), "utf8");

test("usage inspector strips every content-bearing field", () => {
  const result = __test.sanitizeUsageInspectorData({
    items: [{
      id: 1, requestId: "req-1", model: "gpt-test", inputTokens: 3,
      outputTokens: 2, actualCost: "0.001", prompt: SENTINEL,
      bodyText: SENTINEL, messages: [{ content: SENTINEL }],
      responsePreview: SENTINEL, headers: { authorization: SENTINEL },
    }],
  });
  assert.doesNotMatch(JSON.stringify(result), new RegExp(SENTINEL));
  assert.deepEqual(Object.keys(result.items[0]).sort(), [
    "actualCost", "cacheCreationTokens", "cacheReadTokens", "createdAt",
    "durationMs", "id", "inboundEndpoint", "inputTokens", "model",
    "outputTokens", "requestId", "requestType", "requestedModel", "stream",
    "totalCost",
  ].sort());
});

test("metadata inspector HTML cannot render conversation content", () => {
  const data = __test.sanitizeUsageInspectorData({
    items: [{ id: 1, requestId: "req-1", model: "gpt-test", prompt: SENTINEL }],
  });
  const html = __test.renderTrustedHtml(
    __test.renderUsageInspector(
      data,
      "csrf",
      new Request("https://admin.test/allow-ip/admin/requests"),
    ),
    "test-nonce",
  );
  assert.doesNotMatch(html, new RegExp(SENTINEL));
  assert.match(html, /Usage Inspector/);
});

test("usage inspector is single-column on mobile with explicit dark detail colors", () => {
  const html = __test.renderTrustedHtml(
    __test.renderUsageInspector(
      { items: [{ id: 1, requestId: "req-1", model: "gpt-test" }] },
      "csrf",
      new Request("https://admin.test/allow-ip/admin/requests"),
    ),
    "test-nonce",
  );

  assert.match(
    html,
    /@media \(max-width: 680px\)[\s\S]*?\.usage-row, \.usage-detail \{[\s\S]*?grid-template-columns: minmax\(0, 1fr\)/,
  );
  assert.match(html, /\.usage-row \.nav-link \{ width: 100%; \}/);
  assert.match(
    html,
    /@media \(prefers-color-scheme: dark\)[\s\S]*?\.usage-detail div \{ background: #1c1c1e; color: #f5f5f7; \}/,
  );
  assert.match(html, /\.usage-detail dt \{ color: #aeaeb2; \}/);
  assert.match(html, /\.wide-layout \{ align-items: start; \}/);
  assert.match(html, /<body class="wide-layout">/);
});

test("admin UI reflows at 200 percent zoom and keeps dark muted text readable", () => {
  const html = __test.renderTrustedHtml(
    __test.renderUsageInspector(
      { items: [{ id: 1, requestId: "req-1", model: "gpt-test" }] },
      "csrf",
      new Request("https://admin.test/allow-ip/admin/requests"),
    ),
    "test-nonce",
  );

  assert.match(
    html,
    /@media \(max-width: 240px\)[\s\S]*?\.topbar-title \{[\s\S]*?grid-template-columns: minmax\(0, 1fr\)/,
  );
  assert.match(
    html,
    /@media \(max-width: 240px\)[\s\S]*?\.expiry-form input\[type="datetime-local"\],\s*\.manual-ip-grid input\[type="datetime-local"\] \{ min-width: 0; max-width: 100%; \}/,
  );
  assert.match(
    html,
    /@media \(prefers-color-scheme: dark\)[\s\S]*?\.empty \{ color: #98989d; \}/,
  );
  assert.match(
    html,
    /@media \(prefers-color-scheme: dark\)[\s\S]*?\.endpoint-summary \{[\s\S]*?background: rgba\(255, 255, 255, 0\.04\);/,
  );
  assert.ok(contrastRatio("#98989d", "#1c1c1e") >= 4.5);
});

function contrastRatio(foreground, background) {
  const luminance = (color) => {
    const channels = color.match(/[0-9a-f]{2}/gi).map((value) => parseInt(value, 16) / 255);
    const linear = channels.map((value) => (
      value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4
    ));
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
  };
  const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

test("sync calls have a bounded timeout", () => {
  assert.ok(__test.SUB2API_SYNC_TIMEOUT_MS >= 1000);
  assert.ok(__test.SUB2API_SYNC_TIMEOUT_MS <= 10000);
});

test("admin GET policy uses cached invite state", () => {
  assert.equal(__test.shouldRefreshInvitesOnAdminGet(), false);
});

test("admin routes reject unknown paths, unsupported methods, and non-form posts", async () => {
  const env = adminEnv({
    async get() { return null; },
    async put() {},
    async delete() {},
  });

  const unknown = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin/unknown",
  ), env);
  assert.equal(unknown.status, 404);

  const wrongBaseMethod = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin",
    { method: "PUT" },
  ), env);
  assert.equal(wrongBaseMethod.status, 405);
  assert.equal(wrongBaseMethod.headers.get("allow"), "GET, POST");

  const wrongUsageMethod = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin/requests",
    { method: "POST" },
  ), env);
  assert.equal(wrongUsageMethod.status, 405);
  assert.equal(wrongUsageMethod.headers.get("allow"), "GET");

  const unsupported = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "login" }),
    },
  ), env);
  assert.equal(unsupported.status, 415);

  const malformed = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin",
    {
      method: "POST",
      headers: { "content-type": "multipart/form-data" },
      body: "not-a-multipart-body",
    },
  ), env);
  assert.equal(malformed.status, 400);
});

test("authenticated admin posts reject unknown actions instead of redirecting", async () => {
  const token = "unknown-admin-action-session";
  const sessionHash = await sha256Hex(token);
  const csrf = "unknown-admin-action-csrf";
  const values = new Map([
    [`session:${sessionHash}`, JSON.stringify(await boundAdminSession(csrf, Date.now() + 60_000))],
    ["invites", "[]"],
    ["trash", "[]"],
  ]);
  const env = adminEnv({
    async get(key) { return values.get(key) ?? null; },
    async put(key, value) { values.set(key, value); },
    async delete(key) { values.delete(key); },
  });

  const response = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin",
    {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_admin=${token}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({ action: "unknown_action", csrf }),
    },
  ), env);
  const body = await response.text();

  assert.equal(response.status, 400);
  assert.match(body, /Unknown admin action/);
  assert.equal(response.headers.get("location"), null);
});

test("invalid admin cookies are expired and one request reuses one AuthState store", async () => {
  const missingToken = "revoked-admin-session";
  const missing = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin",
    { headers: { cookie: `sub2api_allow_admin=${missingToken}` } },
  ), adminEnv({
    async get() { return null; },
    async put() {},
    async delete() {},
  }));
  assert.equal(missing.status, 200);
  assert.match(missing.headers.get("set-cookie") || "", /Max-Age=0/);

  const token = "request-scoped-auth-state-session";
  const sessionHash = await sha256Hex(token);
  const session = await boundAdminSession("request-scoped-csrf", Date.now() + 60_000);
  let bindingLookups = 0;
  let statusCalls = 0;
  const stub = {
    async status() {
      statusCalls += 1;
      return { migrated: true, legacyCleanupComplete: true };
    },
    async getAdminSession(hash) {
      assert.equal(hash, sessionHash);
      return session;
    },
    async getAdminPage() {
      return {
        inviteCount: 0,
        trashCount: 0,
        unmigratedInviteCount: 0,
        invites: [],
        trash: [],
      };
    },
  };
  const env = {
    ...adminEnv({ async get() { return null; }, async put() {}, async delete() {} }),
    AUTH_STATE: {
      getByName() {
        bindingLookups += 1;
        return stub;
      },
    },
  };

  const response = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin",
    { headers: { cookie: `sub2api_allow_admin=${token}` } },
  ), env);
  assert.equal(response.status, 200);
  assert.equal(bindingLookups, 1);
  assert.equal(statusCalls, 1);
});

test("one admin allowlist mutation reuses the request AuthState readiness check", async () => {
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const token = "request-scoped-cloudflare-mutation-session";
  const csrf = "request-scoped-cloudflare-mutation-csrf";
  const sessionHash = await sha256Hex(token);
  const session = await boundAdminSession(csrf, Date.now() + 60_000);
  let bindingLookups = 0;
  let statusCalls = 0;
  let createdItem = null;
  const markers = new Map();
  const records = new Map();
  const stub = {
    async status() {
      statusCalls += 1;
      return { migrated: true, legacyCleanupComplete: true };
    },
    async getAdminSession(hash) {
      assert.equal(hash, sessionHash);
      return session;
    },
    async getInvites() {
      return {
        revision: 1,
        items: [{ uuid, username: "admin-test", apiConfigs: [], sub2apiSync: {} }],
      };
    },
    async claimRecordLease(_uuid, _ownerToken, now, leaseMs) {
      return { claimed: true, leaseUntil: now + leaseMs };
    },
    async releaseRecordLease() {
      return { released: true };
    },
    async registerCloudflareMutation(marker) {
      markers.set(marker.mutationId, structuredClone(marker));
      return { ok: true, created: true };
    },
    async updateCloudflareMutationItems(mutationId, itemIds) {
      const marker = markers.get(mutationId);
      markers.set(mutationId, { ...marker, itemIds: structuredClone(itemIds) });
      return { ok: true, updated: true };
    },
    async resolveCloudflareMutation(mutationId) {
      return { ok: true, resolved: markers.delete(mutationId) };
    },
  };
  const env = {
    ...adminEnv({
      async get(key) { return records.get(key) ?? null; },
      async put(key, value) { records.set(key, value); },
      async delete(key) { records.delete(key); },
    }),
    AUTH_STATE: {
      getByName() {
        bindingLookups += 1;
        return stub;
      },
    },
    AUTH_RATE_LIMITER: {
      getByName() {
        return {
          async consume() {
            return { allowed: true, retryAfterSeconds: 0, resetAt: Date.now() + 60_000 };
          },
          async reset() { return { ok: true }; },
        };
      },
    },
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init = {}) => {
    if (init.method === "POST") {
      const [item] = JSON.parse(init.body);
      createdItem = { id: "request-scoped-created-item", ...item };
      return Response.json({ success: true, result: {} });
    }
    return Response.json({
      success: true,
      result: createdItem ? [createdItem] : [],
      result_info: { cursors: { after: "" } },
    });
  };

  try {
    const stepUpToken = await __test.totp(
      env.ADMIN_TOTP_SECRET,
      Math.floor(Date.now() / 1000 / 30),
    );
    const response = await handleAdmin(new Request(
      "https://api.example.test/allow-ip/admin",
      {
        method: "POST",
        headers: {
          cookie: `sub2api_allow_admin=${token}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          action: "add_ip_group",
          csrf,
          step_up_token: stepUpToken,
          uuid,
          ip_value: "198.51.100.8",
          expires_in_days: "7",
          expiration_mode: "days",
          admin_context: "p=2&t=3&i=4&v=e",
        }),
      },
    ), env);

    assert.equal(response.status, 303);
    assert.equal(
      response.headers.get("location"),
      `/allow-ip/admin?page=2&trashPage=3&edit=${uuid}&ipPage=4`,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(bindingLookups, 1);
  assert.equal(statusCalls, 1);
});

test("admin preserves stable sync failures without exposing upstream detail", async () => {
  const token = "stable-sync-error-session";
  const sessionHash = await sha256Hex(token);
  const values = new Map([[
    `session:${sessionHash}`,
    JSON.stringify(await boundAdminSession("sync-error-csrf", Date.now() + 60_000)),
  ]]);
  const env = adminEnv({
    async get(key) { return values.get(key) ?? null; },
    async put(key, value) { values.set(key, value); },
    async delete(key) { values.delete(key); },
  });
  const originalFetch = globalThis.fetch;
  const privateDetail = "private-origin-detail-must-not-escape";
  globalThis.fetch = async () => Response.json({
    ok: false,
    error: "dependency_unavailable",
    retryable: true,
    requestId: "sync-admin-503",
    action: "usage_logs_list",
    detail: privateDetail,
  }, {
    status: 503,
    headers: { "x-request-id": "sync-admin-503" },
  });
  try {
    const response = await handleAdmin(new Request(
      "https://api.example.test/allow-ip/admin/requests",
      { headers: { cookie: `sub2api_allow_admin=${token}` } },
    ), env);
    const body = await response.text();
    assert.equal(response.status, 503);
    assert.equal(response.headers.get("x-request-id"), "sync-admin-503");
    assert.equal(response.headers.get("retry-after"), "1");
    assert.match(body, /dependency_unavailable/);
    assert.match(body, /sync-admin-503/);
    assert.doesNotMatch(body, new RegExp(privateDetail));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Cloudflare deletion resolves current IDs instead of stale stored IDs", () => {
  const ids = __test.resolveCurrentCloudflareDeleteIds(
    [{ listItemId: "stale", listValue: "198.51.100.0/24" }],
    [{ id: "current", ip: "198.51.100.0/24" }],
    new Set(),
  );
  assert.deepEqual(ids, ["current"]);
});

test("Cloudflare deletion is deterministic, bounded, serial, and recovers after a later batch fails", async () => {
  const originalFetch = globalThis.fetch;
  const comment = `sub2api ref ${"a".repeat(32)}`;
  const listItems = Array.from({ length: CLOUDFLARE_DELETE_BATCH_SIZE + 3 }, (_, index) => ({
    id: `item_${String(CLOUDFLARE_DELETE_BATCH_SIZE + 2 - index).padStart(5, "0")}`,
    ip: `list-value-${index}`,
    comment,
  }));
  const deleteBatches = [];
  let deleteCalls = 0;
  let failSecondBatch = true;

  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || "GET";
    if (url.pathname.includes("/bulk_operations/")) {
      return Response.json({ success: true, result: { status: "completed" } });
    }
    if (method === "GET") {
      return Response.json({
        success: true,
        result: structuredClone(listItems),
        result_info: { cursors: { after: "" } },
      });
    }
    assert.equal(method, "DELETE");
    deleteCalls += 1;
    const ids = JSON.parse(init.body).items.map((item) => item.id);
    deleteBatches.push(ids);
    if (failSecondBatch && deleteCalls === 2) {
      return Response.json({ success: false }, { status: 503 });
    }
    for (let index = listItems.length - 1; index >= 0; index -= 1) {
      if (ids.includes(listItems[index].id)) listItems.splice(index, 1);
    }
    return Response.json({ success: true, result: { operation_id: `operation_${deleteCalls}` } });
  };

  try {
    await assert.rejects(
      __test.deleteOrphanedCloudflareListItems({
        ACCOUNT_ID: "account",
        IP_LIST_ID: "list",
        CLOUDFLARE_API_TOKEN: "token",
      }, new Set()),
      /delete failed/,
    );
    assert.equal(deleteCalls, 2);
    assert.equal(listItems.length, 3);
    failSecondBatch = false;
    const deleted = await __test.deleteOrphanedCloudflareListItems({
      ACCOUNT_ID: "account",
      IP_LIST_ID: "list",
      CLOUDFLARE_API_TOKEN: "token",
    }, new Set());
    assert.equal(deleted, 3);
    assert.equal(listItems.length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.deepEqual(deleteBatches.map((batch) => batch.length), [
    CLOUDFLARE_DELETE_BATCH_SIZE,
    3,
    3,
  ]);
  assert.deepEqual(deleteBatches[0], [...deleteBatches[0]].sort());
});

test("Cloudflare deletion rejects malformed item IDs without making a request", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return Response.json({ success: true });
  };
  try {
    await assert.rejects(
      __test.deleteCloudflareListItemIds({
        ACCOUNT_ID: "account",
        IP_LIST_ID: "list",
        CLOUDFLARE_API_TOKEN: "token",
      }, ["valid-id", "invalid/id"]),
      /delete failed/,
    );
    assert.equal(calls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("admin dashboard list returns at most 25 summaries without reading IP records", async () => {
  const pageInvites = Array.from({ length: 100 }, (_, index) => ({
    uuid: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
    username: `user-${index}`,
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [],
    sub2apiSync: {},
  }));
  const calls = [];
  let recordReads = 0;
  const stub = {
    async status() { return { migrated: true }; },
    async getAdminPage(...args) {
      calls.push(args);
      return {
        inviteRevision: 2,
        trashRevision: 3,
        inviteCount: 100,
        trashCount: 75,
        unmigratedInviteCount: 9,
        invites: pageInvites,
        trash: [],
      };
    },
    async getInvite() { throw new Error("list view must not look up an invite detail"); },
    async getInvites() { throw new Error("full invite read is forbidden"); },
    async getTrash() { throw new Error("full trash read is forbidden"); },
  };
  const env = {
    AUTH_STATE: { getByName() { return stub; } },
    INVITE_STORE: {
      async get(key) {
        assert.match(key, /^records:/);
        recordReads += 1;
        return "[]";
      },
    },
    CREDENTIAL_ENCRYPTION_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
    ALLOWED_HOSTNAMES: "api.example.test",
  };

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("admin list must not call Sub2API sync");
  };
  try {
    const dashboard = await __test.getAdminDashboard(
      env,
      new URL("https://api.example.test/allow-ip/admin?page=2&trashPage=3"),
    );
    assert.deepEqual(calls, [[25, 25, 0, 1]]);
    assert.equal(dashboard.inviteCount, 100);
    assert.equal(dashboard.trashCount, 75);
    assert.equal(dashboard.unmigratedInviteCount, 9);
    assert.equal(dashboard.invites.length, 25);
    assert.equal(dashboard.selectedInvite, null);
    assert.deepEqual(dashboard.keyGroups, []);
    assert.equal(recordReads, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("selected admin detail reads one invite record and paginates IP groups by 20", async () => {
  const pageInvites = Array.from({ length: 25 }, (_, index) => ({
    uuid: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
    username: `user-${index}`,
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [],
    sub2apiSync: {},
  }));
  const detailUuid = "00000000-0000-4000-8000-000000000063";
  const groups = Array.from({ length: 45 }, (_, index) => ({
    id: `group-${index}`,
    ips: [{ ip: `198.51.100.${index}`, cidr: "198.51.100.0/24" }],
  }));
  let detailLookups = 0;
  let recordReads = 0;
  const stub = {
    async status() { return { migrated: true }; },
    async getAdminPage() {
      return {
        inviteCount: 100,
        trashCount: 0,
        unmigratedInviteCount: 0,
        invites: pageInvites,
        trash: [],
      };
    },
    async getInvite(uuid) {
      detailLookups += 1;
      assert.equal(uuid, detailUuid);
      return { uuid, username: "selected", accessKeyHmac: "b".repeat(64), apiConfigs: [], sub2apiSync: {} };
    },
  };
  const env = {
    AUTH_STATE: { getByName() { return stub; } },
    INVITE_STORE: {
      async get(key) {
        recordReads += 1;
        assert.equal(key, `records:${detailUuid}`);
        return JSON.stringify(groups);
      },
    },
    CREDENTIAL_ENCRYPTION_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
    ALLOWED_HOSTNAMES: "api.example.test",
  };

  const dashboard = await __test.getAdminDashboard(
    env,
    new URL(`https://api.example.test/allow-ip/admin?detail=${detailUuid}&ipPage=2`),
  );

  assert.equal(dashboard.invites.length, 25);
  assert.equal(detailLookups, 1);
  assert.equal(recordReads, 1);
  assert.equal(dashboard.selectedInvite.uuid, detailUuid);
  assert.equal(dashboard.selectedInvite.recordCount, 45);
  assert.equal(dashboard.selectedInvite.ipPage, 2);
  assert.equal(dashboard.selectedInvite.records.length, 20);
  assert.equal(dashboard.selectedInvite.records[0].id, "group-20");
  assert.equal(dashboard.selectedInvite.records[19].id, "group-39");
});

test("edit URL returns credential metadata without decrypting the selected invite", async () => {
  const editUuid = "00000000-0000-4000-8000-000000000001";
  let recordReads = 0;
  let detailLookups = 0;
  const stub = {
    async status() { return { migrated: true }; },
    async getAdminPage() {
      return {
        inviteCount: 1,
        trashCount: 0,
        unmigratedInviteCount: 0,
        invites: [{
          uuid: editUuid,
          username: "editor",
          accessKeyHmac: "configured",
          apiConfigCount: 1,
        }],
        trash: [],
      };
    },
    async getInvite(uuid) {
      detailLookups += 1;
      assert.equal(uuid, editUuid);
      return {
        uuid,
        username: "editor",
        accessKeyHmac: "a".repeat(64),
        apiConfigs: [{
          id: "credential-edit-1",
          name: "OpenAI",
          baseUrl: "https://provider.example.test/v1",
          apiKeyEncrypted: { v: 2, alg: "A256GCM", iv: "not-decryptable", data: "not-decryptable" },
        }],
        sub2apiSync: {},
      };
    },
  };
  const env = {
    AUTH_STATE: { getByName() { return stub; } },
    INVITE_STORE: {
      async get(key) {
        recordReads += 1;
        assert.equal(key, `records:${editUuid}`);
        return "[]";
      },
    },
    CREDENTIAL_ENCRYPTION_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
    ALLOWED_HOSTNAMES: "api.example.test",
    PROVIDER_ALLOWED_HOSTNAMES: "provider.example.test",
  };

  const dashboard = await __test.getAdminDashboard(
    env,
    new URL(`https://api.example.test/allow-ip/admin?edit=${editUuid}`),
  );

  assert.equal(recordReads, 1);
  assert.equal(detailLookups, 1);
  assert.equal(dashboard.invites[0].apiConfigs.length, 0);
  assert.equal(dashboard.invites[0].apiConfigCount, 1);
  assert.equal(dashboard.selectedInvite.uuid, editUuid);
  assert.deepEqual(dashboard.selectedInvite.apiConfigs, [{
    id: "credential-edit-1",
    name: "OpenAI",
    baseUrl: "https://provider.example.test/v1",
    credentialConfigured: true,
  }]);
  assert.doesNotMatch(JSON.stringify(dashboard.selectedInvite), /apiKey|A256GCM|not-decryptable/);
});

test("removing the final saved API row clears its credential reference", () => {
  const branch = ADMIN_SOURCE.match(/if \(rows\.length === 1\) \{([\s\S]*?)\n\s*return;/)?.[1] || "";
  assert.match(branch, /delete row\.dataset\.existingCredentialId/);
  assert.match(branch, /row\.querySelector\("\.credential-meta"\)\?\.remove\(\)/);
  assert.match(branch, /keyInput\.dispatchEvent\(new Event\("input", \{ bubbles: true \}\)\)/);
});

test("admin list HTTP response stays within 96 KiB and renders only the UUID view", async () => {
  const sessionToken = "admin-list-budget-session";
  const sessionHash = await sha256Hex(sessionToken);
  const oversizedLegacyText = "x".repeat(20_000);
  const invites = Array.from({ length: 30 }, (_, index) => ({
    uuid: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
    username: `user-${index}-${oversizedLegacyText}`,
    email: `${oversizedLegacyText}@example.test`,
    remark: oversizedLegacyText,
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [{ name: oversizedLegacyText, baseUrl: "https://api.example.test/v1", apiKey: "secret" }],
    sub2apiSync: {},
  }));
  let recordReads = 0;
  const values = new Map([
    [`session:${sessionHash}`, JSON.stringify(
      await boundAdminSession("csrf", Date.now() + 60_000),
    )],
    ["invites", JSON.stringify(invites)],
    ["trash", "[]"],
  ]);
  const env = adminEnv({
    async get(key) {
      if (key.startsWith("records:")) recordReads += 1;
      return values.get(key) ?? null;
    },
    async put(key, value) { values.set(key, value); },
    async delete(key) { values.delete(key); },
  });

  const response = await handleAdmin(new Request("https://api.example.test/allow-ip/admin", {
    headers: { cookie: `sub2api_allow_admin=${sessionToken}` },
  }), env);
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.equal(recordReads, 0);
  assert.equal((body.match(/<article class="panel invite-card/g) || []).length, 25);
  assert.doesNotMatch(body, /name="action" value="add_ip_group"/);
  assert.doesNotMatch(body, /<h3>IP groups<\/h3>/);
  assert.doesNotMatch(body, /<h2>Create UUID<\/h2>|<h2>Access key migration<\/h2>|<h2>Recycle Bin<\/h2>/);
  assert.match(body, /aria-current="page"[^>]*>UUIDs<\/a>/);
  assert.ok(new TextEncoder().encode(body).byteLength <= 96 * 1024);
});

test("admin detail HTTP response stays within 128 KiB and paginates 20 IP groups", async () => {
  const sessionToken = "admin-detail-budget-session";
  const sessionHash = await sha256Hex(sessionToken);
  const detailUuid = "00000000-0000-4000-8000-000000000019";
  const invites = Array.from({ length: 25 }, (_, index) => ({
    uuid: `00000000-0000-4000-8000-${(index + 25).toString(16).padStart(12, "0")}`,
    username: `user-${index + 25}`,
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [],
    sub2apiSync: {},
  }));
  invites[0] = { ...invites[0], uuid: detailUuid, username: "selected" };
  const groups = Array.from({ length: 45 }, (_, index) => ({
    id: `group-${index}`,
    country: "US",
    region: "Test region",
    city: `City ${index}`,
    addedAt: "2026-07-01T00:00:00.000Z",
    expiresAt: "2027-07-01T00:00:00.000Z",
    ips: [{
      ip: `198.51.100.${index}`,
      version: "IPv4",
      cidr: "198.51.100.0/24",
      listValue: "198.51.100.0/24",
    }],
  }));
  let recordReads = 0;
  let detailLookups = 0;
  const session = await boundAdminSession("csrf", Date.now() + 60_000);
  const stub = {
    async status() { return { migrated: true }; },
    async getAdminSession(hash) {
      assert.equal(hash, sessionHash);
      return session;
    },
    async getAdminPage(inviteOffset, inviteLimit, trashOffset, trashLimit) {
      assert.deepEqual([inviteOffset, inviteLimit, trashOffset, trashLimit], [0, 1, 0, 1]);
      return {
        inviteCount: 100,
        trashCount: 75,
        unmigratedInviteCount: 0,
        invites,
        trash: [],
      };
    },
    async getInvite(uuid) {
      detailLookups += 1;
      assert.equal(uuid, detailUuid);
      return invites[0];
    },
  };
  const env = {
    ...adminEnv({
      async get(key) {
        recordReads += 1;
        assert.equal(key, `records:${detailUuid}`);
        return JSON.stringify(groups);
      },
      async put() {},
      async delete() {},
    }),
    AUTH_STATE: { getByName() { return stub; } },
  };

  const response = await handleAdmin(new Request(
    `https://api.example.test/allow-ip/admin?page=2&trashPage=3&detail=${detailUuid}&ipPage=2`,
    { headers: { cookie: `sub2api_allow_admin=${sessionToken}` } },
  ), env);
  const body = await response.text();

  assert.equal(response.status, 200);
  assert.equal(detailLookups, 1);
  assert.equal(recordReads, 1);
  assert.equal((body.match(/<details class="ip-group"/g) || []).length, 20);
  assert.match(body, /Page 2 of 3 · 45 groups/);
  assert.match(body, new RegExp(`page=2&amp;trashPage=3&amp;detail=${detailUuid}&amp;ipPage=3`));
  const forms = [...body.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/g)].map((match) => match[0]);
  for (const action of [
    "rotate_access_key",
    "reset_sub2api_password",
    "refresh_sub2api_status",
    "delete",
    "add_ip_group",
    "delete_ip_group",
    "update_ip_group_expiration",
  ]) {
    const actionForms = forms.filter((form) => form.includes(`name="action" value="${action}"`));
    assert.ok(actionForms.length > 0, `expected a rendered ${action} form`);
    for (const form of actionForms) {
      assert.match(form, /name="admin_context" value="p=2&amp;t=3&amp;i=2&amp;v=d"/);
    }
  }
  assert.doesNotMatch(body, /<h2>Create UUID<\/h2>|<h2>Access key migration<\/h2>|<h2>UUIDs<\/h2>|<h2>Recycle Bin<\/h2>/);
  assert.ok(body.indexOf("<h2>Selected UUID</h2>") < body.indexOf("<strong>selected</strong>"));
  assert.ok(new TextEncoder().encode(body).byteLength <= 128 * 1024);
});

test("create and maintenance are focused views and legacy trash bookmarks canonicalize", async () => {
  const sessionToken = "admin-focused-view-session";
  const sessionHash = await sha256Hex(sessionToken);
  const trashItems = Array.from({ length: 52 }, (_, index) => index === 51
    ? {
        id: `trash-${index}`,
        type: "ip_group",
        uuid: "00000000-0000-4000-8000-000000000051",
        deletedAt: "2026-07-01T00:00:00.000Z",
        group: { id: "group-51", country: "US", ips: [] },
      }
    : {
        id: `trash-${index}`,
        type: "uuid",
        deletedAt: "2026-07-01T00:00:00.000Z",
        invite: {
          uuid: `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`,
          username: `trash-user-${index}`,
        },
        records: [],
      });
  const values = new Map([
    [`session:${sessionHash}`, JSON.stringify(await boundAdminSession("csrf", Date.now() + 60_000))],
    ["invites", "[]"],
    ["trash", JSON.stringify(trashItems)],
  ]);
  const env = adminEnv({
    async get(key) { return values.get(key) ?? null; },
    async put(key, value) { values.set(key, value); },
    async delete(key) { values.delete(key); },
  });
  const headers = { cookie: `sub2api_allow_admin=${sessionToken}` };

  const create = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin?view=create",
    { headers },
  ), env);
  const createBody = await create.text();
  assert.equal(create.status, 200);
  assert.match(createBody, /<h2>Create UUID<\/h2>/);
  assert.match(createBody, /name="key_group"/);
  assert.match(createBody, /openai-default/);
  assert.doesNotMatch(createBody, /<h2>Access key migration<\/h2>|<h2>UUIDs<\/h2>|<h2>Recycle Bin<\/h2>/);

  const maintenance = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin?view=maintenance&trashPage=3",
    { headers },
  ), env);
  const maintenanceBody = await maintenance.text();
  assert.equal(maintenance.status, 200);
  assert.match(maintenanceBody, /<h2>Access key migration<\/h2>/);
  assert.match(maintenanceBody, /<h2>Recycle Bin<\/h2>/);
  assert.doesNotMatch(maintenanceBody, /<h2>Create UUID<\/h2>|<h2>UUIDs<\/h2>/);
  const maintenanceForms = [...maintenanceBody.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/g)]
    .map((match) => match[0])
    .filter((form) => /name="action" value="(?:restore|purge)_(?:uuid|ip_group)"/.test(form));
  assert.equal(maintenanceForms.length, 4);
  for (const form of maintenanceForms) {
    assert.match(form, /name="trashPage" value="3"/);
  }

  const legacy = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin?page=2&trashPage=3",
    { headers },
  ), env);
  assert.equal(legacy.status, 303);
  assert.equal(legacy.headers.get("location"), "/allow-ip/admin?view=maintenance&trashPage=3");

  const unknownView = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin?view=unknown",
    { headers },
  ), env);
  assert.equal(unknownView.status, 303);
  assert.equal(unknownView.headers.get("location"), "/allow-ip/admin");

  const invalidDetail = await handleAdmin(new Request(
    "https://api.example.test/allow-ip/admin?detail=not-a-uuid",
    { headers },
  ), env);
  assert.equal(invalidDetail.status, 404);
});

test("admin HTML budget fails closed instead of sending an oversized document", async () => {
  const response = __test.html(() => "&".repeat(300_000), 200, 256 * 1024);
  const body = await response.text();

  assert.equal(response.status, 500);
  assert.match(body, /Admin page is too large to display safely/);
  assert.ok(new TextEncoder().encode(body).byteLength <= 256 * 1024);
});

test("admin record byte budget is UTF-8 aware and pagination preserves the other list", () => {
  assert.equal(__test.exceedsUtf8ByteLimit("a".repeat(256 * 1024), __test.ADMIN_RECORD_PAYLOAD_MAX_BYTES), false);
  assert.equal(__test.exceedsUtf8ByteLimit("a".repeat(256 * 1024 + 1), __test.ADMIN_RECORD_PAYLOAD_MAX_BYTES), true);
  assert.equal(__test.exceedsUtf8ByteLimit("é".repeat(4), 7), true);
  assert.equal(__test.parseAdminPageNumber("2", 400), 2);
  assert.equal(__test.parseAdminPageNumber("0", 400), 1);
  assert.equal(__test.parseAdminPageNumber("401", 400), 1);

  const contextForm = new FormData();
  contextForm.set("admin_context", "p=2&t=3&i=4&v=e");
  assert.deepEqual(__test.parseAdminInvitePostContext(contextForm), {
    page: 2,
    trashPage: 3,
    ipPage: 4,
    edit: true,
  });
  for (const invalidContext of [
    "p=2&t=3&i=4&v=e&p=5",
    "p=2&t=3&i=4&v=e&next=https%3A%2F%2Fevil.test",
    "p=2&t=3&i=4&v=e%",
    "p=2&t=3&i=4",
  ]) {
    contextForm.set("admin_context", invalidContext);
    assert.deepEqual(__test.parseAdminInvitePostContext(contextForm), {
      page: 1,
      trashPage: 1,
      ipPage: 1,
      edit: false,
    });
  }

  const inviteNav = __test.renderAdminPagination("invites", 2, 100, 2, 3);
  assert.match(inviteNav, /href="\/allow-ip\/admin"[^>]*>Previous/);
  assert.match(inviteNav, /href="\/allow-ip\/admin\?page=3"[^>]*>Next/);
  const trashNav = __test.renderAdminPagination("trash", 3, 100, 2, 3);
  assert.match(trashNav, /href="\/allow-ip\/admin\?view=maintenance&amp;trashPage=2"[^>]*>Previous/);
  assert.match(trashNav, /href="\/allow-ip\/admin\?view=maintenance&amp;trashPage=4"[^>]*>Next/);
});

function adminEnv(store) {
  return {
    INVITE_STORE: store,
    AUTH_RATE_LIMITER: { getByName() { return {}; } },
    ADMIN_USERNAME: "admin",
    ADMIN_PASSWORD_PBKDF2: "pbkdf2_sha256$310000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ADMIN_TOTP_SECRET: "JBSWY3DPEHPK3PXP",
    CREDENTIAL_ENCRYPTION_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
    ALLOWED_HOSTNAMES: "api.example.test",
    ACCOUNT_ID: "account",
    IP_LIST_ID: "list",
    CLOUDFLARE_API_TOKEN: "token",
    SUB2API_SYNC_SECRET: "s".repeat(32),
    SUB2API_SYNC_URL: "https://api.example.test/_sub2api-sync/provision",
    SUB2API_DEFAULT_BASE_URL: "https://api.example.test/v1",
    SUB2API_LOGIN_URL: "https://api.example.test/login",
  };
}

async function sha256Hex(value) {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(hash)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function boundAdminSession(csrf, expiresAt) {
  return {
    csrf,
    expiresAt,
    totpBinding: await __test.adminSessionTotpBinding(
      "JBSWY3DPEHPK3PXP",
      "h".repeat(32),
    ),
  };
}
