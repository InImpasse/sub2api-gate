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

  const dashboard = await __test.getAdminDashboard(
    env,
    new URL("https://api.example.test/allow-ip/admin?page=2&trashPage=3"),
  );
  assert.deepEqual(calls, [[25, 25, 50, 25]]);
  assert.equal(dashboard.inviteCount, 100);
  assert.equal(dashboard.trashCount, 75);
  assert.equal(dashboard.unmigratedInviteCount, 9);
  assert.equal(dashboard.invites.length, 25);
  assert.equal(dashboard.selectedInvite, null);
  assert.equal(recordReads, 0);
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

test("admin list HTTP response stays within 256 KiB and renders summaries only", async () => {
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
    [`session:${sessionHash}`, JSON.stringify({ csrf: "csrf", expiresAt: Date.now() + 60_000 })],
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
  assert.ok(new TextEncoder().encode(body).byteLength <= 256 * 1024);
});

test("admin detail HTTP response stays within 512 KiB and paginates 20 IP groups", async () => {
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
  const stub = {
    async status() { return { migrated: true }; },
    async getAdminSession(hash) {
      assert.equal(hash, sessionHash);
      return { csrf: "csrf", expiresAt: Date.now() + 60_000 };
    },
    async getAdminPage(inviteOffset, inviteLimit, trashOffset, trashLimit) {
      assert.deepEqual([inviteOffset, inviteLimit, trashOffset, trashLimit], [25, 25, 50, 25]);
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
  assert.ok(new TextEncoder().encode(body).byteLength <= 512 * 1024);
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

  const inviteNav = __test.renderAdminPagination("invites", 2, 100, 2, 3);
  assert.match(inviteNav, /href="\/allow-ip\/admin\?trashPage=3"[^>]*>Previous/);
  assert.match(inviteNav, /href="\/allow-ip\/admin\?page=3&amp;trashPage=3"[^>]*>Next/);
  const trashNav = __test.renderAdminPagination("trash", 3, 100, 2, 3);
  assert.match(trashNav, /href="\/allow-ip\/admin\?page=2&amp;trashPage=2"[^>]*>Previous/);
  assert.match(trashNav, /href="\/allow-ip\/admin\?page=2&amp;trashPage=4"[^>]*>Next/);
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
