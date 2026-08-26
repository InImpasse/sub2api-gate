import assert from "node:assert/strict";
import test from "node:test";

import worker from "../src/index.js";
import { __test as adminTest } from "../src/admin.js";
import {
  DEFAULT_KEY_GROUP_NAME,
  hasInviteStorageSchema,
  parseKeyGroupName,
  protectInviteCredentials,
  revealInviteCredentials,
} from "../src/credential-security.js";
import { consumeRateLimitAttempt } from "../src/auth-rate-limiter.js";
import { renderInviteSummary } from "../src/invite-summary.js";

const UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
const AES_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const HMAC_KEY = "h".repeat(32);
const API_KEY = `sk-${"a".repeat(64)}`;
const TEST_ADMIN_TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const TEST_ADMIN_SESSION_BINDING_KEY = "h".repeat(32);


test("parseKeyGroupName accepts real groups and rejects default", () => {
  assert.equal(parseKeyGroupName("openai-default"), "openai-default");
  assert.equal(parseKeyGroupName("grok"), "grok");
  assert.equal(DEFAULT_KEY_GROUP_NAME, "openai-default");
  assert.equal(parseKeyGroupName("", { required: false }), "");
  assert.throws(() => parseKeyGroupName(""), /Key group is required/);
  for (const invalid of ["default", "Default", "DEFAULT", "bad name", "../x", ""]) {
    if (!invalid) continue;
    assert.throws(() => parseKeyGroupName(invalid), /Invalid key group/);
  }
});

test("scheduled Sub2API key sync caps and rotates daily batches", () => {
  const items = Array.from({ length: 11 }, (_, index) => ({ uuid: String(index) }));
  const first = adminTest.scheduledSub2ApiSyncBatch(items, Date.UTC(2026, 7, 26));
  const second = adminTest.scheduledSub2ApiSyncBatch(items, Date.UTC(2026, 7, 27));
  assert.deepEqual([first.length, second.length].sort((left, right) => left - right), [1, 10]);
  assert.equal(first.some((item) => second.includes(item)), false);
});

test("scheduled Sub2API key sync pulls active keys and keeps them encrypted", async () => {
  const oldKey = `sk-${"a".repeat(64)}`;
  const newKey = `sk-${"b".repeat(64)}`;
  const externalKey = `sk-${"e".repeat(64)}`;
  let revision = 4;
  let stored = await protectInviteCredentials({
    uuid: UUID,
    username: "alice",
    name: "alice",
    accessKeyHmac: "c".repeat(64),
    credentialVersion: 2,
    accessCredentialVersion: 1,
    apiConfigs: [{
      id: "sub2api-sync",
      name: "Sub2API",
      baseUrl: "https://api.example.test/v1",
      apiKey: oldKey,
      groupName: "openai-default",
    }, {
      id: "external-provider",
      name: "External",
      baseUrl: "https://provider.example.test/v1",
      apiKey: externalKey,
    }],
    sub2apiSync: { userId: 9, apiKeyId: 21, tokenId: 21, username: "alice" },
  }, AES_KEY, HMAC_KEY);
  const stub = {
    async status() { return { migrated: true }; },
    async getInvites() { return { revision, items: [stored] }; },
    async getInvite(uuid) {
      assert.equal(uuid, UUID);
      return stored;
    },
    async upsertInvite(expectedRevision, invite) {
      assert.equal(expectedRevision, revision);
      assert.doesNotMatch(JSON.stringify(invite), new RegExp(`${oldKey}|${newKey}|${externalKey}`));
      stored = invite;
      revision += 1;
      return { ok: true, conflict: false, revision };
    },
  };
  const env = {
    AUTH_STATE: { getByName() { return stub; } },
    CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
    ALLOWED_HOSTNAMES: "api.example.test",
    PROVIDER_ALLOWED_HOSTNAMES: "provider.example.test",
    SUB2API_SYNC_SECRET: "s".repeat(32),
    SUB2API_SYNC_URL: "https://api.example.test/_sub2api-sync/provision",
    SUB2API_DEFAULT_BASE_URL: "https://api.example.test/v1",
  };
  const originalFetch = globalThis.fetch;
  let exists = true;
  globalThis.fetch = async (_url, init) => {
    const request = JSON.parse(init.body);
    assert.equal(request.action, "status");
    assert.equal(request.uuid, UUID);
    if (!exists) {
      return Response.json({
        ok: true,
        action: "status",
        uuid: UUID,
        exists: false,
        tokens: [],
        syncedAt: new Date().toISOString(),
      });
    }
    return Response.json({
      ok: true,
      action: "status",
      uuid: UUID,
      exists: true,
      username: "alice",
      email: "alice@example.test",
      userId: 9,
      tokenId: 21,
      passwordHashFingerprint: "d".repeat(64),
      tokens: [{
        tokenId: 21,
        apiKeyId: 21,
        name: "Sub2API",
        tokenKey: newKey,
        apiKey: newKey,
        status: 1,
        groupName: "openai-default",
      }],
      baseUrl: "https://api.example.test/v1",
      loginUrl: "https://api.example.test/login",
      syncedAt: new Date().toISOString(),
    });
  };
  try {
    const result = await adminTest.syncAvailableSub2ApiKeys(env, Date.UTC(2026, 7, 26));
    assert.deepEqual(result, {
      total: 1,
      checked: 1,
      refreshed: 1,
      missing: 0,
      failed: 0,
      conflict: false,
    });
    const revealed = await revealInviteCredentials(stored, AES_KEY);
    assert.equal(revealed.apiConfigs.some((config) => config.apiKey === newKey), true);
    assert.equal(revealed.apiConfigs.some((config) => config.apiKey === oldKey), false);
    assert.equal(revealed.apiConfigs.some((config) => config.apiKey === externalKey), true);
    assert.doesNotMatch(JSON.stringify(stored), new RegExp(`${oldKey}|${newKey}|${externalKey}`));

    exists = false;
    assert.deepEqual(
      await adminTest.syncAvailableSub2ApiKeys(env, Date.UTC(2026, 7, 27)),
      { total: 1, checked: 1, refreshed: 0, missing: 1, failed: 0, conflict: false },
    );
    const afterRemoval = await revealInviteCredentials(stored, AES_KEY);
    assert.equal(afterRemoval.apiConfigs.some((config) => config.apiKey === newKey), false);
    assert.equal(afterRemoval.apiConfigs.some((config) => config.apiKey === externalKey), true);
    assert.doesNotMatch(JSON.stringify(stored), new RegExp(`${oldKey}|${newKey}|${externalKey}`));
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("invite storage schema accepts groupName and rejects default", async () => {
  const valid = {
    uuid: UUID,
    apiConfigs: [{ id: "primary", groupName: "openai-default" }],
  };
  assert.equal(hasInviteStorageSchema(valid), true);
  assert.equal(hasInviteStorageSchema({
    ...valid,
    apiConfigs: [{ id: "primary", groupName: "grok" }],
  }), true);
  assert.equal(hasInviteStorageSchema({
    ...valid,
    apiConfigs: [{ id: "primary", groupName: "default" }],
  }), false);
});

test("group catalog sanitizer drops default, duplicates, and unknown shapes", () => {
  const catalog = adminTest.sanitizeKeyGroupCatalog([
    { id: 1, name: "openai-default", platform: "openai" },
    { id: 2, name: "default", platform: "openai" },
    { id: 2, name: "openai-default", platform: "openai" },
    { id: 3, name: "grok", platform: "openai" },
    { id: 4, name: "bad name" },
    null,
    "openai-default",
  ]);
  assert.deepEqual(catalog.map((group) => group.name), ["openai-default", "grok"]);
});

test("key-test helpers never echo upstream bodies", () => {
  const notice = adminTest.keyTestNotice({
    tested: true,
    httpStatus: 200,
    modelCount: 2,
    modelId: "gpt-5.6-sol",
    body: "PRIVATE_CONVERSATION_SENTINEL",
    content: "should-not-render",
  });
  assert.match(notice, /API key works/);
  assert.doesNotMatch(notice, /PRIVATE_CONVERSATION_SENTINEL|should-not-render/);
  assert.match(adminTest.keyTestNotice({ tested: false, errorCode: "timeout", httpStatus: 504 }), /failed/);
});

test("invite summary test forms stay CSRF-bound and never serialize API keys", () => {
  const secret = "sk-PRIVATE_KEY_SENTINEL_8bd021";
  const html = renderInviteSummary(
    { uuid: UUID, ipPage: 2 },
    [{ id: "sub2api-sync", name: "Sub2API", baseUrl: "https://api.example.test/v1", apiKey: secret, groupName: "grok" }],
    "/allow-ip/admin",
    { page: 2, trashPage: 3 },
    "csrf-token",
  );
  assert.doesNotMatch(html, new RegExp(secret));
  assert.match(html, /name="action" value="test_api_key"/);
  assert.match(html, /name="csrf" value="csrf-token"/);
  assert.match(html, /Key group: grok/);
  assert.match(html, /name="admin_context" value="p=2&amp;t=3&amp;i=2&amp;v=d"/);
});

test("provision payload selects a real group and never sends default", async () => {
  const env = validAdminEnv(memoryKv(new Map([["invites", "[]"], ["trash", "[]"]])));
  let payload;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    payload = JSON.parse(init.body);
    return Response.json({
      ok: true,
      action: "provision",
      uuid: UUID,
      username: "alice",
      userId: 9,
      apiKeyId: 21,
      tokenId: 21,
      apiKey: API_KEY,
      tokenKey: API_KEY,
      loginPassword: "generated-password",
      passwordHashFingerprint: "f".repeat(64),
      tokens: [{
        tokenId: 21,
        apiKeyId: 21,
        name: "Sub2API",
        tokenKey: API_KEY,
        apiKey: API_KEY,
        status: 1,
        groupName: "grok",
      }],
      allowedGroups: ["grok"],
      baseUrl: "https://api.example.test/v1",
      loginUrl: "https://api.example.test/login",
      syncedAt: new Date().toISOString(),
    });
  };
  try {
    const issued = await adminTest.createInvite(env, UUID, {
      username: "alice",
      email: "alice@example.test",
      remark: "",
      apiConfigs: [{
        name: "Sub2API",
        baseUrl: "https://api.example.test/v1",
        apiKey: API_KEY,
      }],
      keyGroup: "grok",
    });
    assert.equal(payload.action, "provision");
    assert.deepEqual(payload.allowedGroups, ["grok"]);
    assert.equal(payload.tokens[0].groupName, "grok");
    assert.notEqual(payload.allowedGroups[0].toLowerCase(), "default");
    assert.equal(issued.invite.apiConfigs[0].groupName, "grok");
  } finally {
    globalThis.fetch = originalFetch;
  }

  await assert.rejects(
    adminTest.createInvite(env, "8c484f74-6d93-43d1-9441-00c7d8d4ab13", {
      username: "bob",
      apiConfigs: [],
      keyGroup: "default",
    }),
    /Invalid key group/,
  );
});

test("sync list_groups and test_api_key results reject content leaks", async () => {
  const env = validAdminEnv(memoryKv(new Map()));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({
    ok: true,
    action: "test_api_key",
    uuid: UUID,
    tested: true,
    httpStatus: 200,
    modelCount: 1,
    modelId: "gpt-5.6-sol",
    body: "PRIVATE_CONVERSATION_SENTINEL",
  });
  try {
    await assert.rejects(
      adminTest.callSub2ApiSync(env, "test_api_key", { uuid: UUID, apiKeyId: 21 }),
      /Sub2API sync request failed/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }

  globalThis.fetch = async () => Response.json({
    ok: true,
    action: "list_groups",
    groups: [{ id: 1, name: "openai-default", platform: "openai" }],
    apiKey: API_KEY,
  });
  try {
    await assert.rejects(
      adminTest.callSub2ApiSync(env, "list_groups", {}),
      /Sub2API sync request failed/,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("admin and public key tests are CSRF-bound, rate-limited, and metadata-only", async () => {
  const sessionToken = "key-test-admin-session";
  const publicToken = "key-test-public-session";
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    username: "alice",
    name: "alice",
    credentialVersion: 2,
    accessCredentialVersion: 1,
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [{
      id: "sub2api-sync",
      name: "Sub2API",
      baseUrl: "https://api.example.test/v1",
      apiKey: API_KEY,
      groupName: "openai-default",
    }],
    sub2apiSync: {
      userId: 9,
      apiKeyId: 21,
      tokenId: 21,
      username: "alice",
      loginUrl: "https://api.example.test/login",
    },
  }, AES_KEY, HMAC_KEY);
  const values = new Map([
    [`session:${await sha256Hex(sessionToken)}`, JSON.stringify(
      await boundAdminSession("admin-csrf", Date.now() + 60_000),
    )],
    [`uuid-session:${await sha256Hex(publicToken)}`, JSON.stringify({
      uuid: UUID,
      csrf: "public-csrf",
      authenticationMethod: "access_key",
      accessCredentialVersion: 1,
      expiresAt: Date.now() + 60_000,
    })],
    ["invites", JSON.stringify([storedInvite])],
    ["trash", "[]"],
    [`records:${UUID}`, "[]"],
  ]);
  const env = {
    ...validAdminEnv(memoryKv(values)),
    TURNSTILE_SITE_KEY: "test-site-key",
    TURNSTILE_SECRET_KEY: "test-turnstile-secret",
  };
  const originalFetch = globalThis.fetch;
  const seenActions = [];
  globalThis.fetch = async (_url, init) => {
    if (String(_url).includes("challenges.cloudflare.com")) {
      throw new Error("key test must not call Turnstile");
    }
    const body = JSON.parse(init.body);
    seenActions.push(body.action);
    assert.equal(body.action, "test_api_key");
    assert.equal(body.uuid, UUID);
    assert.equal(body.apiKeyId, 21);
    return Response.json({
      ok: true,
      action: "test_api_key",
      uuid: UUID,
      apiKeyId: 21,
      tokenId: 21,
      tested: true,
      httpStatus: 200,
      modelCount: 2,
      modelId: "gpt-5.6-sol",
      errorCode: "",
      latencyMs: 18,
      syncedAt: new Date().toISOString(),
    });
  };

  try {
    const csrfRejected = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_admin=${sessionToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        action: "test_api_key",
        csrf: "wrong",
        uuid: UUID,
        config_id: "sub2api-sync",
      }),
    }), env);
    assert.equal(csrfRejected.status, 403);
    assert.equal(seenActions.length, 0);

    const adminOk = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_admin=${sessionToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        action: "test_api_key",
        csrf: "admin-csrf",
        uuid: UUID,
        config_id: "sub2api-sync",
        admin_context: "p=1&t=1&i=1&v=d",
      }),
    }), env);
    const adminHtml = await adminOk.text();
    assert.equal(adminOk.status, 200);
    assert.match(adminHtml, /API key works/);
    assert.doesNotMatch(adminHtml, /PRIVATE_CONVERSATION|"choices"|completion_tokens/);
    assert.doesNotMatch(adminHtml, new RegExp(API_KEY));

    const publicOk = await worker.fetch(new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_uuid=${publicToken}`,
        "content-type": "application/x-www-form-urlencoded",
        "CF-Connecting-IP": "203.0.113.42",
      },
      body: new URLSearchParams({
        action: "test_api_key",
        csrf: "public-csrf",
        config_id: "sub2api-sync",
      }),
    }), env);
    const publicHtml = await publicOk.text();
    assert.equal(publicOk.status, 200);
    assert.match(publicHtml, /API key works/);
    assert.match(publicHtml, /role="status"/);
    assert.match(publicHtml, /Test API key/);
    assert.doesNotMatch(publicHtml, /PRIVATE_CONVERSATION|"choices"|completion_tokens/);
    assert.equal(seenActions.length, 2);

    const limitedEnv = {
      ...env,
      AUTH_RATE_LIMITER: observingRateLimiter(false),
    };
    const limited = await worker.fetch(new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_uuid=${publicToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        action: "test_api_key",
        csrf: "public-csrf",
        config_id: "sub2api-sync",
      }),
    }), limitedEnv);
    assert.equal(limited.status, 429);
    assert.equal(seenActions.length, 2);

    const unauthenticated = await worker.fetch(new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        action: "test_api_key",
        csrf: "public-csrf",
        config_id: "sub2api-sync",
      }),
    }), env);
    const unauthenticatedHtml = await unauthenticated.text();
    assert.equal(unauthenticated.status, 403);
    assert.match(unauthenticatedHtml, /Sign in required/);
    assert.equal(seenActions.length, 2);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("key-test timeouts map to an accessible failure without leaking bodies", async () => {
  const publicToken = "key-test-timeout-session";
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    username: "alice",
    credentialVersion: 2,
    accessCredentialVersion: 1,
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [{
      id: "sub2api-sync",
      name: "Sub2API",
      baseUrl: "https://api.example.test/v1",
      apiKey: API_KEY,
    }],
    sub2apiSync: { userId: 9, apiKeyId: 21, tokenId: 21, username: "alice" },
  }, AES_KEY, HMAC_KEY);
  const values = new Map([
    [`uuid-session:${await sha256Hex(publicToken)}`, JSON.stringify({
      uuid: UUID,
      csrf: "public-csrf",
      authenticationMethod: "access_key",
      accessCredentialVersion: 1,
      expiresAt: Date.now() + 60_000,
    })],
    ["invites", JSON.stringify([storedInvite])],
    [`records:${UUID}`, "[]"],
  ]);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify({
    ok: false,
    action: "test_api_key",
    error: "timeout",
    retryable: true,
    requestId: "req-timeout-1",
  }), {
    status: 504,
    headers: {
      "content-type": "application/json",
      "x-request-id": "req-timeout-1",
    },
  });
  try {
    const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_uuid=${publicToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        action: "test_api_key",
        csrf: "public-csrf",
        config_id: "sub2api-sync",
      }),
    }), {
      ...validAdminEnv(memoryKv(values)),
      TURNSTILE_SITE_KEY: "test-site-key",
      TURNSTILE_SECRET_KEY: "test-turnstile-secret",
    });
    const html = await response.text();
    assert.equal(response.status, 502);
    assert.match(html, /role="alert"/);
    assert.match(html, /API key test failed/);
    assert.doesNotMatch(html, /PRIVATE_CONVERSATION|"choices"|completion_tokens/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("keytest rate-limit scope allows eight attempts", async () => {
  const storage = {
    values: new Map(),
    tail: Promise.resolve(),
    alarm: null,
    transaction(callback) {
      const result = this.tail.then(() => callback(this));
      this.tail = result.catch(() => {});
      return result;
    },
    async get(key) { return this.values.get(key); },
    async put(key, value) { this.values.set(key, structuredClone(value)); },
    async setAlarm(timestamp) { this.alarm = Number(timestamp); },
  };
  const now = 3_000_000;
  const results = await Promise.all(
    Array.from({ length: 10 }, () => consumeRateLimitAttempt(storage, "keytest", now)),
  );
  assert.equal(results.filter((result) => result.allowed).length, 8);
  assert.equal(results.filter((result) => !result.allowed).length, 2);
});


function validAdminEnv(store) {
  return {
    INVITE_STORE: store,
    AUTH_RATE_LIMITER: observingRateLimiter(true),
    ADMIN_USERNAME: "admin",
    ADMIN_PASSWORD_PBKDF2: "pbkdf2_sha256$310000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ADMIN_TOTP_SECRET: TEST_ADMIN_TOTP_SECRET,
    CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
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

function observingRateLimiter(allowed) {
  return {
    getByName() {
      return {
        async consume() {
          return {
            allowed,
            retryAfterSeconds: allowed ? 0 : 60,
            resetAt: Date.now() + 60_000,
          };
        },
        async reset() {
          return { ok: true };
        },
      };
    },
  };
}

function memoryKv(values) {
  return {
    async get(key) { return values.get(key) ?? null; },
    async put(key, value) { values.set(key, value); },
    async delete(key) { values.delete(key); },
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
    totpBinding: await adminTest.adminSessionTotpBinding(
      TEST_ADMIN_TOTP_SECRET,
      TEST_ADMIN_SESSION_BINDING_KEY,
    ),
  };
}
