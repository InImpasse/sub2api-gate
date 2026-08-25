import assert from "node:assert/strict";
import test from "node:test";

import { handleAdmin, __test as adminTest } from "../src/admin.js";
import { createAuthStateStore, __test as authStateTest } from "../src/auth-state.js";

const UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";

test("records KV operations do not make AuthState readiness RPCs", async () => {
  let statusCalls = 0;
  const values = new Map();
  const env = {
    AUTH_STATE: {
      getByName() {
        return {
          async status() {
            statusCalls += 1;
            throw new Error("status must not be called for records KV");
          },
        };
      },
    },
    INVITE_STORE: {
      async get(key) { return values.get(key) ?? null; },
      async put(key, value) { values.set(key, value); },
      async delete(key) { values.delete(key); },
    },
  };
  const store = createAuthStateStore(env);
  const records = [{ id: "network-1", ips: [{ cidr: "198.51.100.0/24" }] }];

  await store.putRecords(UUID, records);
  assert.deepEqual(JSON.parse(await store.getRecords(UUID)), records);
  await store.deleteRecords(UUID);
  assert.equal(await store.getRecords(UUID), null);
  assert.equal(statusCalls, 0);

  await assert.rejects(store.getRecords("not-a-uuid"), /auth_state_uuid_invalid/);
  await assert.rejects(
    store.putRecords(UUID, "x".repeat(4 * 1024 * 1024 + 1)),
    /auth_state_payload_too_large/,
  );
});

test("AuthState byte limits count UTF-8 bytes instead of JavaScript code units", async () => {
  assert.equal(authStateTest.utf8ByteLength("ASCII"), 5);
  assert.equal(authStateTest.utf8ByteLength("界"), 3);
  assert.equal(authStateTest.utf8ByteLength("😀"), 4);

  const oversizedItem = {
    uuid: UUID,
    username: "界".repeat(Math.floor((512 * 1024) / 3) + 1),
    credentialVersion: 2,
    accessCredentialVersion: 1,
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [],
    sub2apiSync: {},
  };
  assert.throws(
    () => authStateTest.normalizeInvite(oversizedItem),
    /auth_state_invite_invalid/,
  );

  const oversizedStoredJson = JSON.stringify({
    value: "界".repeat(Math.floor((512 * 1024) / 3) + 1),
  });
  assert.ok(oversizedStoredJson.length < 512 * 1024);
  assert.ok(authStateTest.utf8ByteLength(oversizedStoredJson) > 512 * 1024);
  assert.throws(
    () => authStateTest.parseStoredJson(oversizedStoredJson, "auth_state_test_corrupt"),
    /auth_state_test_corrupt/,
  );
});

test("AuthState admin sessions allow only bounded authentication state", () => {
  const now = Date.now();
  const expiresAt = now + 60_000;
  const totpBinding = "a".repeat(64);
  assert.deepEqual(
    authStateTest.normalizeAdminSession({
      csrf: "legacy-unbound-csrf",
      expiresAt,
      extra: "drop-me",
    }, now),
    { csrf: "legacy-unbound-csrf", expiresAt },
  );
  assert.throws(
    () => authStateTest.normalizeAdminSession({ csrf: "", expiresAt }, now),
    /auth_state_admin_session_invalid/,
  );
  assert.throws(
    () => authStateTest.normalizeAdminSession({
      csrf: "invalid-binding-csrf",
      expiresAt,
      totpBinding: "a".repeat(63),
    }, now),
    /auth_state_admin_session_invalid/,
  );
  assert.deepEqual(
    authStateTest.normalizeAdminSession({
      csrf: "pending-csrf",
      expiresAt,
      totpBinding,
      loginPhase: "totp",
      extra: "drop-me",
    }, now),
    { csrf: "pending-csrf", expiresAt, totpBinding, loginPhase: "totp" },
  );
  assert.deepEqual(
    authStateTest.normalizeAdminSession({
      csrf: "full-csrf",
      expiresAt,
      totpBinding,
      totpVerifiedAt: now - 1_000,
      extra: "drop-me",
    }, now),
    { csrf: "full-csrf", expiresAt, totpBinding },
  );
  assert.throws(
    () => authStateTest.normalizeAdminSession({
      csrf: "bad-phase",
      expiresAt,
      totpBinding,
      loginPhase: "authenticated",
    }, now),
    /auth_state_admin_session_invalid/,
  );
  assert.throws(
    () => authStateTest.normalizeAdminSession({
      csrf: "missing-binding",
      expiresAt,
      loginPhase: "totp",
    }, now),
    /auth_state_admin_session_invalid/,
  );
  assert.deepEqual(
    authStateTest.normalizeAdminSession({
      csrf: "pending-with-legacy-verification-time",
      expiresAt,
      totpBinding,
      loginPhase: "totp",
      totpVerifiedAt: expiresAt,
    }, now),
    {
      csrf: "pending-with-legacy-verification-time",
      expiresAt,
      totpBinding,
      loginPhase: "totp",
    },
  );
});

test("legacy KV cleanup fails closed, retries, and never deletes records keys", async () => {
  const values = new Map([
    ["invites", "private-invite-source"],
    ["trash", "private-trash-source"],
    [`session:${"a".repeat(64)}`, "private-admin-session"],
    [`uuid-session:${"b".repeat(64)}`, "private-public-session"],
    [`records:${UUID}`, "required-records"],
  ]);
  let cleanupComplete = false;
  let cleanupCalls = 0;
  let failDelete = true;
  const stub = {
    async status() {
      return {
        migrated: true,
        legacyCleanupComplete: cleanupComplete,
        legacyCleanupSchedulerReady: false,
      };
    },
    async runLegacyCleanup(reason) {
      assert.equal(reason, "explicit");
      cleanupCalls += 1;
      try {
        await authStateTest.cleanupLegacySourceKeys(env.INVITE_STORE);
      } catch {
        throw new Error("auth_state_legacy_cleanup_failed");
      }
      cleanupComplete = true;
      return { ok: true, cleaned: true };
    },
  };
  const env = {
    AUTH_STATE: { getByName() { return stub; } },
    INVITE_STORE: {
      async get(key) { return values.get(key) ?? null; },
      async list({ prefix }) {
        return {
          keys: [...values.keys()].filter((key) => key.startsWith(prefix)).map((name) => ({ name })),
          list_complete: true,
        };
      },
      async delete(key) {
        if (key === "trash" && failDelete) {
          failDelete = false;
          throw new Error("temporary delete failure");
        }
        values.delete(key);
      },
    },
  };
  const store = createAuthStateStore(env);
  const ready = await store.ready();
  assert.equal(ready.legacyCleanupComplete, false);
  assert.equal(values.has("invites"), true);
  assert.equal(values.has("trash"), true);
  await assert.rejects(store.purgeLegacySourceKeys(), /auth_state_legacy_cleanup_failed/);
  assert.equal(cleanupComplete, false);

  const result = await store.purgeLegacySourceKeys();
  assert.equal(result.cleaned, true);
  assert.equal(cleanupCalls, 2);
  assert.equal(values.has("invites"), false);
  assert.equal(values.has("trash"), false);
  assert.equal([...values.keys()].some((key) => key.startsWith("session:")), false);
  assert.equal([...values.keys()].some((key) => key.startsWith("uuid-session:")), false);
  assert.equal(values.get(`records:${UUID}`), "required-records");
});

test("unbound AuthState admin sessions are rejected and deleted", async () => {
  const sessionToken = "unbound-auth-state-session";
  const sessionHash = await sha256Hex(sessionToken);
  const authStateDeletes = [];
  const kvDeletes = [];
  const env = adminEnv({
    getByName() {
      return {
        async status() {
          return { migrated: true, legacyCleanupComplete: true };
        },
        async getAdminSession(hash) {
          assert.equal(hash, sessionHash);
          return { csrf: "unbound-auth-state-csrf", expiresAt: Date.now() + 60_000 };
        },
        async deleteSession(kind, hash) {
          authStateDeletes.push([kind, hash]);
          return { deleted: true };
        },
      };
    },
  });
  env.INVITE_STORE.delete = async (key) => kvDeletes.push(key);

  const response = await handleAdmin(new Request("https://api.example.test/allow-ip/admin", {
    headers: { cookie: `sub2api_allow_admin=${sessionToken}` },
  }), env);

  assert.equal(response.status, 200);
  assert.match(await response.text(), /Admin sign in/);
  assert.deepEqual(authStateDeletes, [["admin", sessionHash]]);
  assert.deepEqual(kvDeletes, [`session:${sessionHash}`]);
});

test("TOTP-bound AuthState sessions are rejected and deleted when the canonical seed changes", async () => {
  const sessionToken = "mismatched-auth-state-session";
  const sessionHash = await sha256Hex(sessionToken);
  const authStateDeletes = [];
  const kvDeletes = [];
  const priorBinding = await adminTest.adminSessionTotpBinding(
    "JBSWY3DPEHPK3PXP",
    "h".repeat(32),
  );
  const env = adminEnv({
    getByName() {
      return {
        async status() {
          return { migrated: true, legacyCleanupComplete: true };
        },
        async getAdminSession(hash) {
          assert.equal(hash, sessionHash);
          return {
            csrf: "mismatched-auth-state-csrf",
            expiresAt: Date.now() + 60_000,
            totpBinding: priorBinding,
          };
        },
        async deleteSession(kind, hash) {
          authStateDeletes.push([kind, hash]);
          return { deleted: true };
        },
      };
    },
  });
  env.ADMIN_TOTP_SECRET = "KRUGS4ZANFZSAYJA";
  env.INVITE_STORE.delete = async (key) => kvDeletes.push(key);

  const response = await handleAdmin(new Request("https://api.example.test/allow-ip/admin", {
    headers: { cookie: `sub2api_allow_admin=${sessionToken}` },
  }), env);

  assert.equal(response.status, 200);
  assert.match(await response.text(), /Admin sign in/);
  assert.deepEqual(authStateDeletes, [["admin", sessionHash]]);
  assert.deepEqual(kvDeletes, [`session:${sessionHash}`]);
});

test("unbound legacy KV fallback is rejected and deleted from both configured stores", async () => {
  const sessionToken = "unbound-legacy-fallback-session";
  const sessionHash = await sha256Hex(sessionToken);
  const legacyKey = `session:${sessionHash}`;
  const values = new Map([[
    legacyKey,
    JSON.stringify({ csrf: "unbound-legacy-csrf", expiresAt: Date.now() + 60_000 }),
  ]]);
  let persistedSession = null;
  const authStateDeletes = [];
  const kvDeletes = [];
  const env = adminEnv({
    getByName() {
      return {
        async status() {
          return { migrated: true, legacyCleanupComplete: false };
        },
        async getAdminSession(hash) {
          assert.equal(hash, sessionHash);
          return persistedSession;
        },
        async putAdminSession(hash, payload) {
          assert.equal(hash, sessionHash);
          persistedSession = payload;
          return { ok: true };
        },
        async deleteSession(kind, hash) {
          authStateDeletes.push([kind, hash]);
          persistedSession = null;
          return { deleted: true };
        },
      };
    },
  });
  env.INVITE_STORE = {
    async get(key) { return values.get(key) ?? null; },
    async put(key, value) { values.set(key, value); },
    async delete(key) {
      kvDeletes.push(key);
      values.delete(key);
    },
  };

  const response = await handleAdmin(new Request("https://api.example.test/allow-ip/admin", {
    headers: { cookie: `sub2api_allow_admin=${sessionToken}` },
  }), env);

  assert.equal(response.status, 200);
  assert.match(await response.text(), /Admin sign in/);
  assert.equal(persistedSession, null);
  assert.deepEqual(authStateDeletes, [["admin", sessionHash]]);
  assert.deepEqual(kvDeletes, [legacyKey]);
  assert.equal(values.has(legacyKey), false);
});

test("admin CAS conflicts return a safe HTTP 409 response", async () => {
  const sessionToken = "auth-state-conflict-session";
  const csrf = "auth-state-conflict-csrf";
  const totpBinding = await adminTest.adminSessionTotpBinding(
    "JBSWY3DPEHPK3PXP",
    "h".repeat(32),
  );
  let replaceCalls = 0;
  const stub = {
    async status() {
      return { migrated: true };
    },
    async getAdminSession() {
      return { csrf, expiresAt: Date.now() + 60_000, totpBinding };
    },
    async getInvites() {
      return {
        revision: 4,
        items: [{
          uuid: UUID,
          username: "alice",
          credentialVersion: 2,
          accessCredentialVersion: 1,
          accessKeyHmac: "a".repeat(64),
          apiConfigs: [],
          sub2apiSync: {},
        }],
      };
    },
    async replaceInvites() {
      replaceCalls += 1;
      return { ok: false, conflict: true, revision: 5 };
    },
  };
  const env = adminEnv({
    getByName() {
      return stub;
    },
  });
  const response = await handleAdmin(new Request("https://api.example.test/allow-ip/admin", {
    method: "POST",
    headers: {
      cookie: `sub2api_allow_admin=${sessionToken}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      action: "rotate_access_key",
      csrf,
      uuid: UUID,
    }),
  }), env);
  const body = await response.text();

  assert.equal(response.status, 409);
  assert.match(body, /Update conflict/);
  assert.match(body, /Refresh the page and try again/);
  assert.doesNotMatch(body, /auth_state_conflict|revision|stack/i);
  assert.equal(replaceCalls, 1);
});

function adminEnv(authStateBinding) {
  return {
    AUTH_STATE: authStateBinding,
    INVITE_STORE: {
      async get() { return null; },
      async put() {},
      async delete() {},
    },
    AUTH_RATE_LIMITER: {
      getByName() {
        return {
          async consume() {
            return { allowed: true, retryAfterSeconds: 0, resetAt: Date.now() + 60_000 };
          },
          async reset() {
            return { ok: true };
          },
        };
      },
    },
    ADMIN_USERNAME: "admin",
    ADMIN_PASSWORD_PBKDF2: "pbkdf2_sha256$310000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ADMIN_TOTP_SECRET: "JBSWY3DPEHPK3PXP",
    CREDENTIAL_ENCRYPTION_KEY: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
    ALLOWED_HOSTNAMES: "api.example.test",
    ACCOUNT_ID: "test-account",
    IP_LIST_ID: "test-list",
    CLOUDFLARE_API_TOKEN: "test-token",
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
