import assert from "node:assert/strict";
import test from "node:test";

import { __test as adminTest, resetInviteSub2ApiPassword } from "../src/admin.js";
import { protectInviteCredentials, revealInviteCredentials } from "../src/credential-security.js";

const UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
const ENCRYPTION_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const HMAC_KEY = "test-only-hmac-key-with-at-least-32-bytes";
const BASE_URL = "https://api.example.test/v1";

test("update CAS conflicts reapply the authoritative invite to Sub2API", async () => {
  const storedInvite = await protectedInvite();
  let replaceCalls = 0;
  const syncBodies = [];
  const env = makeEnv(authStub(storedInvite, {
    replaceInvites() {
      replaceCalls += 1;
      return replaceCalls === 1
        ? { ok: false, conflict: true, revision: 2 }
        : { ok: true, conflict: false, revision: 3 };
    },
  }));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(init.body);
    syncBodies.push(body);
    return syncResponse(body, syncBodies.length);
  };

  try {
    await assert.rejects(adminTest.updateInvite(env, UUID, {
      uuid: UUID,
      username: "losing-update",
      email: "losing-update@example.test",
      remark: "losing update",
      apiConfigs: [{ name: "Sub2API", baseUrl: BASE_URL, apiKey: testApiKey("b") }],
    }), /auth_state_conflict/);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(replaceCalls, 2);
  assert.deepEqual(syncBodies.map((body) => body.action), ["provision", "provision"]);
  assert.equal(syncBodies[0].username, "losing-update");
  assert.equal(syncBodies[1].username, "winner");
  assert.equal(syncBodies[1].loginPassword, "winner-password");
  assert.equal(syncBodies[1].resetLoginPassword, true);
});

test("password reset CAS conflicts restore and persist the authoritative password", async () => {
  const storedInvite = await protectedInvite();
  let replaceCalls = 0;
  let finalStoredInvite = null;
  const syncBodies = [];
  const env = makeEnv(authStub(storedInvite, {
    replaceInvites(_revision, items) {
      replaceCalls += 1;
      if (replaceCalls === 1) return { ok: false, conflict: true, revision: 2 };
      [finalStoredInvite] = items;
      return { ok: true, conflict: false, revision: 3 };
    },
  }));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(init.body);
    syncBodies.push(body);
    const password = syncBodies.length === 1 ? "losing-reset-password" : body.loginPassword;
    return syncResponse({ ...body, loginPassword: password }, syncBodies.length);
  };

  try {
    await assert.rejects(resetInviteSub2ApiPassword(env, UUID), /auth_state_conflict/);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(replaceCalls, 2);
  assert.equal(syncBodies[0].resetLoginPassword, true);
  assert.equal(syncBodies[1].loginPassword, "winner-password");
  assert.equal(syncBodies[1].resetLoginPassword, true);
  const revealed = await revealInviteCredentials(finalStoredInvite, ENCRYPTION_KEY);
  assert.equal(revealed.sub2apiSync.loginPassword, "winner-password");
  assert.equal(revealed.sub2apiSync.passwordHashFingerprint, "2".repeat(64));
  assert.doesNotMatch(JSON.stringify(finalStoredInvite), /winner-password|losing-reset-password/);
});

test("delete CAS conflicts restore authoritative Sub2API and Cloudflare state", async () => {
  const storedInvite = await protectedInvite();
  const records = [{
    id: "network-1",
    addedAt: "2026-07-21T00:00:00.000Z",
    updatedAt: "2026-07-21T00:00:00.000Z",
    expiresAt: "2027-07-21T00:00:00.000Z",
    ips: [{
      ip: "198.51.100.44",
      version: "IPv4",
      cidr: "198.51.100.0/24",
      listValue: "198.51.100.0/24",
      listItemId: "old-item-id",
    }],
  }];
  const values = new Map([[`records:${UUID}`, JSON.stringify(records)]]);
  const syncActions = [];
  const cloudflareMethods = [];
  let cloudflareItem = { id: "current-item-id", ip: "198.51.100.0/24", comment: "" };
  const env = makeEnv(authStub(storedInvite, {
    removeInvite() {
      return { ok: false, conflict: true, inviteRevision: 2, trashRevision: 1 };
    },
    replaceInvites() {
      return { ok: true, conflict: false, revision: 3 };
    },
  }), values);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || "GET";
    if (url.hostname === "api.cloudflare.com") {
      cloudflareMethods.push(method);
      if (url.pathname.includes("/bulk_operations/")) {
        return Response.json({ success: true, result: { status: "completed" } });
      }
      if (method === "GET") {
        return Response.json({
          success: true,
          result: cloudflareItem ? [cloudflareItem] : [],
        });
      }
      if (method === "POST") {
        const [created] = JSON.parse(init.body);
        cloudflareItem = { id: "restored-item-id", ip: created.ip, comment: created.comment };
      } else {
        cloudflareItem = null;
      }
      return method === "DELETE"
        ? Response.json({ success: true, result: { operation_id: "delete-operation" } })
        : Response.json({ success: true, result: [] });
    }
    const body = JSON.parse(init.body);
    syncActions.push(body.action);
    return syncResponse(body, syncActions.length);
  };

  try {
    await assert.rejects(adminTest.deleteInvite(env, UUID), /auth_state_conflict/);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.deepEqual(syncActions, ["deprovision", "provision"]);
  assert.deepEqual(cloudflareMethods, ["GET", "DELETE", "GET", "GET", "POST", "GET"]);
  assert.equal(cloudflareItem?.id, "restored-item-id");
  assert.equal(values.has(`records:${UUID}`), true);
});

test("rollback without a mutation marker never deletes a pre-existing list item", async () => {
  const values = new Map();
  const syncActions = [];
  let deletedItemId = "";
  const env = makeEnv(authStub(null), values);
  const provisional = {
    uuid: UUID,
    username: "provisional",
    sub2apiSync: { userId: 9, tokenId: 17 },
  };
  const groups = [{
    id: "network-rollback",
    ips: [{
      ip: "198.51.100.44",
      cidr: "198.51.100.0/24",
      listValue: "198.51.100.0/24",
      listItemId: "stale-item-id",
    }],
  }];
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method || "GET";
    if (url.hostname === "api.cloudflare.com") {
      if (method === "GET") {
        return Response.json({
          success: true,
          result: [{ id: "current-restored-id", ip: "198.51.100.0/24", comment: "" }],
        });
      }
      deletedItemId = JSON.parse(init.body).items[0].id;
      return Response.json({ success: true, result: [] });
    }
    const body = JSON.parse(init.body);
    syncActions.push(body.action);
    return syncResponse(body, 1);
  };

  try {
    await adminTest.rollbackRestoredExternalState(env, provisional, groups);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(deletedItemId, "");
  assert.deepEqual(syncActions, ["deprovision"]);
});

test("arbitrary create storage failures deprovision the provisional Sub2API user", async () => {
  const syncActions = [];
  const env = makeEnv(authStub(null, {
    replaceInvites() { throw new Error("storage unavailable"); },
  }));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(init.body);
    syncActions.push(body.action);
    return syncResponse(body, syncActions.length);
  };
  try {
    await assert.rejects(adminTest.createInvite(env, UUID, {
      username: "provisional",
      email: "provisional@example.test",
      remark: "",
      apiConfigs: [{ name: "Sub2API", baseUrl: BASE_URL, apiKey: testApiKey("d") }],
    }), /auth_state_request_failed/);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.deepEqual(syncActions, ["provision", "deprovision"]);
});

test("arbitrary update storage failures reapply the authoritative Sub2API state", async () => {
  const storedInvite = await protectedInvite();
  let replaceCalls = 0;
  const syncBodies = [];
  const env = makeEnv(authStub(storedInvite, {
    replaceInvites() {
      replaceCalls += 1;
      if (replaceCalls === 1) throw new Error("storage unavailable");
      return { ok: true, conflict: false, revision: 3 };
    },
  }));
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(init.body);
    syncBodies.push(body);
    return syncResponse(body, syncBodies.length);
  };
  try {
    await assert.rejects(adminTest.updateInvite(env, UUID, {
      uuid: UUID,
      username: "losing-update",
      email: "private-update@example.test",
      remark: "",
      apiConfigs: [{ name: "Sub2API", baseUrl: BASE_URL, apiKey: testApiKey("e") }],
    }), /auth_state_request_failed/);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.deepEqual(syncBodies.map((body) => body.action), ["provision", "provision"]);
  assert.equal(syncBodies[1].username, "winner");
});

test("compensation failures expose and log only a stable error code", async () => {
  const sentinel = "PRIVATE_CREDENTIAL_SENTINEL";
  const env = makeEnv(authStub(null, {
    replaceInvites() { throw new Error(`storage ${sentinel}`); },
  }));
  const originalFetch = globalThis.fetch;
  const originalError = console.error;
  const logs = [];
  console.error = (value) => logs.push(String(value));
  globalThis.fetch = async (_input, init) => {
    const body = JSON.parse(init.body);
    if (body.action === "deprovision") throw new Error(sentinel);
    return syncResponse(body, 1);
  };
  try {
    await assert.rejects(adminTest.createInvite(env, UUID, {
      username: "private-user",
      email: "private-email@example.test",
      remark: "",
      apiConfigs: [{ name: "Sub2API", baseUrl: BASE_URL, apiKey: testApiKey("f") }],
    }), (error) => error.message === "auth_state_compensation_failed");
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalError;
  }
  assert.deepEqual(logs, [JSON.stringify({ level: "error", message: "auth_state_compensation_failed" })]);
  assert.doesNotMatch(logs.join("\n"), new RegExp(`${sentinel}|${UUID}|private-user|private-email`));
});

function authStub(storedInvite, overrides = {}) {
  let revision = 1;
  const markers = new Map();
  return {
    async status() {
      return { migrated: true };
    },
    async getInvites() {
      const items = storedInvite ? [structuredClone(storedInvite)] : [];
      return { revision: revision += 1, items };
    },
    async getTrash() {
      return { revision: 0, items: [] };
    },
    async replaceInvites(expectedRevision, items) {
      return overrides.replaceInvites?.(expectedRevision, items)
        ?? { ok: true, conflict: false, revision: expectedRevision + 1 };
    },
    async removeInvite(...args) {
      return overrides.removeInvite?.(...args)
        ?? { ok: true, removed: true, inviteRevision: 2, trashRevision: 1 };
    },
    async registerCloudflareMutation(marker) {
      markers.set(marker.mutationId, structuredClone(marker));
      return { ok: true, created: true };
    },
    async updateCloudflareMutationItems(mutationId, itemIds) {
      const marker = markers.get(mutationId);
      if (marker) markers.set(mutationId, { ...marker, itemIds: structuredClone(itemIds) });
      return { ok: true, updated: Boolean(marker) };
    },
    async getCloudflareMutation(mutationId) {
      return structuredClone(markers.get(mutationId) || null);
    },
    async resolveCloudflareMutation(mutationId) {
      return { ok: true, resolved: markers.delete(mutationId) };
    },
    async releaseCloudflareMutation(mutationId, retryAt) {
      const marker = markers.get(mutationId);
      if (marker) markers.set(mutationId, { ...marker, notBefore: retryAt, leaseUntil: 0 });
      return { ok: true, released: Boolean(marker) };
    },
    async claimCloudflareMutations() { return []; },
    async listCloudflareMutationComments() {
      return [...markers.values()].map((marker) => marker.comment);
    },
    async claimRecordMaintenanceLease(_ownerToken, now, leaseMs) {
      return { claimed: true, leaseUntil: now + leaseMs };
    },
    async releaseRecordMaintenanceLease() { return { released: true }; },
    async claimRecordLease(_uuid, _ownerToken, now, leaseMs) {
      return { claimed: true, leaseUntil: now + leaseMs };
    },
    async releaseRecordLease() { return { released: true }; },
  };
}

function makeEnv(stub, values = new Map()) {
  return {
    AUTH_STATE: {
      getByName() {
        return stub;
      },
    },
    INVITE_STORE: {
      async get(key) { return values.get(key) ?? null; },
      async put(key, value) { values.set(key, value); },
      async delete(key) { values.delete(key); },
    },
    CREDENTIAL_ENCRYPTION_KEY: ENCRYPTION_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
    ALLOWED_HOSTNAMES: "api.example.test",
    ACCOUNT_ID: "test-account",
    IP_LIST_ID: "test-list",
    CLOUDFLARE_API_TOKEN: "test-token",
    SUB2API_SYNC_SECRET: "test-only-sync-secret-with-at-least-32-bytes",
    SUB2API_SYNC_URL: "https://api.example.test/_sub2api-sync/provision",
    SUB2API_DEFAULT_BASE_URL: BASE_URL,
    SUB2API_LOGIN_URL: "https://api.example.test/login",
  };
}

async function protectedInvite() {
  return await protectInviteCredentials({
    uuid: UUID,
    username: "winner",
    name: "winner",
    email: "winner@example.test",
    remark: "authoritative",
    credentialVersion: 2,
    accessCredentialVersion: 1,
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [{
      id: "sub2api-sync",
      name: "Sub2API",
      baseUrl: BASE_URL,
      apiKey: testApiKey("a"),
    }],
    sub2apiSync: {
      userId: 9,
      tokenId: 17,
      username: "winner",
      email: "winner@example.test",
      loginPassword: "winner-password",
      passwordHashFingerprint: "authoritative-fingerprint",
      loginUrl: "https://api.example.test/login",
    },
    createdAt: "2026-07-21T00:00:00.000Z",
    updatedAt: "2026-07-21T00:00:00.000Z",
  }, ENCRYPTION_KEY, HMAC_KEY);
}

function syncResponse(body, sequence) {
  const tokens = (body.tokens || []).map((token, index) => ({
    tokenId: 17 + index,
    apiKeyId: 17 + index,
    name: token.tokenName || token.apiKeyName || "Sub2API",
    tokenKey: token.tokenKey || token.apiKey || testApiKey("c"),
    apiKey: token.tokenKey || token.apiKey || testApiKey("c"),
    status: 1,
  }));
  return Response.json({
    ok: true,
    action: body.action,
    uuid: body.uuid,
    username: body.username || "winner",
    email: body.email || "winner@example.test",
    userId: body.sub2apiUserId || 9,
    tokenId: tokens[0]?.tokenId || 17,
    apiKeyId: tokens[0]?.apiKeyId || 17,
    loginPassword: body.loginPassword || `generated-password-${sequence}`,
    passwordHashFingerprint: String(sequence).repeat(64),
    tokens,
    allowedGroups: ["openai-default"],
    baseUrl: BASE_URL,
    loginUrl: "https://api.example.test/login",
    syncedAt: `2026-07-21T00:00:0${sequence}.000Z`,
  });
}

function testApiKey(character) {
  return `sk-${character.repeat(48)}`;
}
