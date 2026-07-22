import assert from "node:assert/strict";
import test from "node:test";

import { Miniflare } from "miniflare";

import { __test as adminTest } from "../src/admin.js";

const UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
const OTHER_UUID = "4c484f74-6d93-43d1-9441-00c7d8d4ab12";
const CREATE_UUID = "8c484f74-6d93-43d1-9441-00c7d8d4ab13";
const SESSION_TOKEN = "admin-edit-runtime-session";
const CSRF = "admin-edit-runtime-csrf";
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const ENCRYPTION_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const HMAC_KEY = "runtime-test-hmac-key-with-at-least-32-bytes";
const API_SECRET = "sk-admin-edit-private-sentinel";
const REPLACEMENT_API_SECRET = "sk-admin-edit-replacement-sentinel";
const LOGIN_SECRET = "admin-edit-login-private-sentinel";
const CREDENTIAL_ID = "credential-primary";
const OTHER_CREDENTIAL_ID = "credential-other-invite";
const BASE_URL = "https://provider.example.test/v1";

function invite(uuid, username, credentialId, apiKey) {
  return {
    uuid,
    username,
    name: username,
    email: `${username}@example.test`,
    accessKeyHmac: uuid === UUID ? "a".repeat(64) : "b".repeat(64),
    credentialVersion: 2,
    accessCredentialVersion: 1,
    apiConfigs: [{
      id: credentialId,
      name: "Provider",
      baseUrl: BASE_URL,
      apiKey,
    }],
    sub2apiSync: {
      userId: uuid === UUID ? 11 : 12,
      username,
      email: `${username}@example.test`,
      loginPassword: LOGIN_SECRET,
    },
  };
}

function makeMiniflare(outboundBodies) {
  return new Miniflare({
    modules: true,
    scriptPath: new URL("../test-support/admin-credential-harness.js", import.meta.url).pathname,
    modulesRoot: new URL("..", import.meta.url).pathname,
    modulesRules: [{ type: "ESModule", include: ["**/*.js"] }],
    compatibilityDate: "2026-07-21",
    compatibilityFlags: ["nodejs_compat"],
    bindings: {
      ADMIN_USERNAME: "admin",
      ADMIN_PASSWORD_PBKDF2: "pbkdf2_sha256$310000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      ADMIN_TOTP_SECRET: TOTP_SECRET,
      CREDENTIAL_ENCRYPTION_KEY: ENCRYPTION_KEY,
      INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
      ALLOWED_HOSTNAMES: "api.example.test,sync.example.test",
      PROVIDER_ALLOWED_HOSTNAMES: "provider.example.test,provider-two.example.test",
      ACCOUNT_ID: "a".repeat(32),
      IP_LIST_ID: "b".repeat(32),
      CLOUDFLARE_API_TOKEN: "test-cloudflare-token",
      SUB2API_SYNC_SECRET: "s".repeat(32),
      SUB2API_SYNC_URL: "https://sync.example.test/_sub2api-sync/provision",
      SUB2API_DEFAULT_BASE_URL: "https://api.example.test/v1",
      SUB2API_LOGIN_URL: "https://api.example.test/login",
    },
    kvNamespaces: ["INVITE_STORE"],
    durableObjects: {
      AUTH_RATE_LIMITER: { className: "AuthRateLimiter", useSQLite: true },
      AUTH_STATE: { className: "AuthState", useSQLite: true },
    },
    outboundService: async (request) => {
      const observed = { url: request.url, started: true };
      outboundBodies.push(observed);
      const rawBody = await request.text();
      observed.rawBody = rawBody;
      const body = JSON.parse(rawBody);
      Object.assign(observed, body);
      return Response.json({
        ok: true,
        action: body.action,
        uuid: body.uuid,
        exists: true,
        userId: body.sub2apiUserId || 11,
        tokenId: 0,
        username: body.username,
        email: body.email,
        loginPassword: body.loginPassword,
        loginUrl: "https://api.example.test/login",
        passwordHashFingerprint: "f".repeat(64),
        tokens: [],
      });
    },
  });
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function currentTotp() {
  return await adminTest.totp(TOTP_SECRET, Math.floor(Date.now() / 1000 / 30));
}

async function postUpdate(miniflare, apiConfigs) {
  const form = new URLSearchParams({
    action: "update_invite",
    csrf: CSRF,
    original_uuid: UUID,
    uuid: UUID,
    username: "alice",
    email: "alice@example.test",
    remark: "",
    api_configs: apiConfigs,
    step_up_token: await currentTotp(),
  });
  return await miniflare.dispatchFetch("https://api.example.test/allow-ip/admin", {
    method: "POST",
    redirect: "manual",
    headers: {
      cookie: `sub2api_allow_admin=${SESSION_TOKEN}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
}

async function postCreate(miniflare, apiConfigs) {
  const form = new URLSearchParams({
    action: "create",
    csrf: CSRF,
    uuid: CREATE_UUID,
    username: "charlie",
    email: "charlie@example.test",
    remark: "",
    api_configs: apiConfigs,
    step_up_token: await currentTotp(),
  });
  return await miniflare.dispatchFetch("https://api.example.test/allow-ip/admin", {
    method: "POST",
    redirect: "manual",
    headers: {
      cookie: `sub2api_allow_admin=${SESSION_TOKEN}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
}

test("admin edit keeps encrypted credentials without exposing them and rejects invalid reuse", { timeout: 30_000 }, async (t) => {
  const outboundBodies = [];
  const miniflare = makeMiniflare(outboundBodies);
  t.after(async () => await miniflare.dispose());

  const seedResponse = await miniflare.dispatchFetch("http://worker.test/__test__/seed", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      sessionHash: await sha256Hex(SESSION_TOKEN),
      csrf: CSRF,
      invites: [
        invite(UUID, "alice", CREDENTIAL_ID, API_SECRET),
        invite(OTHER_UUID, "bob", OTHER_CREDENTIAL_ID, "sk-other-private-sentinel"),
      ],
    }),
  });
  assert.equal(seedResponse.status, 200);
  const storedBefore = await seedResponse.json();
  assert.match(JSON.stringify(storedBefore), /apiKeyEncrypted/);
  assert.doesNotMatch(JSON.stringify(storedBefore), new RegExp(API_SECRET));

  const editResponse = await miniflare.dispatchFetch(
    `https://api.example.test/allow-ip/admin?edit=${UUID}`,
    { headers: { cookie: `sub2api_allow_admin=${SESSION_TOKEN}` } },
  );
  const editHtml = await editResponse.text();
  assert.equal(editResponse.status, 200);
  assert.doesNotMatch(editHtml, new RegExp(API_SECRET));
  assert.doesNotMatch(editHtml, new RegExp(LOGIN_SECRET));
  assert.doesNotMatch(editHtml, /apiKeyEncrypted|A256GCM/);
  assert.match(editHtml, new RegExp(`Credential ID: ${CREDENTIAL_ID}`));
  assert.match(editHtml, /Saved; leave blank to keep this credential/);
  assert.match(editHtml, new RegExp(`data-existing-credential-id="${CREDENTIAL_ID}"`));
  assert.match(editHtml, /data-field="api-key"[^>]*value=""/);

  const hiddenValue = Array.from(editHtml.matchAll(/name="api_configs" value="([^"]*)"/g))
    .map((match) => match[1])
    .find((value) => value.includes("existing-credential:v1")) || "";
  assert.match(hiddenValue, /existing-credential:v1/);
  const success = await postUpdate(miniflare, hiddenValue);
  assert.equal(success.status, 303, `${await success.text()}\nhidden=${hiddenValue}\noutbound=${JSON.stringify(outboundBodies)}`);
  assert.equal(outboundBodies.length, 1);

  const revealed = await miniflare.dispatchFetch("http://worker.test/__test__/revealed").then((response) => response.json());
  const updated = revealed.items.find((item) => item.uuid === UUID);
  assert.equal(updated.apiConfigs[0].id, CREDENTIAL_ID);
  assert.equal(updated.apiConfigs[0].apiKey, API_SECRET);
  const storedAfter = await miniflare.dispatchFetch("http://worker.test/__test__/stored").then((response) => response.json());
  assert.doesNotMatch(JSON.stringify(storedAfter), new RegExp(API_SECRET));

  const marker = `@existing-credential:v1:${encodeURIComponent(CREDENTIAL_ID)}`;
  const invalidCases = [
    `Provider | ${BASE_URL} | @existing-credential:v1:${encodeURIComponent("credential-tampered")}`,
    `Provider | ${BASE_URL} | @existing-credential:v1:${encodeURIComponent(OTHER_CREDENTIAL_ID)}`,
    `Provider | ${BASE_URL} | ${marker}\nDuplicate | ${BASE_URL} | ${marker}`,
    `Provider | https://provider-two.example.test/v1 | ${marker}`,
  ];
  for (const apiConfigs of invalidCases) {
    const response = await postUpdate(miniflare, apiConfigs);
    assert.equal(response.status, 400, `${apiConfigs}: ${await response.text()}`);
  }
  assert.equal(outboundBodies.length, 1);

  const createWithMarker = await postCreate(
    miniflare,
    `Provider | ${BASE_URL} | ${marker}`,
  );
  assert.equal(createWithMarker.status, 400, await createWithMarker.text());
  assert.equal(outboundBodies.length, 1);

  const replacement = await postUpdate(
    miniflare,
    `Provider | ${BASE_URL} | ${REPLACEMENT_API_SECRET}`,
  );
  assert.equal(replacement.status, 303, await replacement.text());
  assert.equal(outboundBodies.length, 2);

  const replaced = await miniflare.dispatchFetch("http://worker.test/__test__/revealed").then((response) => response.json());
  const replacedInvite = replaced.items.find((item) => item.uuid === UUID);
  assert.equal(replacedInvite.apiConfigs[0].apiKey, REPLACEMENT_API_SECRET);
  assert.notEqual(replacedInvite.apiConfigs[0].id, CREDENTIAL_ID);
  const storedReplacement = await miniflare.dispatchFetch("http://worker.test/__test__/stored").then((response) => response.json());
  assert.doesNotMatch(JSON.stringify(storedReplacement), new RegExp(API_SECRET));
  assert.doesNotMatch(JSON.stringify(storedReplacement), new RegExp(REPLACEMENT_API_SECRET));

  const final = await miniflare.dispatchFetch("http://worker.test/__test__/revealed").then((response) => response.json());
  assert.equal(final.items.find((item) => item.uuid === UUID).apiConfigs[0].apiKey, REPLACEMENT_API_SECRET);
});
