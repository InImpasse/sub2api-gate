import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { renderInviteSummary } from "../src/invite-summary.js";
import { renderUsageInspectorBody, sanitizeUsageInspectorData } from "../src/usage-inspector.js";
import worker, { __test as workerTest, isIPv4, isIPv6, jsString, TURNSTILE_TIMEOUT_MS, verifyTurnstile } from "../src/index.js";
import { __test as adminTest } from "../src/admin.js";
import { accessKeyHmac, pbkdf2PasswordRecord, protectInviteCredentials } from "../src/credential-security.js";
import { findInvite } from "../src/admin.js";
import { fetchWithTimeout } from "../src/request-security.js";

const TEST_ADMIN_TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const TEST_NEXT_TOTP_SECRET = "KRUGS4ZANFZSAYJA";
const TEST_ADMIN_SESSION_BINDING_KEY = "h".repeat(32);
const ADMIN_SOURCE = readFileSync(new URL("../src/admin.js", import.meta.url), "utf8");


test("invite summary never serializes API keys", () => {
  const secret = "sk-PRIVATE_KEY_SENTINEL_8bd021";
  const html = renderInviteSummary(
    { uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11" },
    [{ name: "OpenAI", baseUrl: "https://api.example.com/v1", apiKey: secret }],
    "/allow-ip/admin",
  );
  assert.doesNotMatch(html, new RegExp(secret));
  assert.match(html, /API keys load only/);
  const paged = renderInviteSummary(
    { uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11" },
    [],
    "/allow-ip/admin",
    { page: 2, trashPage: 3 },
  );
  assert.match(paged, /href="\/allow-ip\/admin\?page=2&amp;trashPage=3&amp;edit=7c484f74-6d93-43d1-9441-00c7d8d4ab11"/);
});

test("usage inspector escapes every displayed metadata value", () => {
  const attack = `"><script>globalThis.compromised=true</script>`;
  const data = sanitizeUsageInspectorData({
    items: [{ id: 1, requestId: attack, model: attack, inboundEndpoint: attack }],
  });
  const html = renderUsageInspectorBody(
    data,
    new Request("https://admin.example/allow-ip/admin/requests"),
    "/allow-ip/admin",
  );
  assert.doesNotMatch(html, /<script>globalThis/);
  assert.match(html, /&lt;script&gt;/);
});

test("usage inspector bounds untrusted numbers and list sizes", () => {
  const data = sanitizeUsageInspectorData({
    page: { pageSize: 999999, nextCursor: -3 },
    modelOptions: Array.from({ length: 120 }, (_, index) => `model-${index}`),
    items: [{ id: -1, inputTokens: Infinity, durationMs: 999999999 }],
  });
  assert.equal(data.page.pageSize, 100);
  assert.equal(data.page.nextCursor, 0);
  assert.equal(data.modelOptions.length, 100);
  assert.equal(data.items[0].id, 0);
  assert.equal(data.items[0].inputTokens, 0);
  assert.equal(data.items[0].durationMs, 86_400_000);
});

test("usage inspector preserves PostgreSQL bigint IDs within the JS safe range", () => {
  const id = 4_294_967_296;
  const data = sanitizeUsageInspectorData({
    page: { nextCursor: id },
    items: [{ id }],
  });
  assert.equal(data.page.nextCursor, id);
  assert.equal(data.items[0].id, id);
  assert.equal(adminTest.parseUsageIdentifier(String(id)), id);
  assert.equal(adminTest.parseUsageIdentifier("1.5"), 0);
  assert.equal(adminTest.parseUsageIdentifier(String(Number.MAX_SAFE_INTEGER + 1)), 0);
});

test("usage inspector accepts the legacy detail item shape", () => {
  const data = sanitizeUsageInspectorData({ item: { id: 9, model: "gpt-test" } });
  assert.equal(data.items.length, 1);
  assert.equal(data.items[0].id, 9);
});

test("usage inspector does not offer an unbounded time range", () => {
  const html = renderUsageInspectorBody(
    { items: [] },
    new Request("https://admin.example/allow-ip/admin/requests"),
    "/allow-ip/admin",
  );
  assert.doesNotMatch(html, /value="all"/);
  assert.match(html, /value="30d"/);
});

test("admin setup fails closed when v2 credential secrets are missing", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip/admin"),
    {
      INVITE_STORE: { async get() { return null; } },
      ALLOWED_HOSTNAMES: "api.example.test",
      ADMIN_USERNAME: "admin",
      ADMIN_PASSWORD_HASH: "a".repeat(64),
      ADMIN_TOTP_SECRET: "TESTSECRET",
      ACCOUNT_ID: "account",
      IP_LIST_ID: "list",
      CLOUDFLARE_API_TOKEN: "token",
      SUB2API_SYNC_URL: "https://api.example.test/_sub2api-sync/provision",
      SUB2API_SYNC_SECRET: "s".repeat(32),
    },
  );
  const body = await response.text();
  assert.equal(response.status, 500);
  assert.match(body, /ADMIN_PASSWORD_PBKDF2/);
  assert.match(body, /CREDENTIAL_ENCRYPTION_KEY/);
  assert.match(body, /INVITE_ACCESS_HMAC_KEY/);
  assert.match(body, /AUTH_RATE_LIMITER/);
});

test("public forms reject bodies larger than 32 KiB before external calls", async () => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("external fetch must not run");
  };
  try {
    const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "CF-Connecting-IP": "198.51.100.8",
      },
      body: `invite_key=${"x".repeat(33 * 1024)}`,
    }), {
      ALLOWED_HOSTNAMES: "api.example.test",
      ACCOUNT_ID: "account",
      IP_LIST_ID: "list",
      TURNSTILE_SITE_KEY: "site",
      TURNSTILE_SECRET_KEY: "secret",
      CLOUDFLARE_API_TOKEN: "token",
    });
    assert.equal(response.status, 413);
    assert.equal(fetchCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("admin forms reject bodies larger than 32 KiB before authentication work", async () => {
  let kvReads = 0;
  const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `action=login&username=${"x".repeat(33 * 1024)}`,
  }), validAdminEnv({
    async get() {
      kvReads += 1;
      return null;
    },
  }));

  assert.equal(response.status, 413);
  assert.equal(kvReads, 0);
});

test("bounded fetch aborts a stalled request", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_input, init) => await new Promise((_resolve, reject) => {
    init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true });
  });
  try {
    await assert.rejects(fetchWithTimeout("https://api.example.test/stall", {}, 10));
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(TURNSTILE_TIMEOUT_MS, 5000);
});

test("Turnstile success is bound to the current request hostname", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    assert.equal(init.redirect, "manual");
    return Response.json({
      success: true,
      hostname: "api.example.test",
    });
  };
  try {
    assert.equal((await verifyTurnstile(
      "turnstile-secret",
      "token",
      "198.51.100.44",
      "api.example.test",
    )).success, true);
    assert.equal((await verifyTurnstile(
      "turnstile-secret",
      "token",
      "198.51.100.44",
      "evil.example.test",
    )).success, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Turnstile verification rejects redirects without forwarding the secret", async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = async (url, init) => {
    calls += 1;
    assert.equal(String(url), "https://challenges.cloudflare.com/turnstile/v0/siteverify");
    assert.equal(init.redirect, "manual");
    return new Response(null, {
      status: 302,
      headers: { location: "https://redirect.example.test/collect" },
    });
  };
  try {
    assert.equal((await verifyTurnstile(
      "turnstile-secret",
      "token",
      "198.51.100.44",
      "api.example.test",
    )).success, false);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(calls, 1);
});

test("invalid access keys do not decrypt stored invite credentials", async () => {
  const hmacKey = "test-only-hmac-key-with-at-least-32-bytes";
  const invite = {
    uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    credentialVersion: 2,
    accessKeyHmac: await accessKeyHmac(hmacKey, "s2a_correct"),
    apiConfigs: [{
      name: "OpenAI",
      baseUrl: "https://api.example.test/v1",
      apiKeyEncrypted: { v: 1, alg: "A256GCM", iv: "invalid", data: "invalid" },
    }],
  };
  const env = {
    INVITE_ACCESS_HMAC_KEY: hmacKey,
    CREDENTIAL_ENCRYPTION_KEY: "invalid",
    ALLOWED_HOSTNAMES: "api.example.test",
    INVITE_STORE: {
      async get(key) {
        return key === "invites" ? JSON.stringify([invite]) : null;
      },
    },
  };

  assert.equal(await findInvite(env, "s2a_wrong"), null);
});

test("expired legacy UUIDs are rejected before AuthState decrypts credentials", async () => {
  const hmacKey = "test-only-hmac-key-with-at-least-32-bytes";
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const storedInvite = {
    uuid,
    credentialVersion: 2,
    accessCredentialVersion: 1,
    accessKeyHmac: await accessKeyHmac(hmacKey, "s2a_correct"),
    legacyUuidLoginUntil: "2026-07-01T00:00:00.000Z",
    apiConfigs: [{
      id: "primary",
      name: "OpenAI",
      baseUrl: "https://provider.example.test/v1",
      apiKeyEncrypted: { v: 2, alg: "A256GCM", iv: "invalid", data: "invalid" },
    }],
    sub2apiSync: {},
  };
  let uuidLookups = 0;
  const env = {
    AUTH_STATE: {
      getByName() {
        return {
          async status() { return { migrated: true }; },
          async findInviteByAccessKeyHmac() { return null; },
          async getInvite(candidate) {
            uuidLookups += 1;
            assert.equal(candidate, uuid);
            return storedInvite;
          },
        };
      },
    },
    INVITE_STORE: {
      async get() { throw new Error("legacy invite KV must not be read"); },
    },
    CREDENTIAL_ENCRYPTION_KEY: "invalid",
    INVITE_ACCESS_HMAC_KEY: hmacKey,
    ALLOWED_HOSTNAMES: "api.example.test",
    PROVIDER_ALLOWED_HOSTNAMES: "provider.example.test",
  };

  assert.equal(await findInvite(env, uuid), null);
  assert.equal(uuidLookups, 1);
});

test("access-key lookup uses AuthState without scanning legacy invite KV", async () => {
  const encryptionKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
  const hmacKey = "test-only-hmac-key-with-at-least-32-bytes";
  const accessKey = "s2a_strong-state-test-key";
  const accessHmac = await accessKeyHmac(hmacKey, accessKey);
  const storedInvite = await protectInviteCredentials({
    uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    credentialVersion: 2,
    accessCredentialVersion: 1,
    accessKeyHmac: accessHmac,
    username: "alice",
    apiConfigs: [],
    sub2apiSync: {},
  }, encryptionKey, hmacKey);
  let legacyInviteReads = 0;
  const lookups = [];
  const stub = {
    async status() {
      return { migrated: true };
    },
    async findInviteByAccessKeyHmac(candidate) {
      lookups.push(candidate);
      return candidate === accessHmac ? storedInvite : null;
    },
  };
  const env = {
    AUTH_STATE: {
      getByName() {
        return stub;
      },
    },
    INVITE_STORE: {
      async get(key) {
        if (key === "invites") legacyInviteReads += 1;
        throw new Error("legacy invite KV must not be read");
      },
    },
    CREDENTIAL_ENCRYPTION_KEY: encryptionKey,
    INVITE_ACCESS_HMAC_KEY: hmacKey,
    ALLOWED_HOSTNAMES: "api.example.test",
  };

  const invite = await findInvite(env, accessKey);
  assert.equal(invite?.uuid, storedInvite.uuid);
  assert.deepEqual(lookups, [accessHmac]);
  assert.equal(legacyInviteReads, 0);
});

test("scheduled maintenance purges expired sessions without deleting legacy rollback state", async () => {
  let purgeCalls = 0;
  let legacyCleanupCalls = 0;
  const stub = {
    async status() {
      return {
        migrated: true,
        legacyCleanupComplete: true,
        legacyCleanupSchedulerReady: true,
      };
    },
    async purgeExpiredSessions() {
      purgeCalls += 1;
      return { ok: true, deleted: 2 };
    },
    async runLegacyCleanup() {
      legacyCleanupCalls += 1;
      return { ok: true, cleaned: true, remaining: 0 };
    },
  };
  const waits = [];
  const originalError = console.error;
  console.error = () => {};
  try {
    await worker.scheduled({}, {
      AUTH_STATE: {
        getByName() {
          return stub;
        },
      },
    }, {
      waitUntil(promise) {
        waits.push(promise);
      },
    });
    await Promise.all(waits);
  } finally {
    console.error = originalError;
  }

  assert.equal(waits.length, 1);
  assert.equal(purgeCalls, 1);
  assert.equal(legacyCleanupCalls, 0);
});

test("HTML responses use a per-response script nonce without unsafe-inline", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip"),
    { ALLOWED_HOSTNAMES: "api.example.test", TURNSTILE_SITE_KEY: "site" },
  );
  const csp = response.headers.get("content-security-policy") || "";
  const nonce = csp.match(/script-src 'nonce-([a-f0-9]+)'/)?.[1];
  assert.ok(nonce);
  assert.doesNotMatch(csp.split("style-src")[0], /unsafe-inline/);
  const body = await response.text();
  assert.doesNotMatch(body, /<script(?! nonce=)/);
  assert.match(body, new RegExp(`<script nonce="${nonce}"`));
  assert.doesNotMatch(body, /\son[a-z]+\s*=/i);
});

test("authenticated admin HTML nonces every script and has no event attributes", async () => {
  const sessionToken = "local-admin-session-token";
  const values = new Map([
    [`session:${await sha256Hex(sessionToken)}`, JSON.stringify(
      await boundAdminSession("local-csrf-token", Date.now() + 60_000),
    )],
    ["invites", "[]"],
    ["trash", "[]"],
  ]);
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip/admin", {
      headers: { cookie: `sub2api_allow_admin=${sessionToken}` },
    }),
    validAdminEnv(memoryKv(values)),
  );

  assert.equal(response.status, 200);
  const csp = response.headers.get("content-security-policy") || "";
  const nonce = csp.match(/script-src 'nonce-([a-f0-9]+)'/)?.[1];
  assert.ok(nonce);
  assert.doesNotMatch(csp.split("style-src")[0], /unsafe-inline/);

  const body = await response.text();
  const scriptTags = [...body.matchAll(/<script\b([^>]*)>/gi)];
  assert.ok(scriptTags.length > 0);
  for (const [, attributes] of scriptTags) {
    assert.match(attributes, new RegExp(`\\bnonce="${nonce}"`));
  }
  assert.doesNotMatch(body, /\son[a-z]+\s*=/i);
});

test("raw injected scripts are never automatically trusted by CSP helpers", async () => {
  for (const render of [workerTest.html, adminTest.html]) {
    const response = render("<script>globalThis.compromised=true</script>");
    const csp = response.headers.get("content-security-policy") || "";
    const nonce = csp.match(/script-src 'nonce-([a-f0-9]+)'/)?.[1];
    assert.ok(nonce);
    const body = await response.text();
    assert.match(body, /<script>globalThis\.compromised=true<\/script>/);
    assert.doesNotMatch(body, new RegExp(`<script nonce="${nonce}"`));
  }
});

test("JavaScript string serialization neutralizes script terminators and separators", () => {
  const serialized = jsString("</script><img>\u2028\u2029&");
  assert.doesNotMatch(serialized, /[<>&\u2028\u2029]/u);
  assert.match(serialized, /\\u003c\/script\\u003e/);
});

test("client IP validation rejects malformed and ambiguous addresses", () => {
  assert.equal(isIPv4("198.51.100.44"), true);
  assert.equal(isIPv4("198.051.100.44"), false);
  assert.equal(isIPv4("198.51.100.999"), false);
  assert.equal(isIPv6("2001:db8::42"), true);
  assert.equal(isIPv6("::ffff:192.0.2.1"), true);
  assert.equal(isIPv6("::::"), false);
  assert.equal(isIPv6("1:2:3:4:5:6:7:8:9"), false);
  assert.equal(adminTest.detectIpVersion("198.051.100.44"), "");
  assert.equal(adminTest.detectIpVersion("::ffff:192.0.2.1"), "IPv6");
});

test("public host routing fails closed when ALLOWED_HOSTNAMES is absent", async () => {
  const response = await worker.fetch(new Request("https://api.example.test/allow-ip"), {});
  assert.equal(response.status, 404);
});

test("the deprecated singular hostname setting cannot bypass fail-closed routing", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip"),
    { ALLOWED_HOSTNAME: "api.example.test" },
  );
  assert.equal(response.status, 404);
});

test("public host routing rejects IP literals and invalid mixed allowlists", async () => {
  const ipResponse = await worker.fetch(
    new Request("https://127.0.0.1/allow-ip"),
    { ALLOWED_HOSTNAMES: "127.0.0.1" },
  );
  assert.equal(ipResponse.status, 404);

  const mixedResponse = await worker.fetch(
    new Request("https://api.example.test/allow-ip"),
    { ALLOWED_HOSTNAMES: "api.example.test,169.254.169.254" },
  );
  assert.equal(mixedResponse.status, 404);
});

test("admin configuration rejects HTTP and unapproved Sub2API URLs", () => {
  const valid = {
    INVITE_STORE: {},
    AUTH_RATE_LIMITER: observingRateLimiter(true),
    ADMIN_USERNAME: "admin",
    ADMIN_PASSWORD_PBKDF2: "pbkdf2_sha256$310000$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ADMIN_TOTP_SECRET: "JBSWY3DPEHPK3PXP",
    CREDENTIAL_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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

  assert.equal(adminTest.getAdminSetupError(valid), "");
  assert.match(
    adminTest.getAdminSetupError({ ...valid, IP_LIST_ID: "list/../tokens" }),
    /identifier formats/,
  );
  assert.match(
    adminTest.getAdminSetupError({ ...valid, SUB2API_LOGIN_URL: "http://api.example.test/login" }),
    /HTTPS|https/,
  );
  assert.match(
    adminTest.getAdminSetupError({ ...valid, SUB2API_DEFAULT_BASE_URL: "https://evil.example/v1" }),
    /approved hostname/,
  );
  for (const baseUrl of [
    "https://127.0.0.1/v1",
    "https://169.254.169.254/v1",
    "https://service.local/v1",
    "https://api.example.test.:443/v1",
    "https://api.example.test:8443/v1",
    "https://api.example.test/v1?target=internal",
  ]) {
    assert.match(
      adminTest.getAdminSetupError({ ...valid, ALLOWED_HOSTNAMES: new URL(baseUrl).hostname, SUB2API_DEFAULT_BASE_URL: baseUrl }),
      /approved hostname|ALLOWED_HOSTNAMES/,
      baseUrl,
    );
  }
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      SUB2API_LOGIN_URL: "https://user:password@api.example.test/login",
    }),
    /HTTPS|approved hostname/,
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      SUB2API_SYNC_URL: "https://user:password@api.example.test/_sub2api-sync/provision",
    }),
    /URL credentials/,
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      SUB2API_SYNC_URL: "https://api.example.test/allow-ip?forward=provision",
    }),
    /dedicated \/_sub2api-sync\/provision endpoint/,
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      ALLOWED_HOSTNAMES: "169.254.169.254",
      SUB2API_SYNC_URL: "https://169.254.169.254/_sub2api-sync/provision",
    }),
    /ALLOWED_HOSTNAMES/,
  );
  assert.match(
    adminTest.getAdminSetupError({ ...valid, ALLOWED_HOSTNAMES: "" }),
    /ALLOWED_HOSTNAMES/,
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      PROVIDER_ALLOWED_HOSTNAMES: "api.example.test,provider.example.test",
    }),
    /must not contain a public ALLOWED_HOSTNAMES hostname/,
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      PROVIDER_ALLOWED_HOSTNAMES: "127.0.0.1",
    }),
    /valid provider hostnames/,
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      ADMIN_PASSWORD_PBKDF2: "pbkdf2_sha256$99999$c2FsdA$ZGlnaWVzdA",
    }),
    /PBKDF2/,
  );
  assert.match(
    adminTest.getAdminSetupError({ ...valid, ADMIN_TOTP_SECRET: "invalid-characters!" }),
    /Base32/,
  );
  assert.equal(
    adminTest.getAdminSetupError({
      ...valid,
      ADMIN_TOTP_SECRET_NEXT: "invalid-characters!",
      ADMIN_TOTP_ROTATION_PHASE: "stage",
    }),
    "",
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      CREDENTIAL_ENCRYPTION_KEY: `${valid.CREDENTIAL_ENCRYPTION_KEY}=`,
    }),
    /base64url/,
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      GEOIP_LOOKUP_URL: "https://geo.example.test/lookup/{ip}",
    }),
    /configured together/,
  );
  assert.match(
    adminTest.getAdminSetupError({
      ...valid,
      GEOIP_LOOKUP_URL: "https://unapproved.example.test/lookup/{ip}",
      GEOIP_ALLOWED_HOSTNAMES: "geo.example.test",
    }),
    /approved HTTPS hostname/,
  );
});

test("public gateway and provider URL allowlists are isolated", () => {
  const env = {
    ...validAdminEnv(memoryKv(new Map())),
    PROVIDER_ALLOWED_HOSTNAMES: "provider.example.test",
  };
  assert.equal(
    adminTest.approvedApiConfigUrl(env, {
      name: "Sub2API",
      baseUrl: "https://api.example.test/v1",
    }),
    "https://api.example.test/v1",
  );
  assert.equal(
    adminTest.approvedApiConfigUrl(env, {
      name: "OpenAI",
      baseUrl: "https://provider.example.test/v1",
    }),
    "https://provider.example.test/v1",
  );
  assert.equal(
    adminTest.approvedApiConfigUrl(env, {
      name: "OpenAI",
      baseUrl: "https://api.example.test/provider/v1",
    }),
    "",
  );
  assert.equal(
    adminTest.approvedApiConfigUrl(env, {
      name: "Sub2API",
      baseUrl: "https://provider.example.test/v1",
    }),
    "",
  );
  assert.equal(
    adminTest.approvedApiConfigUrl({
      ...env,
      PROVIDER_ALLOWED_HOSTNAMES: "api.example.test,provider.example.test",
    }, {
      name: "OpenAI",
      baseUrl: "https://provider.example.test/v1",
    }),
    "",
  );
});

test("third-party GeoIP is disabled by default and requires a separate hostname allowlist", async () => {
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async (url, init) => {
    fetchCalls += 1;
    assert.equal(String(url), "https://geo.example.test/lookup/198.51.100.8");
    assert.equal(init.redirect, "manual");
    return Response.json({
      country_code: "DE",
      region: "Berlin",
      city: "Berlin",
      asn: "AS64500",
    });
  };
  try {
    const fallback = await adminTest.lookupIpLocation({}, "198.51.100.8", {
      country: "US",
      region: "Oregon",
      city: "Portland",
      colo: "PDX",
    });
    assert.equal(fetchCalls, 0);
    assert.equal(fallback.source, "cloudflare");
    assert.equal(fallback.country, "US");

    const blocked = await adminTest.lookupIpLocation({
      GEOIP_LOOKUP_URL: "https://geo.example.test/lookup/{ip}",
      GEOIP_ALLOWED_HOSTNAMES: "other.example.test",
    }, "198.51.100.8", {});
    assert.equal(fetchCalls, 0);
    assert.equal(blocked.source, "cloudflare");

    assert.equal(adminTest.resolveGeoIpLookupUrl({
      GEOIP_LOOKUP_URL: "https://user:password@geo.example.test/lookup/{ip}",
      GEOIP_ALLOWED_HOSTNAMES: "geo.example.test",
    }, "198.51.100.8"), "");
    for (const configuration of [
      {
        GEOIP_LOOKUP_URL: "https://169.254.169.254/lookup/{ip}",
        GEOIP_ALLOWED_HOSTNAMES: "169.254.169.254",
      },
      {
        GEOIP_LOOKUP_URL: "https://geo.example.test:8443/lookup/{ip}",
        GEOIP_ALLOWED_HOSTNAMES: "geo.example.test",
      },
      {
        GEOIP_LOOKUP_URL: "https://geo.example.test./lookup/{ip}",
        GEOIP_ALLOWED_HOSTNAMES: "geo.example.test.",
      },
    ]) {
      assert.equal(
        adminTest.resolveGeoIpLookupUrl(configuration, "198.51.100.8"),
        "",
      );
    }

    const enriched = await adminTest.lookupIpLocation({
      GEOIP_LOOKUP_URL: "https://geo.example.test/lookup/{ip}",
      GEOIP_ALLOWED_HOSTNAMES: "geo.example.test",
    }, "198.51.100.8", {});
    assert.equal(fetchCalls, 1);
    assert.equal(enriched.source, "geoip");
    assert.equal(enriched.country, "DE");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Sub2API sync accepts only explicit matching success and never forwards upstream errors", async () => {
  const env = validAdminEnv(memoryKv(new Map()));
  const originalFetch = globalThis.fetch;
  const upstreamSentinel = "upstream-private-error-sentinel";
  let responseFactory;
  let requestBody;
  let requestHeaders;
  globalThis.fetch = async (_url, init) => {
    assert.equal(init.redirect, "manual");
    requestBody = JSON.parse(init.body);
    requestHeaders = new Headers(init.headers);
    return responseFactory();
  };
  try {
    responseFactory = () => Response.json({ ok: true, action: "status", exists: true });
    const accepted = await adminTest.callSub2ApiSync(
      env,
      "status",
      { action: "attacker-value" },
    );
    assert.equal(accepted.exists, true);
    assert.equal(requestBody.action, "status");
    assert.match(requestHeaders.get("x-request-id") || "", /^worker-[a-f0-9]{32}$/);

    const failures = [
      () => Response.json({ action: "status" }),
      () => Response.json({ ok: false, action: "status", error: upstreamSentinel }),
      () => Response.json({ ok: true, action: "provision", error: upstreamSentinel }),
      () => Response.json([]),
      () => Response.json(
        { ok: true, action: "status", error: upstreamSentinel },
        { status: 502 },
      ),
      () => Response.json(
        { ok: true, action: "status" },
        { status: 302, headers: { location: "https://redirect.example.test/" } },
      ),
      () => new Response(upstreamSentinel, {
        headers: { "content-type": "application/json" },
      }),
      () => {
        throw new Error(upstreamSentinel);
      },
    ];
    for (const failure of failures) {
      responseFactory = failure;
      await assert.rejects(
        adminTest.callSub2ApiSync(env, "status", {}),
        (error) => {
          assert.equal(error.message, "Sub2API sync request failed");
          assert.doesNotMatch(error.message, new RegExp(upstreamSentinel));
          return true;
        },
      );
    }

    responseFactory = () => Response.json({
      ok: false,
      error: "dependency_unavailable",
      retryable: true,
      requestId: "sync-request-503",
      action: "status",
    }, {
      status: 503,
      headers: { "x-request-id": "sync-request-503" },
    });
    await assert.rejects(
      adminTest.callSub2ApiSync(env, "status", {}),
      (error) => {
        assert.equal(error.message, "Sub2API sync request failed");
        assert.equal(error.status, 503);
        assert.equal(error.code, "dependency_unavailable");
        assert.equal(error.retryable, true);
        assert.equal(error.requestId, "sync-request-503");
        assert.equal(error.action, "status");
        return true;
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Sub2API sync budgets leave the origin time to terminate timed-out work", () => {
  assert.equal(adminTest.sub2apiSyncTimeoutForAction("login"), 10_000);
  for (const action of ["provision", "status", "deprovision", "purge", "usage_logs_list", "usage_log_detail", "list_groups", "test_api_key"]) {
    assert.equal(adminTest.sub2apiSyncTimeoutForAction(action), 5_000);
  }
});

test("Sub2API sync binds UUID responses and bounds credential-bearing fields", async () => {
  const env = validAdminEnv(memoryKv(new Map()));
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const otherUuid = "4c484f74-6d93-43d1-9441-00c7d8d4ab12";
  const apiKey = `sk-${"a".repeat(64)}`;
  const originalFetch = globalThis.fetch;
  let responseBody;
  globalThis.fetch = async () => Response.json(responseBody);

  const provisionResult = {
    ok: true,
    action: "provision",
    uuid,
    apiKey,
    tokenKey: apiKey,
    loginPassword: "bounded-login-password",
    passwordHashFingerprint: "f".repeat(64),
    tokens: [{
      apiKeyId: 1,
      tokenId: 1,
      name: "Sub2API",
      apiKey,
      tokenKey: apiKey,
      status: 1,
    }],
  };

  try {
    responseBody = provisionResult;
    const accepted = await adminTest.callSub2ApiSync(env, "provision", { uuid });
    assert.equal(accepted.uuid, uuid);

    const maximumValidTokens = Array.from({ length: 100 }, (_value, index) => ({
      apiKeyId: index + 1,
      tokenId: index + 1,
      name: `Sub2API ${"n".repeat(90)}${index}`.slice(0, 100),
      apiKey: `sk-${"a".repeat(125)}`,
      tokenKey: `sk-${"a".repeat(125)}`,
      status: 1,
    }));
    responseBody = { ...provisionResult, tokens: maximumValidTokens };
    assert.ok(new TextEncoder().encode(JSON.stringify(responseBody)).byteLength > 16 * 1024);
    assert.equal(
      (await adminTest.callSub2ApiSync(env, "provision", { uuid })).tokens.length,
      100,
    );

    const rejectedProvisionResponses = [
      { ...provisionResult, uuid: otherUuid },
      { ...provisionResult, uuid: undefined },
      { ...provisionResult, apiKey: `sk-${"a".repeat(126)}` },
      { ...provisionResult, loginPassword: "p".repeat(513) },
      { ...provisionResult, passwordHashFingerprint: "not-a-sha256-fingerprint" },
      { ...provisionResult, tokens: Array.from({ length: 101 }, () => provisionResult.tokens[0]) },
      { ...provisionResult, tokens: [{ ...provisionResult.tokens[0], tokenKey: 123 }] },
    ];
    for (const candidate of rejectedProvisionResponses) {
      responseBody = candidate;
      await assert.rejects(
        adminTest.callSub2ApiSync(env, "provision", { uuid }),
        /Sub2API sync request failed/,
      );
    }

    const loginResult = {
      ok: true,
      action: "login",
      uuid,
      auth: {
        access_token: "access-token",
        refresh_token: "refresh-token",
        expires_in: 3600,
        user: { id: 1, username: "alice", status: true, balance: "100" },
      },
    };
    responseBody = loginResult;
    assert.equal(
      (await adminTest.callSub2ApiSync(env, "login", { uuid })).auth.access_token,
      "access-token",
    );
    for (const auth of [
      { ...loginResult.auth, access_token: 123 },
      { ...loginResult.auth, access_token: "x".repeat(4097) },
      { ...loginResult.auth, access_token: "界".repeat(1366) },
      { ...loginResult.auth, refresh_token: "x".repeat(4097) },
      { ...loginResult.auth, expires_in: Number.POSITIVE_INFINITY },
      { ...loginResult.auth, debug: "must-not-cross-sync-boundary" },
      { ...loginResult.auth, user: "not-an-object" },
      { ...loginResult.auth, user: { ...loginResult.auth.user, password_hash: "secret" } },
      { ...loginResult.auth, user: { ...loginResult.auth.user, conversation_preview: "secret" } },
      { ...loginResult.auth, user: { ...loginResult.auth.user, debug: "secret" } },
      { ...loginResult.auth, user: { ...loginResult.auth.user, username: "界".repeat(171) } },
      { ...loginResult.auth, user: { ...loginResult.auth.user, id: 1.5 } },
    ]) {
      responseBody = { ...loginResult, auth };
      await assert.rejects(
        adminTest.callSub2ApiSync(env, "login", { uuid }),
        /Sub2API sync request failed/,
      );
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Sub2API removal sends the canonical API-key ID and the rollout-compatible token ID", async () => {
  const env = validAdminEnv(memoryKv(new Map()));
  const invite = {
    uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    username: "Alice Example",
    sub2apiSync: { userId: 9, tokenId: 17 },
  };
  const originalFetch = globalThis.fetch;
  const bodies = [];
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(init.body);
    bodies.push(body);
    return Response.json({ ok: true, action: body.action, uuid: body.uuid });
  };
  try {
    await adminTest.deprovisionSub2ApiUser(env, invite);
    await adminTest.purgeSub2ApiUser(env, invite);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.deepEqual(bodies.map((body) => body.action), ["deprovision", "purge"]);
  for (const body of bodies) {
    assert.equal(body.username, "alice-example");
    assert.equal(body.sub2apiApiKeyId, 17);
    assert.equal(body.tokenId, 17);
    assert.equal(Object.hasOwn(body, "sub2apiTokenId"), false);
  }
});

test("orphan cleanup deletes only stale managed comments without active references", async () => {
  const activeComment = `sub2api ref ${"a".repeat(32)}`;
  const staleComment = `sub2api ref ${"b".repeat(32)}`;
  const referencedComment = `sub2api ref ${"c".repeat(32)}`;
  const listItems = [
    { id: "stale-managed", ip: "198.51.100.0/24", comment: staleComment },
    { id: "active-managed", ip: "198.51.101.0/24", comment: activeComment },
    { id: "still-referenced", ip: "198.51.102.0/24", comment: referencedComment },
    { id: "foreign", ip: "198.51.103.0/24", comment: "managed by another service" },
    { id: "malformed", ip: "198.51.104.0/24", comment: "sub2api ref already-managed" },
  ];
  const env = {
    ACCOUNT_ID: "account",
    IP_LIST_ID: "list",
    CLOUDFLARE_API_TOKEN: "cloudflare-token",
  };
  const protectedKeys = new Set(["value:198.51.102.0/24"]);
  const originalFetch = globalThis.fetch;
  const deletedIds = [];
  let fetchCalls = 0;
  globalThis.fetch = async (input, init = {}) => {
    fetchCalls += 1;
    if (new URL(input).pathname.includes("/bulk_operations/")) {
      return Response.json({ success: true, result: { status: "completed" } });
    }
    if (!init.method || init.method === "GET") {
      return Response.json({
        success: true,
        result: listItems,
        result_info: { cursors: { after: "" } },
      });
    }
    assert.equal(init.method, "DELETE");
    deletedIds.push(...JSON.parse(init.body).items.map((item) => item.id));
    return Response.json({ success: true, result: { operation_id: "delete-operation" } });
  };

  try {
    const removed = await adminTest.deleteOrphanedCloudflareListItems(
      env,
      protectedKeys,
      new Set([activeComment]),
    );
    assert.equal(removed, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(fetchCalls, 3);
  assert.deepEqual(deletedIds, ["stale-managed"]);
});

test("every access-changing admin action requires TOTP step-up", () => {
  for (const action of [
    "create",
    "migrate_invite_credentials",
    "finalize_legacy_auth_state_cleanup",
    "rotate_access_key",
    "restore_uuid",
    "reset_sub2api_password",
    "update_invite",
    "delete",
    "purge_uuid",
    "delete_ip_group",
    "restore_ip_group",
    "purge_ip_group",
    "update_ip_group_expiration",
    "add_ip_group",
  ]) {
    assert.equal(adminTest.requiresStepUpAction(action), true, action);
  }
  for (const action of ["login", "logout", "refresh_sub2api_status", "test_api_key"]) {
    assert.equal(adminTest.requiresStepUpAction(action), false, action);
  }
});

test("admin UI renders a TOTP field for every access-changing action", () => {
  for (const action of [
    "create",
    "migrate_invite_credentials",
    "finalize_legacy_auth_state_cleanup",
    "rotate_access_key",
    "restore_uuid",
    "reset_sub2api_password",
    "update_invite",
    "delete",
    "purge_uuid",
    "delete_ip_group",
    "restore_ip_group",
    "purge_ip_group",
    "update_ip_group_expiration",
    "add_ip_group",
  ]) {
    const marker = `name="action" value="${action}"`;
    const actionOffset = ADMIN_SOURCE.indexOf(marker);
    assert.notEqual(actionOffset, -1, action);
    const formEnd = ADMIN_SOURCE.indexOf("</form>", actionOffset);
    assert.notEqual(formEnd, -1, action);
    assert.ok(
      ADMIN_SOURCE.slice(actionOffset, formEnd).includes('name="step_up_token"'),
      action,
    );
  }
});

test("legacy AuthState cleanup requires TOTP and every seven-day deadline to expire", async () => {
  const token = "legacy-cleanup-admin-session";
  const sessionHash = await sha256Hex(token);
  const csrf = "legacy-cleanup-csrf";
  const session = await boundAdminSession(csrf, Date.now() + 60_000);
  let cleanupCalls = 0;
  let deadline = new Date(Date.now() + 60_000).toISOString();
  const stub = {
    async status() {
      return { migrated: true, legacyCleanupComplete: false };
    },
    async getAdminSession(hash) {
      assert.equal(hash, sessionHash);
      return session;
    },
    async getInvites() {
      return {
        revision: 1,
        items: [{
          uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
          username: "legacy-cleanup-user",
          credentialVersion: 2,
          accessCredentialVersion: 1,
          accessKeyHmac: "a".repeat(64),
          legacyUuidLoginUntil: deadline,
          apiConfigs: [],
          sub2apiSync: {},
        }],
      };
    },
    async runLegacyCleanup(reason) {
      assert.equal(reason, "explicit");
      cleanupCalls += 1;
      return { ok: true, cleaned: true };
    },
  };
  const env = {
    ...validAdminEnv(memoryKv(new Map())),
    AUTH_STATE: { getByName() { return stub; } },
  };
  const stepUpToken = await adminTest.totp(
    env.ADMIN_TOTP_SECRET,
    Math.floor(Date.now() / 1000 / 30),
  );
  const submit = async () => await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
    method: "POST",
    headers: {
      cookie: `sub2api_allow_admin=${token}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      action: "finalize_legacy_auth_state_cleanup",
      csrf,
      step_up_token: stepUpToken,
    }),
  }), env);

  const early = await submit();
  assert.equal(early.status, 500);
  assert.equal(cleanupCalls, 0);

  deadline = new Date(Date.now() - 1_000).toISOString();
  const complete = await submit();
  assert.equal(complete.status, 303);
  assert.equal(cleanupCalls, 1);
});

test("UUID restore rejects missing or wrong TOTP before provisioning or issuing a key", async () => {
  const sessionToken = "restore-step-up-session-token";
  const sessionHash = await sha256Hex(sessionToken);
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const trashItem = {
    id: "restore-step-up-trash-id",
    type: "uuid",
    deletedAt: "2026-07-21T00:00:00.000Z",
    invite: { uuid, username: "alice", apiConfigs: [], sub2apiSync: {} },
    records: [],
  };
  const values = new Map([
    [`session:${sessionHash}`, JSON.stringify(
      await boundAdminSession("restore-step-up-csrf", Date.now() + 60_000),
    )],
    ["invites", "[]"],
    ["trash", JSON.stringify([trashItem])],
  ]);
  let writes = 0;
  const store = {
    async get(key) { return values.get(key) ?? null; },
    async put() { writes += 1; },
    async delete() { writes += 1; },
  };
  const env = validAdminEnv(store);
  const counter = Math.floor(Date.now() / 1000 / 30);
  const acceptedCodes = new Set(await Promise.all([
    adminTest.totp(env.ADMIN_TOTP_SECRET, counter - 1),
    adminTest.totp(env.ADMIN_TOTP_SECRET, counter),
    adminTest.totp(env.ADMIN_TOTP_SECRET, counter + 1),
  ]));
  let wrongToken = "000000";
  while (acceptedCodes.has(wrongToken)) {
    wrongToken = String((Number(wrongToken) + 1) % 1_000_000).padStart(6, "0");
  }

  const originalFetch = globalThis.fetch;
  let externalCalls = 0;
  globalThis.fetch = async () => {
    externalCalls += 1;
    throw new Error("rejected restore must not provision Sub2API");
  };

  try {
    for (const stepUpToken of ["", wrongToken]) {
      const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
        method: "POST",
        headers: {
          cookie: `sub2api_allow_admin=${sessionToken}`,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          action: "restore_uuid",
          csrf: "restore-step-up-csrf",
          trash_id: trashItem.id,
          step_up_token: stepUpToken,
        }),
      }), env);
      const body = await response.text();

      assert.equal(response.status, 400);
      assert.match(body, /valid 2FA code/);
      assert.doesNotMatch(body, /One-time credentials|s2a_/);
    }
  } finally {
    globalThis.fetch = originalFetch;
  }

  assert.equal(externalCalls, 0);
  assert.equal(writes, 0);
  assert.equal(values.get("invites"), "[]");
  assert.equal(values.get("trash"), JSON.stringify([trashItem]));
});

test("create rejects an existing UUID before provisioning or KV writes", async () => {
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  let writes = 0;
  const env = validAdminEnv({
    async get(key) {
      return key === "invites" ? JSON.stringify([{ uuid, username: "alice" }]) : null;
    },
    async put() { writes += 1; },
    async delete() { writes += 1; },
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("duplicate UUID must not provision Sub2API");
  };
  try {
    await assert.rejects(
      adminTest.createInvite(env, uuid, {
        username: "changed",
        email: "changed@example.test",
        remark: "",
        apiConfigs: [],
      }),
      /UUID already exists/,
    );
    assert.equal(writes, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("UUID is immutable on updates before provisioning or KV writes", async () => {
  const originalUuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const changedUuid = "4c484f74-6d93-43d1-9441-00c7d8d4ab12";
  let writes = 0;
  const env = validAdminEnv({
    async get() { return null; },
    async put() { writes += 1; },
    async delete() { writes += 1; },
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("immutable UUID must not provision Sub2API");
  };
  try {
    await assert.rejects(
      adminTest.updateInvite(env, originalUuid, {
        uuid: changedUuid,
        username: "alice",
        email: "",
        remark: "",
        apiConfigs: [],
      }),
      /UUID is immutable/,
    );
    assert.equal(writes, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("invite updates reject missing TOTP before credential or KV writes", async () => {
  const token = "admin-session-token";
  const values = new Map([
    [`session:${await sha256Hex(token)}`, JSON.stringify(
      await boundAdminSession("csrf", Date.now() + 60_000),
    )],
  ]);
  let writes = 0;
  const store = {
    async get(key) { return values.get(key) ?? null; },
    async put() { writes += 1; },
    async delete() { writes += 1; },
  };
  const form = new URLSearchParams({
    action: "update_invite",
    csrf: "csrf",
    original_uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    username: "alice",
    api_configs: "OpenAI | https://api.example.test/v1 | sk-private",
  });
  const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
    method: "POST",
    headers: {
      Cookie: `sub2api_allow_admin=${token}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form,
  }), validAdminEnv(store));

  assert.equal(response.status, 400);
  assert.match(await response.text(), /valid 2FA code/);
  assert.equal(writes, 0);
});

test("adding an IP group checks CSRF before TOTP and blocks mutations without step-up", async () => {
  const token = "manual-ip-step-up-session";
  const csrf = "manual-ip-step-up-csrf";
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const values = new Map([
    [`session:${await sha256Hex(token)}`, JSON.stringify(
      await boundAdminSession(csrf, Date.now() + 60_000),
    )],
  ]);
  let writes = 0;
  const store = {
    async get(key) { return values.get(key) ?? null; },
    async put() { writes += 1; },
    async delete() { writes += 1; },
  };
  const env = validAdminEnv(store);
  const originalFetch = globalThis.fetch;
  let externalCalls = 0;
  globalThis.fetch = async () => {
    externalCalls += 1;
    throw new Error("step-up rejection must precede the Cloudflare mutation");
  };
  const submit = async (submittedCsrf, stepUpToken) => await worker.fetch(
    new Request("https://api.example.test/allow-ip/admin", {
      method: "POST",
      headers: {
        Cookie: `sub2api_allow_admin=${token}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        action: "add_ip_group",
        csrf: submittedCsrf,
        step_up_token: stepUpToken,
        uuid,
        ip_value: "198.51.100.8",
        expires_in_days: "7",
        expiration_mode: "days",
      }),
    }),
    env,
  );

  try {
    const csrfRejected = await submit("wrong-csrf", "000000");
    assert.equal(csrfRejected.status, 403);
    assert.equal(externalCalls, 0);
    assert.equal(writes, 0);

    const totpRejected = await submit(csrf, "");
    assert.equal(totpRejected.status, 400);
    assert.match(await totpRejected.text(), /valid 2FA code/);
    assert.equal(externalCalls, 0);
    assert.equal(writes, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Sub2API login reset is routed through TOTP and stores only encrypted credentials", async () => {
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const sessionToken = "password-reset-session-token";
  const values = new Map([
    [`session:${await sha256Hex(sessionToken)}`, JSON.stringify(
      await boundAdminSession("password-reset-csrf", Date.now() + 60_000),
    )],
    ["invites", JSON.stringify([{
      uuid,
      username: "alice",
      email: "alice@example.test",
      apiConfigs: [],
      sub2apiSync: { userId: 9, username: "alice", email: "alice@example.test" },
    }])],
    ["trash", "[]"],
  ]);
  const store = memoryKv(values);
  const env = validAdminEnv(store);
  const stepUpToken = await adminTest.totp(
    env.ADMIN_TOTP_SECRET,
    Math.floor(Date.now() / 1000 / 30),
  );
  const newPassword = "new-login-password-sentinel";
  const newApiKey = `sk-${"a".repeat(64)}`;
  const originalFetch = globalThis.fetch;
  let syncCalls = 0;
  globalThis.fetch = async (_url, init) => {
    syncCalls += 1;
    const requestBody = JSON.parse(init.body);
    assert.equal(requestBody.action, "provision");
    assert.equal(requestBody.resetLoginPassword, true);
    return Response.json({
      ok: true,
      action: "provision",
      uuid,
      username: "alice",
      email: "alice@example.test",
      userId: 9,
      apiKeyId: 11,
      tokenId: 11,
      apiKey: newApiKey,
      tokenKey: newApiKey,
      loginUrl: "https://api.example.test/login",
      loginPassword: newPassword,
      passwordHashFingerprint: "f".repeat(64),
      tokens: [{ tokenId: 11, apiKey: newApiKey, tokenKey: newApiKey, name: "Sub2API", status: 1 }],
      allowedGroups: ["openai-default"],
      baseUrl: "https://api.example.test/v1",
      syncedAt: new Date().toISOString(),
    });
  };

  try {
    const form = new URLSearchParams({
      action: "reset_sub2api_password",
      csrf: "password-reset-csrf",
      uuid,
      step_up_token: stepUpToken,
      admin_context: "p=1&t=1&i=1&v=e",
    });
    const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_admin=${sessionToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form,
    }), env);

    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), `/allow-ip/admin?edit=${uuid}`);
    assert.equal(syncCalls, 1);
    const serialized = values.get("invites");
    assert.doesNotMatch(serialized, new RegExp(newPassword));
    assert.doesNotMatch(serialized, new RegExp(newApiKey));
    const [stored] = JSON.parse(serialized);
    assert.equal(stored.sub2apiSync.loginPassword, undefined);
    assert.equal(stored.sub2apiSync.loginPasswordEncrypted.alg, "A256GCM");
    assert.equal(stored.apiConfigs[0].apiKey, undefined);
    assert.equal(stored.apiConfigs[0].apiKeyEncrypted.alg, "A256GCM");

    const adminPage = await worker.fetch(new Request(`https://api.example.test/allow-ip/admin?detail=${uuid}`, {
      headers: { cookie: `sub2api_allow_admin=${sessionToken}` },
    }), env);
    const html = await adminPage.text();
    assert.match(html, /name="action" value="reset_sub2api_password"/);
    assert.match(html, /aria-label="2FA code for login reset"/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Sub2API status refresh is explicit, CSRF protected, and limited to one invite", async () => {
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const sessionToken = "status-refresh-session-token";
  const values = new Map([
    [`session:${await sha256Hex(sessionToken)}`, JSON.stringify(
      await boundAdminSession("status-refresh-csrf", Date.now() + 60_000),
    )],
    ["invites", JSON.stringify([{
      uuid,
      username: "alice",
      email: "alice@example.test",
      apiConfigs: [],
      sub2apiSync: {
        userId: 9,
        username: "alice",
        email: "alice@example.test",
        passwordHashFingerprint: "a".repeat(64),
      },
    }])],
    ["trash", "[]"],
  ]);
  const env = validAdminEnv(memoryKv(values));
  const originalFetch = globalThis.fetch;
  let syncCalls = 0;
  globalThis.fetch = async (_url, init) => {
    syncCalls += 1;
    const requestBody = JSON.parse(init.body);
    assert.equal(requestBody.action, "status");
    assert.equal(requestBody.uuid, uuid);
    assert.equal(requestBody.sub2apiUserId, 9);
    return Response.json({
      ok: true,
      action: "status",
      exists: true,
      uuid,
      username: "alice",
      email: "alice@example.test",
      userId: 9,
      tokenId: 11,
      passwordHashFingerprint: "b".repeat(64),
      loginUrl: "https://api.example.test/login",
      baseUrl: "https://api.example.test/v1",
      syncedAt: new Date().toISOString(),
    });
  };

  try {
    const rejected = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_admin=${sessionToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        action: "refresh_sub2api_status",
        csrf: "wrong-csrf",
        uuid,
      }),
    }), env);
    assert.equal(rejected.status, 403);
    assert.equal(syncCalls, 0);

    const form = new URLSearchParams({
      action: "refresh_sub2api_status",
      csrf: "status-refresh-csrf",
      uuid,
      admin_context: "p=1&t=1&i=1&v=e",
    });
    const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_admin=${sessionToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: form,
    }), env);

    assert.equal(response.status, 303);
    assert.equal(response.headers.get("location"), `/allow-ip/admin?edit=${uuid}`);
    assert.equal(syncCalls, 1);
    const [stored] = JSON.parse(values.get("invites"));
    assert.equal(stored.sub2apiSync.passwordHashFingerprint, "b".repeat(64));
    assert.equal(stored.sub2apiSync.passwordChangedExternally, true);

    const adminPage = await worker.fetch(new Request(`https://api.example.test/allow-ip/admin?detail=${uuid}`, {
      headers: { cookie: `sub2api_allow_admin=${sessionToken}` },
    }), env);
    const html = await adminPage.text();
    assert.equal(syncCalls, 1);
    assert.match(html, /name="action" value="refresh_sub2api_status"/);
    assert.match(html, /Refresh Sub2API/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("legacy configured invite secrets cannot become internal UUID identities", async () => {
  assert.equal(await findInvite({
    INVITE_KEYS: "legacy-secret-value",
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
  }, "legacy-secret-value"), null);
});

test("TOTP step-up accepts the current code and rejects an invalid code", async () => {
  const originalNow = Date.now;
  const fixedNow = Date.parse("2026-07-19T12:00:00Z");
  Date.now = () => fixedNow;
  try {
    const secret = "JBSWY3DPEHPK3PXP";
    const token = await adminTest.totp(secret, Math.floor(fixedNow / 1000 / 30));
    assert.equal(await adminTest.verifyTotp(secret, token), true);
    const form = new FormData();
    form.set("step_up_token", token);
    await assert.doesNotReject(adminTest.requireStepUpTotp(form, { ADMIN_TOTP_SECRET: secret }));
    form.set("step_up_token", "000000");
    await assert.rejects(
      adminTest.requireStepUpTotp(form, { ADMIN_TOTP_SECRET: secret }),
      /valid 2FA code/,
    );
    assert.equal(await adminTest.verifyTotp("invalid-characters!", token), false);
  } finally {
    Date.now = originalNow;
  }
});

test("final Worker accepts only the canonical TOTP while staging Secrets remain", async () => {
  const originalNow = Date.now;
  const fixedNow = Date.parse("2026-07-23T12:00:00Z");
  Date.now = () => fixedNow;
  try {
    const counter = Math.floor(fixedNow / 1000 / 30);
    const canonicalCode = await adminTest.totp(TEST_ADMIN_TOTP_SECRET, counter);
    const temporaryCode = await adminTest.totp(TEST_NEXT_TOTP_SECRET, counter);
    assert.notEqual(canonicalCode, temporaryCode);
    const envWithStagingSecrets = {
      ADMIN_TOTP_SECRET: TEST_ADMIN_TOTP_SECRET,
      ADMIN_TOTP_SECRET_NEXT: TEST_NEXT_TOTP_SECRET,
      ADMIN_TOTP_ROTATION_PHASE: "stage",
    };

    assert.equal(await adminTest.verifyAdminTotp(envWithStagingSecrets, canonicalCode), true);
    assert.equal(await adminTest.verifyAdminTotp(envWithStagingSecrets, temporaryCode), false);

    const form = new FormData();
    form.set("step_up_token", temporaryCode);
    await assert.rejects(
      adminTest.requireStepUpTotp(form, envWithStagingSecrets),
      /valid 2FA code/,
    );
    form.set("step_up_token", canonicalCode);
    await assert.doesNotReject(adminTest.requireStepUpTotp(form, envWithStagingSecrets));
  } finally {
    Date.now = originalNow;
  }
});

test("administrator TOTP follows canonical secret replacement", async () => {
  const originalNow = Date.now;
  const fixedNow = Date.parse("2026-07-23T12:00:00Z");
  Date.now = () => fixedNow;
  try {
    const counter = Math.floor(fixedNow / 1000 / 30);
    const oldCode = await adminTest.totp(TEST_ADMIN_TOTP_SECRET, counter);
    const newCode = await adminTest.totp(TEST_NEXT_TOTP_SECRET, counter);
    const oldCanonical = { ADMIN_TOTP_SECRET: TEST_ADMIN_TOTP_SECRET };
    const newCanonicalWithStagingSecrets = {
      ADMIN_TOTP_SECRET: TEST_NEXT_TOTP_SECRET,
      ADMIN_TOTP_SECRET_NEXT: TEST_ADMIN_TOTP_SECRET,
      ADMIN_TOTP_ROTATION_PHASE: "promoted",
    };
    assert.equal(await adminTest.verifyAdminTotp(oldCanonical, oldCode), true);
    assert.equal(await adminTest.verifyAdminTotp(oldCanonical, newCode), false);
    assert.equal(await adminTest.verifyAdminTotp(newCanonicalWithStagingSecrets, oldCode), false);
    assert.equal(await adminTest.verifyAdminTotp(newCanonicalWithStagingSecrets, newCode), true);
  } finally {
    Date.now = originalNow;
  }
});

test("administrator TOTP configuration is canonical-only", () => {
  const canonical = { ADMIN_TOTP_SECRET: TEST_ADMIN_TOTP_SECRET };
  assert.deepEqual(adminTest.configuredAdminTotpSecrets(canonical), [TEST_ADMIN_TOTP_SECRET]);
  assert.deepEqual(
    adminTest.configuredAdminTotpSecrets({
      ...canonical,
      ADMIN_TOTP_SECRET_NEXT: TEST_NEXT_TOTP_SECRET,
      ADMIN_TOTP_ROTATION_PHASE: "stage",
    }),
    [TEST_ADMIN_TOTP_SECRET],
  );
});

test("administrator session binding changes when the canonical TOTP secret changes", async () => {
  const oldCanonical = await adminSessionTotpBinding(TEST_ADMIN_TOTP_SECRET);
  const newCanonical = await adminSessionTotpBinding(TEST_NEXT_TOTP_SECRET);

  assert.notEqual(oldCanonical, newCanonical);
});

test("administrator session binding is HMAC-keyed and rejects short keys", async () => {
  const binding = await adminTest.adminSessionTotpBinding(
    TEST_ADMIN_TOTP_SECRET,
    TEST_ADMIN_SESSION_BINDING_KEY,
  );
  const repeat = await adminTest.adminSessionTotpBinding(
    TEST_ADMIN_TOTP_SECRET,
    TEST_ADMIN_SESSION_BINDING_KEY,
  );
  const otherKey = await adminTest.adminSessionTotpBinding(
    TEST_ADMIN_TOTP_SECRET,
    "k".repeat(32),
  );

  assert.match(binding, /^[a-f0-9]{64}$/);
  assert.equal(binding, repeat);
  assert.notEqual(binding, otherKey);
  await assert.rejects(
    adminTest.adminSessionTotpBinding(
      TEST_ADMIN_TOTP_SECRET,
      "s".repeat(31),
    ),
    /INVITE_ACCESS_HMAC_KEY must be at least 32 characters/,
  );
});

test("temporary rotation Secrets do not invalidate canonical-bound sessions", async () => {
  const token = "prior-set-bound-session";
  const key = `session:${await sha256Hex(token)}`;
  const values = new Map([[
    key,
    JSON.stringify(await boundAdminSession("prior-set-csrf", Date.now() + 60_000)),
  ]]);
  const env = validAdminEnv(memoryKv(values));
  env.ADMIN_TOTP_SECRET_NEXT = TEST_NEXT_TOTP_SECRET;
  env.ADMIN_TOTP_ROTATION_PHASE = "stage";

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
    headers: { cookie: `sub2api_allow_admin=${token}` },
  }), env);

  assert.equal(response.status, 200);
  assert.match(await response.text(), /UUID Admin/);
  assert.equal(values.has(key), true);
});

test("admin login persists the canonical TOTP binding while temporary Secrets remain", async () => {
  const values = new Map();
  const env = validAdminEnv(memoryKv(values));
  env.ADMIN_TOTP_SECRET_NEXT = TEST_NEXT_TOTP_SECRET;
  env.ADMIN_TOTP_ROTATION_PHASE = "stage";
  env.ADMIN_PASSWORD_PBKDF2 = await pbkdf2PasswordRecord(
    "test-admin-password",
    100_000,
    new Uint8Array(16).fill(7),
  );
  const form = new FormData();
  form.set("username", env.ADMIN_USERNAME);
  form.set("password", "test-admin-password");
  form.set(
    "token",
    await adminTest.totp(env.ADMIN_TOTP_SECRET, Math.floor(Date.now() / 1000 / 30)),
  );

  const response = await adminTest.handleAdminLogin(
    form,
    env,
    new Request("https://api.example.test/allow-ip/admin", {
      headers: { "CF-Connecting-IP": "198.51.100.44" },
    }),
  );
  const persisted = [...values.entries()].find(([key]) => key.startsWith("session:"));

  assert.equal(response.status, 303);
  assert.ok(persisted);
  assert.match(persisted[0], /^session:[a-f0-9]{64}$/);
  assert.equal(
    JSON.parse(persisted[1]).totpBinding,
    await adminSessionTotpBinding(env.ADMIN_TOTP_SECRET),
  );
});

test("routine admin listing never decrypts stored credential envelopes", async () => {
  const token = "admin-session-token";
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const values = new Map([
    [`session:${await sha256Hex(token)}`, JSON.stringify(
      await boundAdminSession("csrf", Date.now() + 60_000),
    )],
    ["invites", JSON.stringify([{
      uuid,
      username: "alice",
      accessKeyHmac: "stored-hmac",
      apiConfigs: [{
        name: "OpenAI",
        baseUrl: "https://api.example.test/v1",
        apiKeyEncrypted: { v: 1, alg: "A256GCM", iv: "invalid", data: "invalid" },
      }],
      sub2apiSync: {
        loginUrl: "https://api.example.test/login",
        loginPasswordEncrypted: { v: 1, alg: "A256GCM", iv: "invalid", data: "invalid" },
      },
    }])],
    ["trash", "[]"],
    [`records:${uuid}`, "[]"],
  ]);
  const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
    headers: { Cookie: `sub2api_allow_admin=${token}` },
  }), validAdminEnv(memoryKv(values)));

  assert.equal(response.status, 200);
  const body = await response.text();
  assert.match(body, /1 endpoint/);
  assert.doesNotMatch(body, /A256GCM|invalid/);
  assert.doesNotMatch(body, /Access key migration/);
  assert.match(body, /Access key only/);
});

test("admin reports access-key migration state and legacy UUID time remaining", () => {
  const now = Date.parse("2026-07-19T00:00:00Z");
  assert.equal(adminTest.inviteCredentialStatus({}, now).state, "migration_required");
  assert.deepEqual(
    adminTest.inviteCredentialStatus({ accessKeyHmac: "hmac" }, now),
    { state: "access_key_only", className: "status-ok", label: "Access key only" },
  );
  assert.match(adminTest.inviteCredentialStatus({
    accessKeyHmac: "hmac",
    legacyUuidLoginUntil: "2026-07-26T00:00:00Z",
  }, now).label, /7 days remaining/);
  assert.equal(adminTest.inviteCredentialStatus({
    accessKeyHmac: "hmac",
    legacyUuidLoginUntil: "2026-07-18T23:59:59Z",
  }, now).state, "legacy_expired");
});

test("admin sessions without a finite expiry are deleted and rejected", async () => {
  const token = "malformed-admin-session-token";
  const key = `session:${await sha256Hex(token)}`;
  const values = new Map([
    [key, JSON.stringify({ csrf: "csrf", expiresAt: "not-a-timestamp" })],
  ]);
  const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
    headers: { cookie: `sub2api_allow_admin=${token}` },
  }), validAdminEnv(memoryKv(values)));

  assert.equal(response.status, 200);
  assert.match(await response.text(), /Admin sign in/);
  assert.equal(values.has(key), false);
});

test("credential migration permanently sanitizes legacy trash records", async () => {
  const token = "trash-migration-session-token";
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const deletedAt = "2026-07-18T00:00:00.000Z";
  const values = new Map([
    [`session:${await sha256Hex(token)}`, JSON.stringify(
      await boundAdminSession("csrf", Date.now() + 60_000),
    )],
    ["invites", "[]"],
    ["trash", JSON.stringify([{
      id: "legacy-trash-id",
      type: "uuid",
      deletedAt,
      futureTopLevelSecret: "top-level-secret-sentinel",
      invite: {
        uuid,
        username: "alice",
        email: "alice@example.test",
        apiConfigs: [{
          id: "api-1",
          name: "OpenAI",
          baseUrl: "https://api.example.test/v1",
          apiKey: "plain-api-key-sentinel",
          apiKeyEncrypted: { v: 1, alg: "A256GCM", iv: "iv", data: "ciphertext-sentinel" },
        }],
        sub2apiSync: {
          userId: 9,
          loginPassword: "plain-password-sentinel",
          loginPasswordEncrypted: { v: 1, alg: "A256GCM", iv: "iv", data: "password-ciphertext-sentinel" },
          passwordHash: "password-hash-sentinel",
        },
        futureCredentialEnvelope: "future-envelope-sentinel",
      },
      records: [{
        id: "network-record",
        addedAt: deletedAt,
        futureCredential: "record-secret-sentinel",
        ips: [{
          ip: "198.51.100.44",
          cidr: "198.51.100.0/24",
          listValue: "198.51.100.0/24",
          futureCredential: "ip-secret-sentinel",
        }],
      }],
    }, {
      id: "unknown-trash-id",
      type: "future_secret_record",
      credential: "unknown-type-secret-sentinel",
    }])],
  ]);
  const env = validAdminEnv(memoryKv(values));
  const stepUpToken = await adminTest.totp(
    env.ADMIN_TOTP_SECRET,
    Math.floor(Date.now() / 1000 / 30),
  );
  const form = new URLSearchParams({
    action: "migrate_invite_credentials",
    csrf: "csrf",
    step_up_token: stepUpToken,
  });

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
    method: "POST",
    headers: {
      cookie: `sub2api_allow_admin=${token}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: form,
  }), env);

  assert.equal(response.status, 200);
  const serialized = values.get("trash");
  assert.doesNotMatch(serialized, /secret-sentinel|ciphertext-sentinel|future-envelope|apiKey|loginPassword|passwordHash|A256GCM/i);
  const stored = JSON.parse(serialized);
  assert.equal(stored.length, 1);
  assert.equal(stored[0].id, "legacy-trash-id");
  assert.equal(stored[0].invite.uuid, uuid);
  assert.equal(stored[0].invite.deletedAt, deletedAt);
  assert.equal(stored[0].records[0].ips[0].listValue, "198.51.100.0/24");
});

test("credential migration issues bounded 25-account batches and reports the remainder", async () => {
  const token = "bounded-credential-migration-session";
  const csrf = "bounded-credential-migration-csrf";
  const invites = Array.from({ length: 30 }, (_, index) => ({
    uuid: `7c484f74-6d93-43d1-9441-${String(index + 1).padStart(12, "0")}`,
    username: `migration-user-${index + 1}`,
    credentialVersion: 1,
    accessCredentialVersion: 0,
    apiConfigs: [],
    sub2apiSync: {},
  }));
  const values = new Map([
    [`session:${await sha256Hex(token)}`, JSON.stringify(
      await boundAdminSession(csrf, Date.now() + 60_000),
    )],
    ["invites", JSON.stringify(invites)],
    ["trash", "[]"],
  ]);
  const env = validAdminEnv(memoryKv(values));
  const stepUpToken = await adminTest.totp(
    env.ADMIN_TOTP_SECRET,
    Math.floor(Date.now() / 1000 / 30),
  );
  const request = () => new Request("https://api.example.test/allow-ip/admin", {
    method: "POST",
    headers: {
      cookie: `sub2api_allow_admin=${token}`,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      action: "migrate_invite_credentials",
      csrf,
      step_up_token: stepUpToken,
    }),
  });

  const first = await worker.fetch(request(), env);
  const firstBody = await first.text();
  assert.equal(first.status, 200);
  assert.equal((firstBody.match(/<code>s2a_/g) || []).length, 25);
  assert.match(firstBody, /5 accounts remain/);
  assert.ok(new TextEncoder().encode(firstBody).byteLength < 256 * 1024);
  let stored = JSON.parse(values.get("invites"));
  assert.equal(stored.filter((invite) => invite.accessKeyHmac).length, 25);
  assert.equal(stored.filter((invite) => !invite.accessKeyHmac).length, 5);

  const second = await worker.fetch(request(), env);
  const secondBody = await second.text();
  assert.equal(second.status, 200);
  assert.equal((secondBody.match(/<code>s2a_/g) || []).length, 5);
  assert.doesNotMatch(secondBody, /accounts remain/);
  stored = JSON.parse(values.get("invites"));
  assert.equal(stored.every((invite) => invite.accessKeyHmac), true);
});

test("admin login rate limiting uses one Durable Object HMAC bucket per IP", async () => {
  const seenKeys = [];
  const env = {
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
    AUTH_RATE_LIMITER: observingRateLimiter(false, seenKeys),
    INVITE_STORE: {
      async get() { throw new Error("rate-limited login must not read KV"); },
      async put() {
        throw new Error("rate-limited login must not write");
      },
      async delete() {
        throw new Error("rate-limited login must not delete");
      },
    },
  };
  const form = new FormData();
  form.set("username", "private-admin");
  form.set("password", "not-evaluated");
  form.set("token", "000000");
  const response = await adminTest.handleAdminLogin(
    form,
    env,
    new Request("https://api.example.test/allow-ip/admin", {
      headers: { "CF-Connecting-IP": "198.51.100.44" },
    }),
  );

  assert.equal(response.status, 429);
  const alternateForm = new FormData();
  alternateForm.set("username", "different-admin-name");
  alternateForm.set("password", "not-evaluated");
  alternateForm.set("token", "000000");
  const alternateResponse = await adminTest.handleAdminLogin(
    alternateForm,
    env,
    new Request("https://api.example.test/allow-ip/admin", {
      headers: { "CF-Connecting-IP": "198.51.100.44" },
    }),
  );

  assert.equal(alternateResponse.status, 429);
  assert.equal(seenKeys.length, 2);
  assert.match(seenKeys[0], /^login-attempt:[a-f0-9]{64}$/);
  assert.equal(seenKeys[0], seenKeys[1]);
  assert.doesNotMatch(seenKeys[0], /private-admin|198\.51\.100\.44/);
});

test("TOTP step-up is rate-limited by an HMAC of the authenticated session", async () => {
  const sessionToken = "totp-rate-limit-session-token";
  const sessionHash = await sha256Hex(sessionToken);
  const values = new Map([
    [`session:${sessionHash}`, JSON.stringify(
      await boundAdminSession("totp-rate-limit-csrf", Date.now() + 60_000),
    )],
  ]);
  let kvWrites = 0;
  const store = memoryKv(values);
  const originalPut = store.put;
  store.put = async (...args) => {
    kvWrites += 1;
    return await originalPut(...args);
  };
  const seenKeys = [];
  const env = {
    ...validAdminEnv(store),
    AUTH_RATE_LIMITER: observingRateLimiter(false, seenKeys),
  };
  const originalFetch = globalThis.fetch;
  let externalCalls = 0;
  globalThis.fetch = async () => {
    externalCalls += 1;
    throw new Error("rate-limited TOTP must not call a sensitive upstream");
  };

  try {
    const makeRequest = (csrf) => worker.fetch(new Request("https://api.example.test/allow-ip/admin", {
      method: "POST",
      headers: {
        cookie: `sub2api_allow_admin=${sessionToken}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        action: "reset_sub2api_password",
        csrf,
        step_up_token: "not-evaluated",
        uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
      }),
    }), env);

    const csrfRejected = await makeRequest("wrong-csrf");
    assert.equal(csrfRejected.status, 403);
    assert.equal(seenKeys.length, 0);

    const rateLimited = await makeRequest("totp-rate-limit-csrf");
    assert.equal(rateLimited.status, 429);
    assert.equal(seenKeys.length, 1);
    assert.match(seenKeys[0], /^totp-attempt:[a-f0-9]{64}$/);
    assert.doesNotMatch(seenKeys[0], new RegExp(sessionToken));
    assert.doesNotMatch(seenKeys[0], new RegExp(sessionHash));
    assert.equal(kvWrites, 0);
    assert.equal(externalCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("public invite rate limiting runs after successful Turnstile verification", async () => {
  const seenKeys = [];
  const env = {
    ALLOWED_HOSTNAMES: "api.example.test",
    ACCOUNT_ID: "account",
    IP_LIST_ID: "list",
    TURNSTILE_SITE_KEY: "site",
    TURNSTILE_SECRET_KEY: "turnstile-secret",
    CLOUDFLARE_API_TOKEN: "cloudflare-token",
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
    AUTH_RATE_LIMITER: observingRateLimiter(false, seenKeys),
    INVITE_STORE: {
      async get() { throw new Error("rate-limited invite must not read KV"); },
      async put() {
        throw new Error("rate-limited invite must not write");
      },
      async delete() {
        throw new Error("rate-limited invite must not delete");
      },
    },
  };
  const originalFetch = globalThis.fetch;
  let turnstileCalls = 0;
  globalThis.fetch = async () => {
    turnstileCalls += 1;
    return Response.json({ success: true, hostname: "api.example.test" });
  };

  try {
    const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "CF-Connecting-IP": "198.51.100.44",
      },
      body: new URLSearchParams({ invite_key: "s2a_invalid" }),
    }), env);

    assert.equal(response.status, 429);
    assert.equal(turnstileCalls, 1);
    assert.equal(seenKeys.length, 1);
    assert.match(seenKeys[0], /^invite-attempt:[a-f0-9]{64}$/);
    assert.doesNotMatch(seenKeys[0], /198\.51\.100\.44/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("failed Turnstile verification cannot consume a public invite bucket", async () => {
  const seenKeys = [];
  const env = {
    ALLOWED_HOSTNAMES: "api.example.test",
    ACCOUNT_ID: "account",
    IP_LIST_ID: "list",
    TURNSTILE_SITE_KEY: "site",
    TURNSTILE_SECRET_KEY: "turnstile-secret",
    CLOUDFLARE_API_TOKEN: "cloudflare-token",
    INVITE_ACCESS_HMAC_KEY: "h".repeat(32),
    AUTH_RATE_LIMITER: observingRateLimiter(false, seenKeys),
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({
    success: false,
    hostname: "api.example.test",
  });

  try {
    const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "CF-Connecting-IP": "198.51.100.44",
      },
      body: new URLSearchParams({ invite_key: "s2a_invalid" }),
    }), env);

    assert.equal(response.status, 403);
    assert.equal(seenKeys.length, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("IPv4 authorization is explicitly described as a /24 network grant", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip"),
    { ALLOWED_HOSTNAMES: "api.example.test", TURNSTILE_SITE_KEY: "site" },
  );
  const body = await response.text();
  assert.match(body, /entire \/24 network/);
  assert.match(body, /Authorize current network/);
});

test("public sign-in labels UUID as temporary legacy compatibility", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip"),
    { ALLOWED_HOSTNAMES: "api.example.test", TURNSTILE_SITE_KEY: "site" },
  );
  const body = await response.text();
  assert.match(body, /Access key or legacy UUID/);
  assert.match(body, /temporary migration compatibility/);
  assert.doesNotMatch(body, />Access key or UUID</);
});

test("public Turnstile uses explicit rendering with a compact mobile breakpoint", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip"),
    { ALLOWED_HOSTNAMES: "api.example.test", TURNSTILE_SITE_KEY: "site" },
  );
  const body = await response.text();

  assert.match(body, /turnstile\.render\(/);
  assert.match(body, /window\.innerWidth < 372 \? "compact" : "flexible"/);
  assert.match(body, /api\.js\?render=explicit&amp;onload=onTurnstileLoad/);
  assert.match(
    body,
    /@media \(max-width: 240px\)[\s\S]*?\.turnstile-widget \{[\s\S]*?width: 130px;[\s\S]*?max-width: 100%;/,
  );
  assert.doesNotMatch(body, /data-sitekey=/);
});

test("public helper text meets AA contrast and long headings can wrap", async () => {
  const response = await worker.fetch(
    new Request("https://api.example.test/allow-ip"),
    { ALLOWED_HOSTNAMES: "api.example.test", TURNSTILE_SITE_KEY: "site" },
  );
  const body = await response.text();
  const ledeColor = body.match(/\.lede\s*{[^}]*color:\s*(#[0-9a-f]{6})/is)?.[1];

  assert.ok(ledeColor, "the helper-text color must be explicit");
  assert.ok(contrastRatio(ledeColor, "#f5f5f7") >= 4.5);
  assert.match(body, /h1\s*{[^}]*overflow-wrap:\s*anywhere/is);
  assert.match(body, /\.identity-title \{ overflow-wrap: anywhere; \}/);
  assert.match(
    body,
    /@media \(max-width: 560px\)[\s\S]*?\.identity-title \{ font-size: 24px; line-height: 1\.15; \}/,
  );
});

function validAdminEnv(store) {
  return {
    INVITE_STORE: store,
    AUTH_RATE_LIMITER: observingRateLimiter(true),
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

function observingRateLimiter(allowed, seenKeys = []) {
  return {
    getByName(key) {
      seenKeys.push(key);
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

async function adminSessionTotpBinding(canonicalSecret) {
  return await adminTest.adminSessionTotpBinding(
    canonicalSecret,
    TEST_ADMIN_SESSION_BINDING_KEY,
  );
}

async function boundAdminSession(csrf, expiresAt) {
  return {
    csrf,
    expiresAt,
    totpBinding: await adminSessionTotpBinding(TEST_ADMIN_TOTP_SECRET),
  };
}

function contrastRatio(foreground, background) {
  const values = [relativeLuminance(foreground), relativeLuminance(background)].sort((a, b) => b - a);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

function relativeLuminance(color) {
  const channels = color.slice(1).match(/.{2}/g).map((value) => Number.parseInt(value, 16) / 255);
  const linear = channels.map((value) => value <= 0.04045
    ? value / 12.92
    : ((value + 0.055) / 1.055) ** 2.4);
  return (0.2126 * linear[0]) + (0.7152 * linear[1]) + (0.0722 * linear[2]);
}
