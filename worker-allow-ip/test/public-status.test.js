import assert from "node:assert/strict";
import test from "node:test";

import worker, { getCurrentAllowStatus } from "../src/index.js";
import { protectInviteCredentials } from "../src/credential-security.js";


const UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
const AES_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const HMAC_KEY = "test-only-hmac-key-with-at-least-32-bytes";

function kvWithRecords(records) {
  const reads = [];
  return {
    reads,
    store: {
      async get(key) {
        reads.push(key);
        return JSON.stringify(records);
      },
    },
  };
}

test("allow status reads only the invite KV record for IPv4 and IPv6", async () => {
  const kv = kvWithRecords([{
    id: "group-1",
    addedAt: "2026-07-01T00:00:00.000Z",
    expiresAt: "2099-07-01T00:00:00.000Z",
    ips: [
      { ip: "203.0.113.42", cidr: "203.0.113.0/24", listValue: "203.0.113.0/24" },
      { ip: "2001:db8::42", cidr: "2001:db8::42/128", listValue: "2001:db8::42/128" },
    ],
  }]);
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    throw new Error("public status must not perform an external fetch");
  };

  try {
    const request = new Request("https://api.example.test/allow-ip", {
      headers: {
        "CF-Connecting-IP": "203.0.113.42",
        "CF-Connecting-IPv6": "2001:db8::42",
      },
    });
    const status = await getCurrentAllowStatus(
      { INVITE_STORE: kv.store },
      request,
      { uuid: UUID },
    );

    assert.equal(status.ok, true);
    assert.deepEqual(kv.reads, [`records:${UUID}`]);
    assert.deepEqual(status.ips.map((item) => item.alreadyListed), [true, true]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("allow status returns false for an IP absent from the invite KV record", async () => {
  const kv = kvWithRecords([]);
  const status = await getCurrentAllowStatus(
    { INVITE_STORE: kv.store },
    new Request("https://api.example.test/allow-ip", {
      headers: { "CF-Connecting-IP": "198.51.100.9" },
    }),
    { uuid: UUID },
  );

  assert.equal(status.ok, false);
  assert.equal(status.ips[0].listValue, "198.51.100.0/24");
  assert.equal(status.ips[0].alreadyListed, false);
  assert.deepEqual(kv.reads, [`records:${UUID}`]);
});

test("allow status rejects missing or pseudo client IPs without reading KV", async () => {
  const kv = kvWithRecords([]);
  const status = await getCurrentAllowStatus(
    { INVITE_STORE: kv.store },
    new Request("https://api.example.test/allow-ip", {
      headers: {
        "CF-Connecting-IP": "240.0.0.7",
        "CF-Pseudo-IPv4": "240.0.0.7",
      },
    }),
    { uuid: UUID },
  );

  assert.equal(status.ok, false);
  assert.deepEqual(status.ips, []);
  assert.match(status.error, /valid client IP/i);
  assert.deepEqual(kv.reads, []);
});

test("a v2 access-key session resolves the invite by internal UUID", async () => {
  const token = "session-token";
  const sessionKey = `uuid-session:${await sha256Hex(token)}`;
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    credentialVersion: 2,
    accessCredentialVersion: 3,
    accessKeyHmac: "not-an-internal-lookup-key",
    username: "alice",
  }, AES_KEY, HMAC_KEY);
  const values = new Map([
    ["invites", JSON.stringify([storedInvite])],
    [sessionKey, JSON.stringify({
      uuid: UUID,
      csrf: "csrf-token",
      authenticationMethod: "access_key",
      accessCredentialVersion: 3,
      expiresAt: Date.now() + 60_000,
    })],
    [`records:${UUID}`, "[]"],
  ]);

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
    headers: {
      Cookie: `sub2api_allow_uuid=${token}`,
      "CF-Connecting-IP": "198.51.100.9",
    },
  }), {
    INVITE_STORE: memoryKv(values),
    ALLOWED_HOSTNAMES: "api.example.test",
    CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
  });

  assert.equal(response.status, 200);
  assert.match(await response.text(), /UUID 7c484f74-6d93-43d1-9441-00c7d8d4ab11 is signed in/);
});

test("public session lookup uses AuthState while status still reads only records KV", async () => {
  const token = "auth-state-session-token";
  const sessionHash = await sha256Hex(token);
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    credentialVersion: 2,
    accessCredentialVersion: 3,
    accessKeyHmac: "a".repeat(64),
    username: "alice",
    apiConfigs: [],
    sub2apiSync: {},
  }, AES_KEY, HMAC_KEY);
  const reads = [];
  const stub = {
    async status() {
      return { migrated: true };
    },
    async getPublicSession(candidate) {
      assert.equal(candidate, sessionHash);
      return {
        session: {
          uuid: UUID,
          csrf: "csrf-token",
          authenticationMethod: "access_key",
          accessCredentialVersion: 3,
          expiresAt: Date.now() + 60_000,
        },
        invite: storedInvite,
      };
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
        reads.push(key);
        if (key === `records:${UUID}`) return "[]";
        throw new Error("legacy session KV must not be read");
      },
    },
    ALLOWED_HOSTNAMES: "api.example.test",
    CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
  };

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
    headers: {
      Cookie: `sub2api_allow_uuid=${token}`,
      "CF-Connecting-IP": "198.51.100.9",
    },
  }), env);

  assert.equal(response.status, 200);
  assert.match(await response.text(), /UUID 7c484f74-6d93-43d1-9441-00c7d8d4ab11 is signed in/);
  assert.deepEqual(reads, [`records:${UUID}`]);
});

test("a rejected AuthState public session expires the browser UUID cookie", async () => {
  const token = "rejected-auth-state-session";
  const sessionHash = await sha256Hex(token);
  const stub = {
    async status() {
      return { migrated: true };
    },
    async getPublicSession(candidate) {
      assert.equal(candidate, sessionHash);
      return null;
    },
  };

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
    headers: { Cookie: `sub2api_allow_uuid=${token}` },
  }), {
    AUTH_STATE: {
      getByName() {
        return stub;
      },
    },
    ALLOWED_HOSTNAMES: "api.example.test",
  });

  assert.equal(response.status, 200);
  assert.match(await response.text(), /Join the allowlist/);
  assert.match(response.headers.get("set-cookie") || "", /sub2api_allow_uuid=;[^\r\n]*Max-Age=0/);
});

test("rotating an access key invalidates sessions issued for the previous version", async () => {
  const token = "stale-session-token";
  const sessionKey = `uuid-session:${await sha256Hex(token)}`;
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    credentialVersion: 2,
    accessCredentialVersion: 4,
    accessKeyHmac: "new-key-hmac",
  }, AES_KEY, HMAC_KEY);
  const values = new Map([
    ["invites", JSON.stringify([storedInvite])],
    [sessionKey, JSON.stringify({
      uuid: UUID,
      csrf: "csrf-token",
      authenticationMethod: "access_key",
      accessCredentialVersion: 3,
      expiresAt: Date.now() + 60_000,
    })],
  ]);

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
    headers: { Cookie: `sub2api_allow_uuid=${token}` },
  }), {
    INVITE_STORE: memoryKv(values),
    ALLOWED_HOSTNAMES: "api.example.test",
    CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
  });

  assert.match(await response.text(), /Join the allowlist/);
  assert.match(response.headers.get("set-cookie") || "", /sub2api_allow_uuid=;[^\r\n]*Max-Age=0/);
});

test("legacy UUID sessions expire at the credential migration deadline", async () => {
  const token = "legacy-session-token";
  const sessionKey = `uuid-session:${await sha256Hex(token)}`;
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    credentialVersion: 2,
    accessCredentialVersion: 1,
    accessKeyHmac: "new-access-key-hmac",
    legacyUuidLoginUntil: new Date(Date.now() - 1_000).toISOString(),
  }, AES_KEY, HMAC_KEY);
  const values = new Map([
    ["invites", JSON.stringify([storedInvite])],
    [sessionKey, JSON.stringify({
      uuid: UUID,
      csrf: "csrf-token",
      expiresAt: Date.now() + 60_000,
    })],
  ]);

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
    headers: { Cookie: `sub2api_allow_uuid=${token}` },
  }), {
    INVITE_STORE: memoryKv(values),
    ALLOWED_HOSTNAMES: "api.example.test",
    CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
  });

  assert.match(await response.text(), /Join the allowlist/);
  assert.match(response.headers.get("set-cookie") || "", /sub2api_allow_uuid=;[^\r\n]*Max-Age=0/);
});

test("public sessions without a finite expiry are rejected", async () => {
  const token = "malformed-session-token";
  const sessionKey = `uuid-session:${await sha256Hex(token)}`;
  const values = new Map([
    [sessionKey, JSON.stringify({
      uuid: UUID,
      csrf: "csrf-token",
      authenticationMethod: "access_key",
      accessCredentialVersion: 1,
      expiresAt: "not-a-timestamp",
    })],
  ]);

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
    headers: { Cookie: `sub2api_allow_uuid=${token}` },
  }), {
    INVITE_STORE: memoryKv(values),
    ALLOWED_HOSTNAMES: "api.example.test",
  });

  assert.equal(response.status, 200);
  assert.match(await response.text(), /Join the allowlist/);
  assert.match(response.headers.get("set-cookie") || "", /sub2api_allow_uuid=;[^\r\n]*Max-Age=0/);
});

test("Sub2API auto-login rejects a cross-origin login URL before fetching a token", async () => {
  const token = "cross-origin-login-session";
  const sessionKey = `uuid-session:${await sha256Hex(token)}`;
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    credentialVersion: 2,
    accessCredentialVersion: 1,
    username: "alice",
    sub2apiSync: {
      userId: 17,
      username: "alice",
      email: "alice@example.test",
      loginPassword: "test-login-password",
      loginUrl: "https://other.example.test/login",
    },
  }, AES_KEY, HMAC_KEY);
  const values = new Map([
    ["invites", JSON.stringify([storedInvite])],
    [sessionKey, JSON.stringify({
      uuid: UUID,
      csrf: "csrf-token",
      authenticationMethod: "access_key",
      accessCredentialVersion: 1,
      expiresAt: Date.now() + 60_000,
    })],
  ]);
  const originalFetch = globalThis.fetch;
  let tokenFetches = 0;
  globalThis.fetch = async () => {
    tokenFetches += 1;
    return Response.json({
      ok: true,
      action: "login",
      auth: { access_token: "must-not-be-fetched" },
    });
  };

  try {
    const response = await worker.fetch(new Request("https://api.example.test/allow-ip/sub2api-login", {
      headers: { Cookie: `sub2api_allow_uuid=${token}` },
    }), {
      INVITE_STORE: memoryKv(values),
      ALLOWED_HOSTNAMES: "api.example.test,other.example.test",
      CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
      INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
      SUB2API_SYNC_URL: "https://api.example.test/_sub2api-sync/provision",
      SUB2API_SYNC_SECRET: "s".repeat(32),
    });

    assert.equal(response.status, 200);
    assert.equal(tokenFetches, 0);
    assert.match(await response.text(), /Sub2API login unavailable/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Sub2API auto-login fetches a token when the login URL has the request origin", async () => {
  const token = "same-origin-login-session";
  const sessionKey = `uuid-session:${await sha256Hex(token)}`;
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    credentialVersion: 2,
    accessCredentialVersion: 1,
    username: "alice",
    sub2apiSync: {
      userId: 17,
      username: "alice",
      email: "alice@example.test",
      loginPassword: "test-login-password",
      loginUrl: "https://api.example.test/login",
    },
  }, AES_KEY, HMAC_KEY);
  const values = new Map([
    ["invites", JSON.stringify([storedInvite])],
    [sessionKey, JSON.stringify({
      uuid: UUID,
      csrf: "csrf-token",
      authenticationMethod: "access_key",
      accessCredentialVersion: 1,
      expiresAt: Date.now() + 60_000,
    })],
  ]);
  const originalFetch = globalThis.fetch;
  let tokenFetches = 0;
  let loginPayload;
  globalThis.fetch = async (_url, init) => {
    tokenFetches += 1;
    loginPayload = JSON.parse(init.body);
    return Response.json({
      ok: true,
      action: "login",
      uuid: UUID,
      auth: { access_token: "same-origin-access-token" },
    });
  };

  try {
    const response = await worker.fetch(new Request("https://api.example.test/allow-ip/sub2api-login", {
      headers: { Cookie: `sub2api_allow_uuid=${token}` },
    }), {
      INVITE_STORE: memoryKv(values),
      ALLOWED_HOSTNAMES: "api.example.test",
      CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
      INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
      SUB2API_SYNC_URL: "https://api.example.test/_sub2api-sync/provision",
      SUB2API_SYNC_SECRET: "s".repeat(32),
    });
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.equal(tokenFetches, 1);
    assert.deepEqual(
      {
        action: loginPayload.action,
        uuid: loginPayload.uuid,
        username: loginPayload.username,
        sub2apiUserId: loginPayload.sub2apiUserId,
      },
      {
        action: "login",
        uuid: UUID,
        username: "alice",
        sub2apiUserId: 17,
      },
    );
    assert.match(body, /Signing in/);
    assert.match(body, /same-origin-access-token/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("an already-authorized dashboard does not load the Turnstile client", async () => {
  const token = "authorized-network-session";
  const sessionKey = `uuid-session:${await sha256Hex(token)}`;
  const storedInvite = await protectInviteCredentials({
    uuid: UUID,
    credentialVersion: 2,
    accessCredentialVersion: 1,
    username: "alice",
  }, AES_KEY, HMAC_KEY);
  const values = new Map([
    ["invites", JSON.stringify([storedInvite])],
    [sessionKey, JSON.stringify({
      uuid: UUID,
      csrf: "csrf-token",
      authenticationMethod: "access_key",
      accessCredentialVersion: 1,
      expiresAt: Date.now() + 60_000,
    })],
    [`records:${UUID}`, JSON.stringify([{
      id: "network-1",
      expiresAt: "2099-07-01T00:00:00.000Z",
      ips: [{ ip: "198.51.100.9", cidr: "198.51.100.0/24" }],
    }])],
  ]);

  const response = await worker.fetch(new Request("https://api.example.test/allow-ip", {
    headers: {
      Cookie: `sub2api_allow_uuid=${token}`,
      "CF-Connecting-IP": "198.51.100.9",
    },
  }), {
    INVITE_STORE: memoryKv(values),
    ALLOWED_HOSTNAMES: "api.example.test",
    CREDENTIAL_ENCRYPTION_KEY: AES_KEY,
    INVITE_ACCESS_HMAC_KEY: HMAC_KEY,
  });
  const body = await response.text();

  assert.match(body, /Current network authorization is active/);
  assert.doesNotMatch(body, /<script[^>]+src="https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js/);
  assert.doesNotMatch(body, /id="turnstile-widget"/);
});

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
