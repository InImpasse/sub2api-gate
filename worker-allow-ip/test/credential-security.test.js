import assert from "node:assert/strict";
import test from "node:test";

import {
  accessKeyHmac,
  cloudflareListComment,
  cloudflareListValueHmac,
  cloudflareMutationComment,
  decryptCredential,
  encryptCredential,
  generateAccessKey,
  hasInviteStorageSchema,
  issueInviteAccessCredential,
  matchesInviteAccess,
  pbkdf2PasswordRecord,
  protectInviteCredentials,
  rateLimitFingerprint,
  revealInviteCredentials,
  sanitizeInviteForTrash,
  timingSafeTextEqual,
  verifyPbkdf2Password,
} from "../src/credential-security.js";

const AES_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const HMAC_KEY = "test-only-hmac-key-with-at-least-32-bytes";

test("access credentials are random, hashed and AES-GCM encrypted", async () => {
  const accessKey = generateAccessKey();
  assert.match(accessKey, /^s2a_[A-Za-z0-9_-]{43}$/);
  assert.notEqual(await accessKeyHmac(HMAC_KEY, accessKey), accessKey);

  const encrypted = await encryptCredential(AES_KEY, "sk-private-sentinel", "test:api-key");
  assert.deepEqual(Object.keys(encrypted).sort(), ["alg", "data", "iv", "v"]);
  assert.doesNotMatch(JSON.stringify(encrypted), /private-sentinel/);
  assert.equal(await decryptCredential(AES_KEY, encrypted, "test:api-key"), "sk-private-sentinel");
  await assert.rejects(
    decryptCredential(AES_KEY, encrypted, "test:other-field"),
  );
  const replacement = encrypted.data.startsWith("A") ? "B" : "A";
  await assert.rejects(
    decryptCredential(
      AES_KEY,
      { ...encrypted, data: `${replacement}${encrypted.data.slice(1)}` },
      "test:api-key",
    ),
  );
});

test("credential envelopes require canonical base64url, a 96-bit IV and a full GCM tag", async () => {
  const encrypted = await encryptCredential(AES_KEY, "credential-sentinel", "test:credential");
  const invalid = [
    [{ ...encrypted, iv: `${encrypted.iv}=` }, /canonical unpadded base64url/],
    [{ ...encrypted, data: `${encrypted.data}=` }, /canonical unpadded base64url/],
    [{ ...encrypted, data: "AB" }, /canonical unpadded base64url/],
    [{ ...encrypted, iv: "AAAAAAAAAAAAAAA" }, /IV must contain 12 bytes/],
    [{ ...encrypted, data: "AAAAAAAAAAAAAAAAAAAA" }, /128-bit authentication tag/],
    [{ ...encrypted, keyId: "unexpected" }, /Unsupported credential envelope/],
  ];
  for (const [envelope, expected] of invalid) {
    await assert.rejects(decryptCredential(AES_KEY, envelope, "test:credential"), expected);
  }
  await assert.rejects(
    encryptCredential(`${AES_KEY}=`, "credential-sentinel", "test:credential"),
    /canonical unpadded base64url/,
  );
});

test("legacy v1 credential envelopes remain readable during migration", async () => {
  const rawKey = Uint8Array.from({ length: 32 }, (_value, index) => index);
  const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
  const iv = new Uint8Array(12).fill(7);
  const data = new Uint8Array(await crypto.subtle.encrypt({
    name: "AES-GCM",
    iv,
    additionalData: new TextEncoder().encode("sub2api-gate:credential:v1"),
    tagLength: 128,
  }, key, new TextEncoder().encode("legacy-secret")));
  const legacyEnvelope = {
    v: 1,
    alg: "A256GCM",
    iv: Buffer.from(iv).toString("base64url"),
    data: Buffer.from(data).toString("base64url"),
  };

  assert.equal(await decryptCredential(AES_KEY, legacyEnvelope), "legacy-secret");
});

test("invite credential envelopes cannot be transplanted across invites or fields", async () => {
  const first = await protectInviteCredentials({
    uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    apiConfigs: [{ id: "primary", name: "OpenAI", baseUrl: "https://api.example.com/v1", apiKey: "sk-first" }],
    sub2apiSync: { loginPassword: "password-first" },
  }, AES_KEY, HMAC_KEY);
  const second = await protectInviteCredentials({
    uuid: "9d1ff6de-fdfa-4f89-97b1-80d449be78b1",
    apiConfigs: [{ id: "primary", name: "OpenAI", baseUrl: "https://api.example.com/v1", apiKey: "sk-second" }],
    sub2apiSync: { loginPassword: "password-second" },
  }, AES_KEY, HMAC_KEY);

  await assert.rejects(revealInviteCredentials({
    ...second,
    apiConfigs: [{ ...second.apiConfigs[0], apiKeyEncrypted: first.apiConfigs[0].apiKeyEncrypted }],
  }, AES_KEY));
  await assert.rejects(revealInviteCredentials({
    ...first,
    sub2apiSync: {
      ...first.sub2apiSync,
      loginPasswordEncrypted: first.apiConfigs[0].apiKeyEncrypted,
    },
  }, AES_KEY));
});

test("invite v2 storage encrypts recoverable credentials and trash removes them", async () => {
  const invite = {
    uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    username: "alice",
    apiConfigs: [{ name: "OpenAI", baseUrl: "https://api.example.com/v1", apiKey: "sk-api-secret" }],
    sub2apiSync: { userId: 3, loginPassword: "login-secret", passwordHash: "bcrypt-secret" },
  };
  const stored = await protectInviteCredentials(invite, AES_KEY, HMAC_KEY);
  stored.futureCredentialEnvelope = { alg: "A256GCM", data: "future-ciphertext" };
  assert.equal(stored.storageVersion, 2);
  assert.doesNotMatch(JSON.stringify(stored), /sk-api-secret|login-secret|bcrypt-secret/);
  assert.equal(stored.apiConfigs[0].apiKey, undefined);
  assert.equal(stored.sub2apiSync.loginPassword, undefined);
  assert.equal(stored.sub2apiSync.passwordHash, undefined);

  const revealed = await revealInviteCredentials(stored, AES_KEY);
  assert.equal(revealed.apiConfigs[0].apiKey, "sk-api-secret");
  assert.equal(revealed.sub2apiSync.loginPassword, "login-secret");

  const trash = sanitizeInviteForTrash(stored);
  assert.doesNotMatch(JSON.stringify(trash), /Encrypted|cipher|A256GCM|apiKey|loginPassword/i);
  assert.equal(trash.futureCredentialEnvelope, undefined);
});

test("invite v2 storage drops unknown credential and content fields", async () => {
  const stored = await protectInviteCredentials({
    uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    username: "alice",
    remark: "approved metadata",
    refresh_token: "top-level-refresh-sentinel",
    prompt: "top-level-prompt-sentinel",
    request_body: "top-level-request-sentinel",
    apiConfigs: [{
      id: "primary",
      name: "OpenAI",
      baseUrl: "https://api.example.com/v1",
      apiKey: "sk-api-secret",
      futureCredential: "api-config-future-sentinel",
      content: "api-config-content-sentinel",
    }],
    sub2apiSync: {
      userId: 3,
      username: "alice",
      loginPassword: "login-secret",
      passwordHash: "bcrypt-secret",
      access_token: "sync-access-sentinel",
      refresh_token: "sync-refresh-sentinel",
      response_body: "sync-response-sentinel",
      futureCredential: "sync-future-sentinel",
    },
  }, AES_KEY, HMAC_KEY);

  assert.deepEqual(
    Object.keys(stored).sort(),
    ["apiConfigs", "remark", "storageVersion", "sub2apiSync", "username", "uuid"],
  );
  assert.deepEqual(
    Object.keys(stored.apiConfigs[0]).sort(),
    ["apiKeyEncrypted", "baseUrl", "id", "name"],
  );
  assert.deepEqual(
    Object.keys(stored.sub2apiSync).sort(),
    ["loginPasswordEncrypted", "passwordHashFingerprint", "userId", "username"],
  );
  assert.doesNotMatch(
    JSON.stringify(stored),
    /sentinel|prompt|content|request_body|response_body|access_token|refresh_token|futureCredential/,
  );
  const revealed = await revealInviteCredentials(stored, AES_KEY);
  assert.equal(revealed.apiConfigs[0].apiKey, "sk-api-secret");
  assert.equal(revealed.sub2apiSync.loginPassword, "login-secret");
});

test("invite storage schema validates credential envelopes and hash fingerprints", async () => {
  const encrypted = await encryptCredential(AES_KEY, "credential-sentinel", "test:schema");
  const valid = {
    uuid: "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
    accessKeyHmac: "a".repeat(64),
    apiConfigs: [{ id: "primary", apiKeyEncrypted: encrypted }],
    sub2apiSync: {
      loginPasswordEncrypted: { ...encrypted, v: 1 },
      passwordHashFingerprint: "b".repeat(64),
    },
  };
  assert.equal(hasInviteStorageSchema(valid), true);

  for (const invalid of [
    { ...valid, accessKeyHmac: "raw-access-key" },
    {
      ...valid,
      apiConfigs: [{ id: "primary", apiKeyEncrypted: { ...encrypted, content: "prompt" } }],
    },
    {
      ...valid,
      apiConfigs: [{ id: "primary", apiKeyEncrypted: { ...encrypted, iv: `${encrypted.iv}=` } }],
    },
    {
      ...valid,
      apiConfigs: [{ id: "primary", apiKeyEncrypted: { ...encrypted, data: "A".repeat(4000) } }],
    },
    {
      ...valid,
      sub2apiSync: { ...valid.sub2apiSync, passwordHashFingerprint: "raw-password-hash" },
    },
    {
      ...valid,
      sub2apiSync: {
        ...valid.sub2apiSync,
        loginPasswordEncrypted: { ...encrypted, refresh_token: "nested-refresh" },
      },
    },
  ]) {
    assert.equal(hasInviteStorageSchema(invalid), false);
  }
  await assert.rejects(
    encryptCredential(AES_KEY, "界".repeat(683), "test:oversized"),
    /Credential plaintext is too large/,
  );
});

test("new access keys replace UUID authentication after a seven day transition", async () => {
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const started = new Date("2026-07-19T00:00:00Z");
  const issued = await issueInviteAccessCredential({ uuid }, HMAC_KEY, started, true);
  assert.doesNotMatch(JSON.stringify(issued.invite), new RegExp(issued.accessKey));
  assert.equal(await matchesInviteAccess(issued.invite, issued.accessKey, HMAC_KEY, started), true);
  assert.equal(await matchesInviteAccess(issued.invite, uuid, HMAC_KEY, started), true);
  assert.equal(
    await matchesInviteAccess(issued.invite, uuid, HMAC_KEY, new Date("2026-07-26T00:00:01Z")),
    false,
  );

  const comment = await cloudflareListComment(HMAC_KEY, uuid);
  assert.match(comment, /^sub2api ref [a-f0-9]{32}$/);
  assert.doesNotMatch(comment, new RegExp(uuid));
});

test("invite matching accepts one precomputed HMAC across a stored-invite scan", async () => {
  const input = "s2a_precomputed";
  const candidateHmac = await accessKeyHmac(HMAC_KEY, input);
  assert.equal(await matchesInviteAccess({
    credentialVersion: 2,
    accessKeyHmac: candidateHmac,
  }, input, "deliberately-too-short", new Date(), candidateHmac), true);
});

test("rate-limit fingerprints are domain-separated and hide their source value", async () => {
  const ip = "198.51.100.44";
  const publicFingerprint = await rateLimitFingerprint(HMAC_KEY, "public-invite-ip", ip);
  const adminFingerprint = await rateLimitFingerprint(HMAC_KEY, "admin-login-ip", ip);
  assert.match(publicFingerprint, /^[a-f0-9]{64}$/);
  assert.notEqual(publicFingerprint, adminFingerprint);
  assert.doesNotMatch(publicFingerprint, /198\.51\.100\.44/);
});

test("Cloudflare mutation references and value fingerprints hide and separate inputs", async () => {
  const mutationId = "f".repeat(64);
  const value = "198.51.100.0/24";
  const comment = await cloudflareMutationComment(HMAC_KEY, mutationId);
  const valueHash = await cloudflareListValueHmac(HMAC_KEY, value);
  assert.match(comment, /^sub2api ref [a-f0-9]{32}$/);
  assert.match(valueHash, /^[a-f0-9]{64}$/);
  assert.doesNotMatch(comment, /198\.51\.100|ffff/);
  assert.doesNotMatch(valueHash, /198\.51\.100/);
  assert.notEqual(comment.slice(-32), valueHash.slice(0, 32));
});

test("unmigrated invites keep UUID access only until credentials are issued", async () => {
  const uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  assert.equal(await matchesInviteAccess({ uuid }, uuid, HMAC_KEY), true);
});

test("admin passwords use a salted PBKDF2 record and reject tampering", async () => {
  const record = await pbkdf2PasswordRecord(
    "correct horse battery staple",
    310_000,
    new Uint8Array(16).fill(7),
  );
  assert.match(record, /^pbkdf2_sha256\$310000\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  assert.equal(await verifyPbkdf2Password("correct horse battery staple", record), true);
  assert.equal(await verifyPbkdf2Password("wrong password", record), false);
  assert.equal(await verifyPbkdf2Password("correct horse battery staple", `${record}x`), false);
});

test("secret comparisons hash inputs before constant-time comparison", async () => {
  assert.equal(await timingSafeTextEqual("same", "same"), true);
  assert.equal(await timingSafeTextEqual("short", "a different length"), false);
});

test("secret comparisons use the Worker-native timingSafeEqual when available", async () => {
  const subtle = crypto.subtle;
  const original = subtle.timingSafeEqual;
  let calls = 0;
  Object.defineProperty(subtle, "timingSafeEqual", {
    configurable: true,
    value(left, right) {
      calls += 1;
      assert.equal(left.byteLength, 32);
      assert.equal(right.byteLength, 32);
      return left.every((byte, index) => byte === right[index]);
    },
  });
  try {
    assert.equal(await timingSafeTextEqual("native", "native"), true);
    assert.equal(await timingSafeTextEqual("native", "different"), false);
    assert.equal(calls, 2);
  } finally {
    if (original) {
      Object.defineProperty(subtle, "timingSafeEqual", { configurable: true, value: original });
    } else {
      delete subtle.timingSafeEqual;
    }
  }
});
