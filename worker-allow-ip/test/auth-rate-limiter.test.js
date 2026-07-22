import assert from "node:assert/strict";
import test from "node:test";

import {
  clearRateLimitStorage,
  consumeAuthAttempt,
  consumeRateLimitAttempt,
  handleRateLimitAlarm,
  resetAuthAttempts,
  resetRateLimitBucket,
} from "../src/auth-rate-limiter.js";

const VALID_KEY = `login-attempt:${"a".repeat(64)}`;

class SerialStorage {
  constructor() {
    this.values = new Map();
    this.tail = Promise.resolve();
    this.alarm = null;
    this.transactionCalls = 0;
  }

  transaction(callback) {
    this.transactionCalls += 1;
    const result = this.tail.then(() => callback(this));
    this.tail = result.catch(() => {});
    return result;
  }

  async get(key) {
    return this.values.get(key);
  }

  async put(key, value) {
    this.values.set(key, structuredClone(value));
  }

  async delete(key) {
    this.values.delete(key);
  }

  async setAlarm(timestamp) {
    this.alarm = Number(timestamp);
  }

  async deleteAlarm() {
    this.alarm = null;
  }

  async deleteAll() {
    this.values.clear();
  }
}

test("storage transaction atomically enforces the exact admin threshold", async () => {
  const storage = new SerialStorage();
  const now = 1_000_000;
  const results = await Promise.all(
    Array.from({ length: 20 }, () => consumeRateLimitAttempt(storage, "admin", now)),
  );

  assert.equal(results.filter((result) => result.allowed).length, 5);
  assert.equal(results.filter((result) => !result.allowed).length, 15);
  assert.deepEqual(storage.values.get("bucket"), {
    v: 1,
    count: 5,
    resetAt: now + 15 * 60 * 1000,
  });
});

test("expired buckets reset and denied attempts never extend their window", async () => {
  const storage = new SerialStorage();
  const now = 2_000_000;
  const accepted = await Promise.all(
    Array.from({ length: 5 }, () => consumeRateLimitAttempt(storage, "totp", now)),
  );
  const firstResetAt = accepted[0].resetAt;
  assert.equal(storage.alarm, firstResetAt);

  const denied = await consumeRateLimitAttempt(storage, "totp", now + 30_000);
  assert.equal(denied.allowed, false);
  assert.equal(denied.resetAt, firstResetAt);
  assert.equal(storage.alarm, firstResetAt);

  const afterExpiry = await consumeRateLimitAttempt(storage, "totp", firstResetAt);
  assert.equal(afterExpiry.allowed, true);
  assert.equal(afterExpiry.resetAt, firstResetAt + 15 * 60 * 1000);
  assert.equal(storage.values.get("bucket").count, 1);
});

test("reset and alarm cleanup remove both persisted state and scheduled alarms", async () => {
  const storage = new SerialStorage();
  await consumeRateLimitAttempt(storage, "invite", 3_000_000);
  assert.equal(storage.values.size, 1);
  assert.ok(storage.alarm);

  assert.deepEqual(await resetRateLimitBucket(storage, "invite"), { ok: true });
  assert.equal(storage.values.size, 0);
  assert.equal(storage.alarm, null);

  await consumeRateLimitAttempt(storage, "invite", 4_000_000);
  await clearRateLimitStorage(storage);
  assert.equal(storage.values.size, 0);
  assert.equal(storage.alarm, null);
});

test("alarm cancellation is best effort after the bucket is reset", async () => {
  const storage = new SerialStorage();
  await consumeRateLimitAttempt(storage, "invite", 4_500_000);
  const alarm = storage.alarm;
  storage.deleteAlarm = async () => {
    throw new Error("best-effort cancellation failed");
  };

  await assert.doesNotReject(clearRateLimitStorage(storage));
  assert.equal(storage.alarm, alarm);
  assert.equal(storage.values.size, 0);
  assert.deepEqual(await handleRateLimitAlarm(storage, alarm), { action: "empty" });
});

test("late and repeated alarms preserve a newer bucket and reschedule its expiry", async () => {
  const storage = new SerialStorage();
  const oldWindowStart = 5_000_000;
  const first = await consumeRateLimitAttempt(storage, "invite", oldWindowStart);
  const newer = await consumeRateLimitAttempt(storage, "invite", first.resetAt);

  const staleDelivery = await handleRateLimitAlarm(storage, first.resetAt);
  assert.deepEqual(staleDelivery, { action: "rescheduled", resetAt: newer.resetAt });
  assert.equal(storage.alarm, newer.resetAt);
  assert.equal(storage.values.get("bucket").count, 1);

  const duplicateDelivery = await handleRateLimitAlarm(storage, first.resetAt + 1);
  assert.deepEqual(duplicateDelivery, { action: "rescheduled", resetAt: newer.resetAt });
  assert.equal(storage.alarm, newer.resetAt);
  assert.equal(storage.values.get("bucket").count, 1);

  assert.deepEqual(
    await handleRateLimitAlarm(storage, newer.resetAt),
    { action: "deleted" },
  );
  assert.equal(storage.values.size, 0);
});

test("malformed or unknown persisted bucket versions fail closed", async () => {
  const malformed = [
    null,
    { count: 1, resetAt: 9_999_999 },
    { v: 2, count: 1, resetAt: 9_999_999 },
    { v: 1, count: "1", resetAt: 9_999_999 },
    { v: 1, count: -1, resetAt: 9_999_999 },
    { v: 1, count: 1, resetAt: "later" },
  ];
  for (const value of malformed) {
    const storage = new SerialStorage();
    storage.values.set("bucket", value);
    await assert.rejects(
      consumeRateLimitAttempt(storage, "admin", 5_000_000),
      /auth_rate_limiter_state_invalid/,
    );
    assert.equal(storage.values.get("bucket"), value);
  }
});

test("unknown scopes fail before any storage transaction", async () => {
  const storage = new SerialStorage();
  await assert.rejects(
    consumeRateLimitAttempt(storage, "unknown", 6_000_000),
    /auth_rate_limiter_scope_invalid/,
  );
  assert.equal(storage.transactionCalls, 0);
});

test("RPC client uses deterministic HMAC-only names and validates responses", async () => {
  const seen = [];
  const env = {
    AUTH_RATE_LIMITER: {
      getByName(name) {
        seen.push(name);
        return {
          async consume(scope) {
            assert.equal(scope, "admin");
            return { allowed: true, retryAfterSeconds: 0, resetAt: 7_000_000 };
          },
          async reset(scope) {
            assert.equal(scope, "admin");
            return { ok: true };
          },
        };
      },
    },
  };

  assert.equal(await consumeAuthAttempt(env, "admin", VALID_KEY), true);
  await assert.doesNotReject(resetAuthAttempts(env, "admin", VALID_KEY));
  assert.deepEqual(seen, [VALID_KEY, VALID_KEY]);
});

test("missing bindings, stub failures and malformed RPC results fail closed", async () => {
  await assert.rejects(
    consumeAuthAttempt({}, "admin", VALID_KEY),
    /auth_rate_limiter_unavailable/,
  );
  await assert.rejects(
    consumeAuthAttempt({
      AUTH_RATE_LIMITER: { getByName: () => ({}) },
    }, "admin", VALID_KEY),
    /auth_rate_limiter_unavailable/,
  );
  await assert.rejects(
    consumeAuthAttempt({
      AUTH_RATE_LIMITER: {
        getByName: () => ({
          async consume() {
            throw new Error("runtime detail must not escape");
          },
        }),
      },
    }, "admin", VALID_KEY),
    /auth_rate_limiter_request_failed/,
  );

  for (const result of [
    null,
    {},
    { allowed: "yes", retryAfterSeconds: 0, resetAt: 1 },
    { allowed: false, retryAfterSeconds: 0, resetAt: 1 },
    { allowed: true, retryAfterSeconds: 1, resetAt: 1 },
    { allowed: true, retryAfterSeconds: 0, resetAt: "later" },
  ]) {
    await assert.rejects(
      consumeAuthAttempt({
        AUTH_RATE_LIMITER: {
          getByName: () => ({ async consume() { return result; } }),
        },
      }, "admin", VALID_KEY),
      /auth_rate_limiter_invalid_response/,
    );
  }
});
