const BUCKET_VERSION = 1;
const BUCKET_KEY = "bucket";

const POLICIES = Object.freeze({
  admin: Object.freeze({ limit: 5, windowSeconds: 15 * 60 }),
  invite: Object.freeze({ limit: 10, windowSeconds: 15 * 60 }),
  totp: Object.freeze({ limit: 5, windowSeconds: 15 * 60 }),
  keytest: Object.freeze({ limit: 8, windowSeconds: 15 * 60 }),
});

export async function consumeRateLimitAttempt(storage, scope, now = Date.now()) {
  const policy = requirePolicy(scope);
  requireStorageMethod(storage, "transaction");
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new Error("auth_rate_limiter_clock_invalid");
  }

  return await storage.transaction(async (transaction) => {
    requireStorageMethod(transaction, "get");
    requireStorageMethod(transaction, "put");
    requireStorageMethod(transaction, "setAlarm");

    const stored = await transaction.get(BUCKET_KEY);
    const current = normalizeBucket(stored, now, policy.windowSeconds);
    if (current.count >= policy.limit) {
      return {
        allowed: false,
        retryAfterSeconds: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
        resetAt: current.resetAt,
      };
    }

    const next = {
      v: BUCKET_VERSION,
      count: current.count + 1,
      resetAt: current.resetAt,
    };
    await transaction.put(BUCKET_KEY, next);
    await transaction.setAlarm(next.resetAt);
    return {
      allowed: true,
      retryAfterSeconds: 0,
      resetAt: next.resetAt,
    };
  });
}

export async function resetRateLimitBucket(storage, scope) {
  requirePolicy(scope);
  await clearRateLimitStorage(storage);
  return { ok: true };
}

export async function clearRateLimitStorage(storage) {
  requireStorageMethod(storage, "deleteAlarm");
  requireStorageMethod(storage, "deleteAll");
  await storage.deleteAll();
  try {
    await storage.deleteAlarm();
  } catch {
    // Alarm cancellation is best effort. A late delivery is made harmless below.
  }
}

export async function handleRateLimitAlarm(storage, now = Date.now()) {
  if (!Number.isSafeInteger(now) || now < 0) {
    throw new Error("auth_rate_limiter_clock_invalid");
  }
  requireStorageMethod(storage, "transaction");

  return await storage.transaction(async (transaction) => {
    requireStorageMethod(transaction, "get");
    requireStorageMethod(transaction, "delete");
    requireStorageMethod(transaction, "setAlarm");

    const stored = await transaction.get(BUCKET_KEY);
    if (stored === undefined) return { action: "empty" };
    const bucket = validateBucket(stored);
    if (bucket.resetAt > now) {
      await transaction.setAlarm(bucket.resetAt);
      return { action: "rescheduled", resetAt: bucket.resetAt };
    }
    await transaction.delete(BUCKET_KEY);
    return { action: "deleted" };
  });
}

function normalizeBucket(value, now, windowSeconds) {
  if (value === undefined) {
    return freshBucket(now, windowSeconds);
  }
  const bucket = validateBucket(value);
  if (bucket.resetAt <= now) {
    return freshBucket(now, windowSeconds);
  }
  return bucket;
}

function validateBucket(value) {
  if (
    !value
    || typeof value !== "object"
    || Array.isArray(value)
    || value.v !== BUCKET_VERSION
    || !Number.isSafeInteger(value.count)
    || value.count < 0
    || !Number.isSafeInteger(value.resetAt)
    || value.resetAt < 0
  ) {
    throw new Error("auth_rate_limiter_state_invalid");
  }
  return {
    v: BUCKET_VERSION,
    count: value.count,
    resetAt: value.resetAt,
  };
}

function freshBucket(now, windowSeconds) {
  return {
    v: BUCKET_VERSION,
    count: 0,
    resetAt: now + windowSeconds * 1000,
  };
}

function requirePolicy(scope) {
  if (!Object.hasOwn(POLICIES, scope)) {
    throw new Error("auth_rate_limiter_scope_invalid");
  }
  return POLICIES[scope];
}

function requireStorageMethod(storage, method) {
  if (!storage || typeof storage[method] !== "function") {
    throw new Error("auth_rate_limiter_storage_invalid");
  }
}

export async function consumeAuthAttempt(env, scope, key) {
  const result = await callLimiter(env, "consume", scope, key);
  if (
    !result
    || typeof result !== "object"
    || Array.isArray(result)
    || typeof result.allowed !== "boolean"
    || !Number.isSafeInteger(result.retryAfterSeconds)
    || result.retryAfterSeconds < (result.allowed ? 0 : 1)
    || (result.allowed && result.retryAfterSeconds !== 0)
    || !Number.isSafeInteger(result.resetAt)
    || result.resetAt < 0
  ) {
    throw new Error("auth_rate_limiter_invalid_response");
  }
  return result.allowed;
}

export async function resetAuthAttempts(env, scope, key) {
  const result = await callLimiter(env, "reset", scope, key);
  if (
    !result
    || typeof result !== "object"
    || Array.isArray(result)
    || result.ok !== true
  ) {
    throw new Error("auth_rate_limiter_invalid_response");
  }
}

async function callLimiter(env, action, scope, key) {
  requirePolicy(scope);
  const namespace = env?.AUTH_RATE_LIMITER;
  if (!namespace || typeof namespace.getByName !== "function") {
    throw new Error("auth_rate_limiter_unavailable");
  }

  const normalizedKey = String(key || "");
  if (!/^[a-z-]+:[a-f0-9]{64}$/.test(normalizedKey)) {
    throw new Error("auth_rate_limiter_key_invalid");
  }

  let stub;
  try {
    stub = namespace.getByName(normalizedKey);
  } catch {
    throw new Error("auth_rate_limiter_unavailable");
  }
  if (!stub || typeof stub[action] !== "function") {
    throw new Error("auth_rate_limiter_unavailable");
  }

  try {
    return await stub[action](scope);
  } catch {
    throw new Error("auth_rate_limiter_request_failed");
  }
}

export const __test = Object.freeze({
  BUCKET_VERSION,
  POLICIES,
  normalizeBucket,
  validateBucket,
});
