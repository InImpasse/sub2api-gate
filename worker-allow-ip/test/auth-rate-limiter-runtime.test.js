import assert from "node:assert/strict";
import test from "node:test";

import { Miniflare } from "miniflare";

test("real Workers runtime serializes concurrent limiter RPC calls", { timeout: 30_000 }, async (t) => {
  const miniflare = new Miniflare({
    modules: true,
    scriptPath: new URL("../test-support/auth-rate-limiter-harness.js", import.meta.url).pathname,
    modulesRoot: new URL("..", import.meta.url).pathname,
    modulesRules: [{ type: "ESModule", include: ["**/*.js"] }],
    compatibilityDate: "2026-05-03",
    compatibilityFlags: ["nodejs_compat"],
    durableObjects: {
      AUTH_RATE_LIMITER: {
        className: "AuthRateLimiter",
        useSQLite: true,
      },
    },
  });
  t.after(async () => await miniflare.dispose());

  const consume = async (key) => {
    const response = await miniflare.dispatchFetch(
      `http://worker.test/consume?scope=admin&key=${encodeURIComponent(key)}`,
      { method: "POST" },
    );
    assert.equal(response.status, 200);
    return await response.json();
  };

  const firstBucket = await Promise.all(
    Array.from({ length: 20 }, () => consume("bucket-a")),
  );
  assert.equal(firstBucket.filter((result) => result.allowed).length, 5);
  assert.equal(firstBucket.filter((result) => !result.allowed).length, 15);

  const secondBucket = await Promise.all(
    Array.from({ length: 6 }, () => consume("bucket-b")),
  );
  assert.equal(secondBucket.filter((result) => result.allowed).length, 5);
  assert.equal(secondBucket.filter((result) => !result.allowed).length, 1);

  const reset = await miniflare.dispatchFetch(
    "http://worker.test/reset?scope=admin&key=bucket-a",
    { method: "POST" },
  );
  assert.deepEqual(await reset.json(), { ok: true });
  assert.equal((await consume("bucket-a")).allowed, true);
});
