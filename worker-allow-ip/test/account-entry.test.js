import assert from "node:assert/strict";
import test from "node:test";
import { __test } from "../src/index.js";

test("all accounts submit the session-bound automatic sign-in action", () => {
  const requestUrl = new URL("https://api.example.test/allow-ip");
  for (const sync of [
    {},
    { username: "fixture", loginUrl: "https://api.example.test/login" },
    { username: "fixture", loginPassword: "test-only-password" },
    { email: "fixture@example.test", loginPassword: "test-only-password", loginUrl: "https://api.example.test/login" },
    { username: "fixture", loginPassword: "test-only-password", loginUrl: "https://other.example.test/login" },
  ]) {
    const html = __test.renderSub2ApiLogin({ sub2apiSync: sync }, requestUrl, "csrf-fixture");
    assert.match(html, /Open Sub2API/);
    assert.match(html, /class="api-card account-card"/);
    assert.match(html, /method="post" action="\/allow-ip"/);
    assert.match(html, /name="action" value="open_sub2api"/);
    assert.match(html, /name="csrf" value="csrf-fixture"/);
    assert.doesNotMatch(html, /test-only-password|other\.example\.test/);
  }
});
