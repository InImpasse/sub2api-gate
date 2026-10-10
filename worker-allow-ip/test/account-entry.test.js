import assert from "node:assert/strict";
import test from "node:test";
import { __test } from "../src/index.js";

test("all accounts retain an entry, with automatic sign-in only when ready", () => {
  const requestUrl = new URL("https://api.example.test/allow-ip");
  for (const [sync, automatic] of [
    [{}, false],
    [{ username: "fixture", loginUrl: "https://api.example.test/login" }, false],
    [{ username: "fixture", loginPassword: "test-only-password" }, true],
    [{ email: "fixture@example.test", loginPassword: "test-only-password", loginUrl: "https://api.example.test/login" }, true],
    [{ username: "fixture", loginPassword: "test-only-password", loginUrl: "https://other.example.test/login" }, false],
  ]) {
    const html = __test.renderSub2ApiLogin({ sub2apiSync: sync }, requestUrl);
    assert.match(html, /Open Sub2API/);
    assert.match(html, /class="api-card account-card"/);
    assert.match(html, automatic ? /href="\/allow-ip\/sub2api-login"/ : /href="https:\/\/api.example.test\/login"/);
    assert.equal(html.includes("Automatic sign-in is unavailable"), !automatic);
    assert.doesNotMatch(html, /test-only-password|other\.example\.test/);
  }
});
