import assert from "node:assert/strict";
import test from "node:test";

import {
  isApprovedHostname,
  parseApprovedHostnames,
  parseApprovedHttpsUrl,
} from "../src/url-security.js";

test("runtime hostname allowlists reject local, IP-literal and malformed targets", () => {
  for (const hostname of [
    "127.0.0.1",
    "169.254.169.254",
    "[::1]",
    "localhost",
    "service.localhost",
    "service.local",
    "api.example.test.",
    "single-label",
    "api..example.test",
    "api_example.test",
    "2130706433",
  ]) {
    assert.equal(isApprovedHostname(hostname), false, hostname);
  }

  assert.equal(isApprovedHostname("api.example.test"), true);
  assert.equal(isApprovedHostname("xn--bcher-kva.example"), true);
  assert.deepEqual(
    parseApprovedHostnames("API.EXAMPLE.TEST,api.example.test"),
    ["api.example.test"],
  );
  assert.deepEqual(parseApprovedHostnames("api.example.test,127.0.0.1"), []);
});

test("approved HTTPS URLs reject non-default ports, credentials and URL decoration", () => {
  const allowed = "api.example.test";
  for (const value of [
    "http://api.example.test/v1",
    "https://user:password@api.example.test/v1",
    "https://api.example.test:8443/v1",
    "https://api.example.test/v1?target=internal",
    "https://api.example.test/v1#internal",
    "https://127.0.0.1/v1",
  ]) {
    assert.equal(parseApprovedHttpsUrl(value, allowed), null, value);
  }

  assert.equal(
    parseApprovedHttpsUrl("https://api.example.test:443/v1", allowed)?.href,
    "https://api.example.test/v1",
  );
  assert.equal(
    parseApprovedHttpsUrl(
      "https://api.example.test/geo?ip=192.0.2.1",
      allowed,
      { allowSearch: true },
    )?.hostname,
    "api.example.test",
  );
});
