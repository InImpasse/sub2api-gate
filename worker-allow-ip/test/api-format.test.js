import assert from "node:assert/strict";
import test from "node:test";
import { __test } from "../src/index.js";

test("API examples use the key group protocol and support legacy Claude labels", () => {
  for (const [name, groupName, anthropic] of [
    ["Claude", "anthropic-default", true],
    ["Claude", "", true],
    ["Claude", "openai-default", false],
    ["GPT", "", false],
  ]) {
    const html = __test.renderApiConfig({
      name, groupName, baseUrl: "https://api.example.test/v1/", apiKey: "sk-test-sentinel",
    });
    if (anthropic) {
      assert.match(html, /Claude \/ Anthropic Messages format/);
      assert.match(html, /\/v1\/messages/);
      assert.match(html, /x-api-key: sk-test-sentinel/);
      assert.match(html, /anthropic-version: 2023-06-01/);
      assert.doesNotMatch(html, /chat\/completions/);
    } else {
      assert.match(html, /OpenAI format/);
      assert.match(html, /\/v1\/chat\/completions/);
      assert.doesNotMatch(html, /anthropic-version/);
    }
    assert.doesNotMatch(html, /\/v1\/\//);
    assert.match(html, />curl [^<]*sk-\*+/);
  }
});
