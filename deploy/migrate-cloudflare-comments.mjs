#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { cloudflareApiFetch, listCloudflareItems, readCloudflareJson, waitForCloudflareOperation } from "../worker-allow-ip/src/cloudflare-client.js";
import {
  assertCloudflareListSnapshot,
  assertCloudflareReplacement,
  buildCloudflareCommentReplacement,
  countLegacyCloudflareComments,
} from "../worker-allow-ip/src/cloudflare-comment-migration.js";
import {
  destroyPrivateHmacState,
  readPrivateHmacState,
} from "./private-worker-secret-state.mjs";

const mode = process.argv[2] || "check";
if (!["check", "--apply"].includes(mode)) {
  console.error("usage: migrate-cloudflare-comments.mjs [check|--apply]");
  process.exit(2);
}
if (mode === "--apply") {
  execFileSync(
    fileURLToPath(new URL("./require-clean-worktree.sh", import.meta.url)),
    ["check"],
    { stdio: "inherit" },
  );
  if (!process.stdin.isTTY) {
    console.error("cloudflare_comment_apply_requires_private_tty");
    process.exit(2);
  }
}

if (mode === "check") {
  const syntheticUuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11";
  const syntheticItems = [
    {
      id: "legacy",
      ip: "198.51.100.0/24",
      comment: `sub2api uuid ${syntheticUuid} raw 198.51.100.8`,
    },
    {
      id: "managed",
      ip: "2001:db8::1/128",
      comment: "sub2api ref 0123456789abcdef0123456789abcdef",
    },
    {
      id: "unmanaged",
      ip: "203.0.113.0/24",
      comment: "manual operations entry",
    },
  ];
  const syntheticKey = "sub2api-gate-offline-comment-check-v1";
  const replacement = await buildCloudflareCommentReplacement(
    syntheticItems,
    syntheticKey,
  );
  if (
    replacement.legacyCount !== 1
    || replacement.items.length !== syntheticItems.length
    || replacement.items[0].comment.includes(syntheticUuid)
    || !/^sub2api ref [a-f0-9]{32}$/.test(replacement.items[0].comment)
    || replacement.items[1].comment !== syntheticItems[1].comment
    || replacement.items[2].comment !== syntheticItems[2].comment
  ) {
    throw new Error("cloudflare_comment_offline_check_failed");
  }
  console.log(JSON.stringify({ mode: "check", syntheticItems: syntheticItems.length }));
  process.exit(0);
}

const env = {
  ACCOUNT_ID: process.env.CLOUDFLARE_ACCOUNT_ID || "",
  IP_LIST_ID: process.env.CLOUDFLARE_IP_LIST_ID || "",
  CLOUDFLARE_API_TOKEN: process.env.CLOUDFLARE_API_TOKEN || "",
};
if (!env.ACCOUNT_ID || !env.IP_LIST_ID || !env.CLOUDFLARE_API_TOKEN) {
  console.error("required Cloudflare credentials are missing");
  process.exit(2);
}

const result = await listCloudflareItems(env);
if (!result.ok) throw new Error("cloudflare_list_lookup_failed");
const legacyCount = countLegacyCloudflareComments(result.items);
const repoDir = fileURLToPath(new URL("../", import.meta.url));
const statePath = join(
  repoDir,
  ".local",
  "worker-secret-state",
  "invite-access-hmac-migration.key",
);
const operatorUid = process.getuid?.();
if (!Number.isInteger(operatorUid)) {
  console.error("cloudflare_comment_operator_identity_unavailable");
  process.exit(2);
}
const state = readPrivateHmacState(statePath, {
  expectedUid: operatorUid,
  missingOk: legacyCount === 0,
});

console.log(JSON.stringify({ mode, scanned: result.items.length, legacyComments: legacyCount }));
if (legacyCount === 0) {
  if (state) destroyPrivateHmacState(statePath, state, { expectedUid: operatorUid });
  console.log(JSON.stringify({ mode: "verified", updated: 0, stateDestroyed: Boolean(state) }));
  process.exit(0);
}
const replacement = await buildCloudflareCommentReplacement(result.items, state.hmacKey);

const confirmed = await listCloudflareItems(env);
if (!confirmed.ok) throw new Error("cloudflare_list_confirmation_failed");
assertCloudflareListSnapshot(result.items, confirmed.items);

const response = await cloudflareApiFetch(
  env,
  `/rules/lists/${env.IP_LIST_ID}/items`,
  { method: "PUT", body: JSON.stringify(replacement.items) },
);
const payload = await readCloudflareJson(response);
if (!response.ok || payload.success !== true) throw new Error("cloudflare_comment_update_failed");
await waitForCloudflareOperation(env, payload);

const verified = await listCloudflareItems(env);
if (!verified.ok) throw new Error("cloudflare_list_verification_failed");
assertCloudflareReplacement(replacement.items, verified.items);
destroyPrivateHmacState(statePath, state, { expectedUid: operatorUid });
console.log(JSON.stringify({ mode: "applied", updated: replacement.legacyCount, stateDestroyed: true }));
