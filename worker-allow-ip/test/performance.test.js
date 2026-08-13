import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";


test("public GET path does not synchronize Sub2API", async () => {
  const source = await readFile(new URL("../src/index.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /refreshInviteForDisplay/);
  assert.doesNotMatch(source, /refreshInviteFromSub2Api/);
  assert.match(source, /backdrop-filter: blur\(20px\) saturate\(180%\)/);
  assert.match(source, /background: rgba\(255, 255, 255, 0\.04\)/);
  assert.doesNotMatch(source, /gradient\(/);
  assert.doesNotMatch(source, /ambient-orb/);
  assert.match(source, /<p>\$\{escapeHtml\(message\)\}<\/p>/);
  assert.match(source, /button:focus-visible/);
  assert.match(source, /prefers-reduced-motion/);
});

test("admin GET path does not run full invite synchronization", async () => {
  const source = await readFile(new URL("../src/admin.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /refreshInvitesFromSub2Api/);
  assert.match(source, /const ADMIN_PAGE_SIZE = 25/);
  assert.match(source, /readAdminPage\(/);
  assert.match(source, /getAdminDashboard\(env, adminUrl\)/);
  assert.match(source, /ADMIN_IP_GROUP_PAGE_SIZE = 20/);
  assert.match(source, /ADMIN_LIST_HTML_MAX_BYTES = 96 \* 1024/);
  assert.match(source, /ADMIN_DETAIL_HTML_MAX_BYTES = 128 \* 1024/);
  assert.match(source, /ADMIN_EDIT_HTML_MAX_BYTES = 160 \* 1024/);
  assert.doesNotMatch(source, /hydrateAdminInvites/);
  assert.match(source, /ADMIN_RECORD_PAYLOAD_MAX_BYTES = 256 \* 1024/);
  assert.doesNotMatch(source, /getInvitesWithRecords/);
  assert.match(source, /AbortSignal\.timeout\(sub2apiSyncTimeoutForAction\(action\)\)/);
  assert.match(source, /SUB2API_SYNC_LOGIN_TIMEOUT_MS = 10_000/);
  assert.match(source, /fetchWithTimeout\(lookupUrl/);
  assert.match(source, /GEOIP_TIMEOUT_MS/);
  assert.match(source, /GEOIP_ALLOWED_HOSTNAMES/);
  assert.equal(source.match(/redirect: "manual"/g)?.length, 2);
  assert.doesNotMatch(source, /api\.ip\.sb/);
  assert.match(source, /summary:focus-visible/);
  assert.match(source, /prefers-reduced-motion/);
  assert.match(source, /backdrop-filter: blur\(20px\) saturate\(180%\)/);
  assert.match(source, /background: rgba\(255, 255, 255, 0\.04\)/);
  assert.doesNotMatch(source, /gradient\(/);
  assert.doesNotMatch(source, /ambient-orb/);
  assert.match(source, /view === "create" \|\| view === "edit"/);
  assert.match(source, /PENDING_LOGIN_TTL_SECONDS = 5 \* 60/);
  assert.match(source, /value="login_totp"/);
});

test("Worker runtime configuration enables current Node compatibility", async () => {
  const [config, secretManifestText] = await Promise.all([
    readFile(new URL("../wrangler.jsonc", import.meta.url), "utf8"),
    readFile(new URL("../required-secrets.json", import.meta.url), "utf8"),
  ]);
  const secretManifest = JSON.parse(secretManifestText);
  assert.match(config, /"main": "src\/worker-entry\.js"/);
  assert.match(config, /"compatibility_flags": \["nodejs_compat"\]/);
  assert.match(config, /"GEOIP_LOOKUP_URL": ""/);
  assert.match(config, /"GEOIP_ALLOWED_HOSTNAMES": ""/);
  assert.match(config, /"PROVIDER_ALLOWED_HOSTNAMES": ""/);
  assert.match(config, /"name": "AUTH_STATE"/);
  assert.match(config, /"class_name": "AuthState"/);
  assert.match(config, /"tag": "v2"/);
  assert.match(config, /"new_sqlite_classes": \["AuthState"\]/);
  assert.doesNotMatch(config, /"secrets"\s*:/);
  assert.deepEqual(secretManifest.required, [
    "TURNSTILE_SECRET_KEY",
    "CLOUDFLARE_API_TOKEN",
    "ADMIN_PASSWORD_PBKDF2",
    "ADMIN_TOTP_SECRET",
    "CREDENTIAL_ENCRYPTION_KEY",
    "INVITE_ACCESS_HMAC_KEY",
    "SUB2API_SYNC_SECRET",
  ]);
  for (const secret of secretManifest.required) {
    assert.doesNotMatch(config, new RegExp(`"${secret}"`));
  }
});

test("Worker production entry exports both RPC classes and fails closed without AUTH_STATE", async () => {
  const [source, authStateSource] = await Promise.all([
    readFile(new URL("../src/worker-entry.js", import.meta.url), "utf8"),
    readFile(new URL("../src/auth-state.js", import.meta.url), "utf8"),
  ]);
  assert.match(source, /import \{ DurableObject \} from "cloudflare:workers"/);
  assert.match(source, /class AuthRateLimiter extends DurableObject/);
  assert.match(source, /class AuthState extends DurableObject/);
  assert.match(source, /async getAdminPage\(inviteOffset, inviteLimit, trashOffset, trashLimit\)/);
  assert.match(source, /async runLegacyCleanup\(reason\)/);
  assert.match(source, /reason !== "explicit"/);
  assert.doesNotMatch(source, /await this\.runLegacyCleanup\("alarm"\)/);
  assert.match(source, /async alarm\(\) \{[\s\S]*inspectLegacySourceKeys/);
  assert.match(source, /authStateConsumeLegacyCleanupRecheck/);
  assert.match(source, /initializeAuthStateStorage\(ctx\.storage\)/);
  assert.match(source, /async consume\(scope\)/);
  assert.match(source, /async reset\(scope\)/);
  assert.match(source, /async alarm\(\)/);
  assert.match(source, /function failClosedIfAuthStateMissing\(env\)/);
  assert.match(source, /isAuthStateBindingConfigured\(env\)/);
  assert.match(source, /status: 503/);
  assert.match(source, /async fetch\(request, env, ctx\)/);
  assert.match(source, /return await worker\.fetch\(request, env, ctx\)/);
  assert.match(authStateSource, /length\(CAST\(payload AS BLOB\)\)/);
  assert.doesNotMatch(authStateSource, /CHECK \(length\(payload\)/);
  assert.match(authStateSource, /utf8ByteLength\(encoded\) > maxBytes/);
  assert.match(authStateSource, /utf8ByteLength\(raw\) > MAX_COLLECTION_BYTES/);
  assert.match(authStateSource, /utf8ByteLength\(raw\) > MAX_SESSION_BYTES/);
  assert.match(authStateSource, /AUTH_STATE_SCHEMA_VERSION = 4/);
  assert.match(authStateSource, /LEGACY_CLEANUP_RECHECKS = 2/);
  const adminPageSource = authStateSource
    .split("export function authStateGetAdminPage(", 2)[1]
    .split("\nexport function authStateGetInvite", 1)[0];
  assert.doesNotMatch(adminPageSource, /SELECT payload FROM invites/);
  assert.doesNotMatch(adminPageSource, /SELECT payload FROM trash/);
  assert.match(adminPageSource, /adminInviteSummaryFromRow/);
  assert.match(adminPageSource, /adminTrashSummaryFromRow/);
  assert.doesNotMatch(adminPageSource, /parseStoredInvite\(row\.payload\)/);
  assert.doesNotMatch(adminPageSource, /parseStoredTrash\(row\.payload\)/);
});

test("production routes never point at the sync service", async () => {
  const [source, stableSource, canarySource] = await Promise.all([
    readFile(new URL("../../nginx/sub2api.conf", import.meta.url), "utf8"),
    readFile(new URL("../../nginx/snippets/sub2api-upstream-stable.conf", import.meta.url), "utf8"),
    readFile(new URL("../../nginx/snippets/sub2api-upstream-canary.conf", import.meta.url), "utf8"),
  ]);
  const upstream = source.split("upstream sub2api_backend {")[1].split("}")[0];
  const v1 = source.split("location ^~ /v1/ {")[1].split("}")[0];
  assert.match(upstream, /include \/etc\/nginx\/snippets\/sub2api-upstream-active\.conf;/);
  assert.deepEqual(stableSource.trim(), "server 127.0.0.1:8080;");
  assert.deepEqual(canarySource.trim(), "server 127.0.0.1:8081;");
  assert.match(v1, /proxy_pass http:\/\/sub2api_backend;/);
  assert.doesNotMatch(v1, /3021|mirror/);
  assert.doesNotMatch(`${upstream}\n${stableSource}\n${canarySource}`, /3021|mirror/);
});
