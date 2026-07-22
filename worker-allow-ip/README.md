# Sub2API allow-ip Worker

This directory contains the Cloudflare Worker used for:

- the public `allow-ip` page
- the admin panel
- UUID-based access management
- Cloudflare Rules List writes
- syncing UUID users to the origin-side Sub2API provisioning service

Use the root documentation for the full deployment guide:

- Chinese: [../README.zh-CN.md](../README.zh-CN.md)
- English: [../README.md](../README.md)

## Quick Worker Notes

- `wrangler.jsonc` in this repository is a template and contains placeholder values
- set real secrets with `wrangler secret put ...`
- `ADMIN_TOTP_SECRET` must contain 16-128 Base32 characters without separators
- do not commit real account IDs, KV IDs, or Turnstile secrets
- initialize managed secrets through `deploy/generate-worker-secrets.py`; its
  operator-owned ignored HMAC migration file is consumed and removed only by the
  verified Cloudflare comment migration, never passed through argv or env
- `ALLOWED_HOSTNAMES` contains only public Worker/Sub2API hostnames;
  `PROVIDER_ALLOWED_HOSTNAMES` must contain at least one approved external API
  provider hostname in production. The two lists must not overlap, and real
  provider hostnames belong only in the ignored `wrangler.private.jsonc`. The
  tracked empty placeholder is intentionally rejected by preflight and runtime.
- `AUTH_STATE` is the authoritative SQLite Durable Object for invites, trash,
  admin sessions, and public sessions; `INVITE_STORE` remains only for
  `records:*` IP groups and a one-time lazy import of legacy auth keys
- third-party GeoIP is disabled by default; enable it only by setting both
  `GEOIP_LOOKUP_URL` (an HTTPS template with exactly one `{ip}` placeholder) and
  the separate `GEOIP_ALLOWED_HOSTNAMES` allowlist. Otherwise the Worker uses
  Cloudflare `request.cf` metadata and sends no visitor IP to another provider

Basic deploy flow:

```bash
cd worker-allow-ip
npm install
cp wrangler.jsonc wrangler.private.jsonc
chmod 600 wrangler.private.jsonc
# Fill only non-secret production bindings in the ignored private file.
npm run deploy:dry-run
# Run npm run deploy:apply only after explicit deployment approval.
```

The check/dry-run path does not publish a Worker and reports that remote Worker
Secrets have not been verified. The explicit apply path first lists secret names
from Cloudflare, suppresses that list, and fails before publishing when any
required name is missing. Secret values are never returned or printed.

## Local browser UI gate

The browser gate uses the exact pinned Playwright version and a local Miniflare
Worker. It uses only reserved test domains and sentinel credentials; it does not
contact production or mutate remote state.

```bash
cd worker-allow-ip
npm install
npx playwright install chromium
npm run test:browser-ui
```

The matrix covers `320x568`, `360x800`, `390x844`, `768x1024`, `1024x768`,
`1366x768`, and `1440x900` in light and dark themes. A separate 240 CSS pixel
case exercises the reflow produced by a 480 pixel viewport at 200% zoom. It
checks public form/dashboard rendering, Turnstile compact/flexible and
conditional loading, 25-invite admin summaries, 20 IP groups, Usage Inspector
list/detail layouts, long text, keyboard tabs/ARIA, contrast, horizontal
overflow, control overlap, HTML byte limits, and nonblank screenshot pixels.

Screenshots, the HTML report, and `metrics.json` are written under the ignored
`../.local/browser-ui-gate/` directory. PerformanceObserver values there are
local Playwright laboratory observations only. They are not field INP or a
Chrome DevTools Core Web Vitals acceptance, and they do not measure public
network TTFB. The release CWV gate remains incomplete until it is rerun with the
Chrome DevTools MCP trace workflow.

## Auth state integration contract

Use `createAuthStateStore(env)` from `src/auth-state.js`. Missing or invalid
`AUTH_STATE` bindings throw and the production entrypoint returns 503; callers
must never fall back to `INVITE_STORE` for authentication.

- `readInvites({ reveal: true })` returns `{ revision, items }`; write with
  `compareAndSwapInvites(revision, items)` or `upsertInvite(revision, invite)`.
- `readTrash()` returns its own revision. Delete/restore operations accept both
  revisions so invite and trash changes commit atomically.
- A CAS response with `conflict: true` requires a fresh read and an explicit
  retry or user-visible conflict. Never overwrite it with a stale full array.
- `create/get/deleteAdminSession` and `create/get/deletePublicSession` use only
  token hashes. Invite credential rotation and deletion revoke matching public
  sessions in the same SQLite transaction.
- The first `ready()` reads legacy `invites`, `trash`, `session:*`, and
  `uuid-session:*` KV keys, protects credentials, and atomically marks the
  import complete. Later KV changes are ignored. Legacy auth keys are not
  deleted automatically; any cleanup remains an explicit post-rollout action.

The AuthState object is a low-volume `/allow-ip` coordination boundary. It is
not referenced by Nginx or the `/v1/*` request path and cannot add Sub2API API
latency.
