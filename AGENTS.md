# AGENTS.md

## Project Memory
- The repository contains a static demo at `demo/index.html`, a Cloudflare Worker under `worker-allow-ip/`, and an origin-side provisioning sync service under `sub2api-sync/`.
- The user explicitly approved production redeployment on 2026-07-22. Continue only through the documented staged gates; never echo credentials or bypass private-TTY API-key/TOTP checks.
- Conversation request/response content must never be persisted. Token, cost, model, status, latency, endpoint, and request-ID metadata may remain.
- IPv4 `/24` authorization is an intentional business rule and must remain explicit in the UI and confirmation text.

## Recent Decisions
- `/v1/*` stays a direct Nginx proxy through the named `sub2api_backend` upstream. Its reviewed active include points to stable `127.0.0.1:8080` before cutover and canary `127.0.0.1:8081` after the atomic switch; there is no mirror, gateway relay, capture endpoint, or response-body log on the request path.
- The admin usage view exposes only bounded usage metadata: request ID, model, token counts, cost, status/type, endpoint, timing, stream flag, and timestamp. It never reads or renders conversation bodies.
- Public allow-status GETs read the invite's KV IP records and do not call Cloudflare Rules List APIs. Cloudflare API calls remain only on explicit allowlist mutations and maintenance actions.
- The ignored `worker-allow-ip/wrangler.private.jsonc` holds local non-secret Cloudflare bindings. The tracked `wrangler.jsonc` contains placeholders only; Worker secrets stay in Cloudflare Secrets.
- Invite v2 records use one-time 32-byte access keys stored as HMAC, AES-256-GCM credential envelopes, PBKDF2 admin passwords, and a seven-day legacy UUID transition. Cloudflare List comments contain only domain-separated HMAC references.
- Invite v2 persistence is an explicit field allowlist at both the credential-protection and AuthState RPC boundaries. Unknown top-level, API-config, and sync fields are dropped during legacy KV migration and rejected by direct Durable Object writes, so future credential or content fields cannot be retained accidentally.
- Public invite rate-limit identities use domain-separated HMAC fingerprints instead of raw client IPs. Invite lookup computes the submitted v2 access-key HMAC once per request and reuses it across the stored-invite scan.
- Authentication throttling uses a SQLite-backed `AuthRateLimiter` Durable Object with RPC and alarm cleanup: admin login and TOTP step-up allow five attempts per 15 minutes, public invite lookup allows ten, and public attempts are counted only after Turnstile succeeds. Durable Object names contain only domain-separated HMAC fingerprints.
- Sub2API status refresh is available only as an explicit, CSRF-protected single-invite admin action. The unused batch refresh implementation was removed so admin GET requests cannot add sync or Sub2API load.
- The sync boundary accepts only canonical RFC 4122 UUID text and non-empty supported API keys. Its internal Sub2API login response is capped at 64 KiB even when the upstream omits Content-Length.
- Cloudflare API calls accept only validated account/list identifiers and the exact Rules Lists item/bulk-operation path shapes. Fixed authorization headers cannot be overridden by callers.
- `migrations/002_remove_conversation_capture.sql` removes custom capture columns and installs triggers that blank audit, prompt-audit, moderation, ops error (including real-schema request/response headers and bodies), and system-log content while retaining usage/classification metadata. Content-type discovery recursively resolves domains and arrays and rejects content-capable user schemas outside `public`.
- `migrations/002_scrub_conversation_history.sql` never skips locked history rows; it waits or fails so an advancing cursor cannot leave content behind. `migrations/verify_no_conversation_content.sql` applies the same domain, array, XML, `bytea`, JSON, text, and non-`public` schema boundary. `payment_audit_logs.detail` is an explicit non-conversation financial reconciliation exception; `idempotency_records.response_body` remains a backend-only exception and is protected by an architecture test.
- `migrations/001_default_to_openai_default.sql` migrates references from the exact `default` group to `openai-default`, validates remaining foreign-key references, and deactivates the source group transactionally. It has not been executed.
- The sync service runs from Compose as UID 65532 with a read-only root filesystem, no Docker socket, a least-privilege PostgreSQL role, Redis `SET NX EX` replay protection, and loopback-only port 3021.
- The sync release image is built only before maintenance by `deploy/sync-canary.py prepare-image` from digest-pinned PostgreSQL 18.4 and Python bases with Dockerfile-step networking disabled. Runtime Compose has no build definition, uses `pull_policy: never` plus `--no-build --pull never`, and the controller rejects any mismatch between the root-owned `/run/sub2api-gate/sync-image.json` Git/image attestation and the running container's exact `.Image` ID.
- Sub2API's application Redis is memory-only with a tmpfs persistence directory and RDB/AOF disabled. Source-audited `wait:account:*`, `sticky_session:*`, and `cyber_session_block:*` state is allowed only for runtime compatibility, is cleared on restart, and is always discarded rather than migrated; content payload keyspaces remain denied.
- The admin list reads 25 AuthState summaries and zero IP-record KV values. Selecting or editing one invite loads at most that invite's single byte-limited record value and paginates 20 IP groups; this path is isolated from `/v1/*`.
- Invite mutations compensate external Sub2API/Cloudflare effects after AuthState CAS conflicts. The safe 409 response never exposes internal revision or error detail.
- `deploy/security-preflight.sh` delegates all Wrangler bindings, migrations, secrets, routes, URLs, and compatibility checks to `validate-wrangler-config.mjs` as parsed JSON. Do not reintroduce line-oriented checks that reject valid pretty-printed private configuration.
- Production `PROVIDER_ALLOWED_HOSTNAMES` must contain at least one valid provider hostname and remain disjoint from public `ALLOWED_HOSTNAMES`. The parsed private-config gate rejects missing/empty values, and the Worker production entry returns 503 before business logic when either list is invalid.
- Bare-metal Nginx core dumps are denied in three layers: the tracked systemd drop-in sets `LimitCORE=0`, the Nginx main-context test config sets `worker_rlimit_core 0`, and `security-preflight.sh` verifies every stable Nginx process has soft and hard `Max core file size` equal to zero through `/proc`.
- Database apply tools expand PostgreSQL URLs through `deploy/pg-env-exec.py`: loopback URLs require explicit `sslmode=disable`; non-loopback URLs require `sslmode=verify-full` plus `sslrootcert=system` or an absolute CA path. Credentials never enter client argv.
- Safe schema export and sanitized PostgreSQL migration run `deploy/verify-postgres-portability.sql` before `pg_dump`. Only `plpgsql`, `pgcrypto`, and PostgreSQL 18 trusted `pg_trgm` are approved; `pg_trgm` is retained for Sub2API 0.1.162 local fuzzy-search indexes and has no remote or credential boundary. Every other extension, FDW, foreign server, user mapping, and foreign table fails closed without printing object options. The safe export executes both privacy-residue and portability gates inside its exported snapshot.
- Safe metadata exports are root-only atomic timestamped directories with a structured manifest binding Git HEAD, source PostgreSQL system identifier, artifact hashes, and critical privacy/migration policy hashes. `maintenance-cutover.py --apply` requires the exact export directory and verifies the manifest, live source cluster identity, capture-free live Nginx tree, and named `/v1` upstream before stopping writers.
- `deploy/security-preflight.sh` and `deploy/configure-redis-acl.py` share the `O_NOFOLLOW` parser in `deploy/private_env.py`. Private environment files use literal, unquoted visible ASCII only; ambiguous quoting, escaping, interpolation, inline comments, duplicate/invalid keys, and Docker/Compose control keys are rejected.
- Legacy Docker log cleanup is a two-stage operation. `cleanup-conversation-logs.sh --apply --stage record --legacy-container NAME` records a stopped container's validated local Docker identity and `LogPath`; cleanup and final `verify` require that exact name/ID, the same daemon/root, and removal of both the path and container log directory. The tool never deletes Docker internals or prints the recorded path.
- The empty-data Compose canary is an isolated tmpfs preflight on loopback `18081`; it cannot connect external PostgreSQL/Redis and must never be selected by Nginx. Port `8081` is reserved for a later canary backed by the newly migrated target data.
- Main Sub2API publishing is a literal `127.0.0.1:8080:8080`, and both main and traffic-canary runtimes fix `SERVER_MODE=release` plus `RUN_MODE=standard`. `security-preflight.sh` rejects conflicting legacy `BIND_HOST`, `SERVER_PORT`, `SERVER_MODE`, or `RUN_MODE` values; these architecture constants are not exposed in `.env.example`.
- `docker-compose.traffic-canary.yml` is the only traffic-capable `8081` target. `deploy/traffic-canary.py` requires the sanitized `/mnt/data` app/PG18/volatile-Redis8 target, runs privacy and least-privilege gates, and proves its app, PostgreSQL cluster, and Redis runtime identities differ from the live legacy `8080` containers before Nginx may switch.
- The Nginx canary switch repeats that identity check while holding the shared operation lock, before probing `8081` or modifying the active upstream. After a successful first release, keep the target managed on `8081`; no automatic port promotion or sync canary is part of this stack.
- Per-hostname AOP is a four-step control-plane/origin transition: Cloudflare certificate `upload` without hostname association, Nginx `optional`, Cloudflare `associate` with exact GET readback, then installer public `probe` before `required`. The root-only control state binds zone, hostname, certificate ID, CA fingerprint, and policy fingerprint; every remote write is preceded by an `*_in_flight` state, ambiguous results become `*_unknown`, and no compensating PUT/DELETE is sent after an ambiguous response.
- Public and admin Worker routes now enforce explicit path, method, media-type, and bounded-form contracts. Turnstile retries are generation-bound so stale callbacks cannot restore an obsolete widget, admin pagination/detail/edit/maintenance actions preserve one strictly parsed compact context, and every clipboard action exposes an accessible failure state.
- One Worker request reuses one AuthState store through Cloudflare mutation paths. The sync service uses stable request-ID JSON errors, shared dependency deadlines, bounded admission control, shorter PostgreSQL timeouts, and one database session for cold usage loads; Nginx preserves upstream `429`, `502`, and `504` envelopes while formatting only locally generated failures.
- `deploy/recover-worker-admin.py` performs at most one version upload and one deployment, then proves their exact IDs through bounded read-only reconciliation. Ambiguous outcomes remain `remote_outcome_unknown` and are never retried as writes. Its private temporary-file cleanup attempts every path, preserves an existing remote-outcome error, and fails closed if any residue cannot be removed.

## Status
- UI layout, typography, responsive behavior, reduced-motion handling, CSP nonces, fail-closed host validation, and metadata-only Usage Inspector behavior are implemented locally. Source and browser contracts cover reflow down to the 240 CSS px 200%-zoom equivalent, compact Turnstile states, dark-mode AA contrast, long-value wrapping, clipboard failure feedback, and admin context preservation.
- On 2026-07-22, the stable final local snapshot passed 182 Worker tests and 480 Python architecture/privacy/sync/deployment/compatibility/migration/canary/UI tests; one exact root-owned `/mnt/data` preflight remained skipped under the non-root local user. `npm audit --audit-level=high` reported zero vulnerabilities and the local Wrangler bundle dry-run passed.
- PostgreSQL 18 privacy/schema-drift (including locked rows, domains, XML, `bytea`, arrays, non-`public` schemas, `prompt_hash`, and optional ops retry fields), portability, runtime logging, least-privilege roles, usage, and default-group gates passed. Redis ACL/replay/crash recovery, Nginx 1.18/current AOP/direct-v1/SSE/Upgrade, all six Compose combinations, and real Sub2API 0.1.162 no-file-log/sync-health integration also passed.
- The static demo is 54,512 bytes (13,461 bytes gzip) with no external script, stylesheet, font, or image fetches. This is a resource-boundary check only, not a browser performance result.
- The isolated empty-data canary started successfully with Sub2API 0.1.162 and its reviewed commit, PostgreSQL 18, and Redis 8.8.0; health, UID 1000, private tmpfs ownership, no file log, and Docker log driver `none` were verified before the temporary stack was removed.
- Shell syntax, Python compilation, Compose parsing, targeted credential scan, private Wrangler permission/ignore checks, tracked and untracked whitespace checks, and `git diff --check` passed. Credential scan found only explicit test sentinels and placeholders.
- The production private Worker config now has `PROVIDER_ALLOWED_HOSTNAMES=api.openai.com`; all nine reviewed live accounts are OpenAI OAuth with no custom base URL. On 2026-07-24, the required Worker Secret names were verified from the local OAuth-authorized Wrangler session and the temporary TOTP-rotation Secret names were confirmed absent; no Secret values were read or changed.
- The local Playwright browser matrix now passes all 24 tests across nine rendered scenarios, seven required viewport sizes, light/dark themes, and the 240 CSS px 200%-zoom equivalent. Its 133 results and 134 PNGs have screenshot/pixel, overflow, overlap, clipping, contrast, HTML-budget, local LCP/CLS, and Event Timing checks under `.local/browser-ui-gate/`; Chrome DevTools MCP remains unavailable, so formal trace-based LCP/INP/CLS acceptance is still unperformed.
- Production preparation is active at Git release `f4d9100`: `/home/ubuntu/sub2api-gate-release` and the exact root-owned `/mnt/data/sub2api-gate` tree exist, the ignored mode-0600 private `.env` safely reuses legacy PostgreSQL/JWT/TOTP-encryption/sync values and has distinct new role/Redis credentials, Redis ACL hashes are installed, Node.js 22 is installed for validation, Nginx was restarted with `LimitCORE=0`, `/health` remained 200, the full server security preflight passed, and the sync image was built and attested. No database migration, container cutover, Worker deployment, AOP association, or legacy deletion has occurred.
- The next gate requires human private-TTY input: run `install-nginx-direct-v1.py --apply` with an existing Sub2API API key, then run the source privacy migration with the operator's migration TOTP seed and current code. Until that direct cutover and scrub completes, the old `/v1/* -> 3021` mirror/capture and legacy logs may still retain conversation content. Do not claim privacy completion yet.

- On 2026-07-22, exact release `dae2818` was installed at root-owned `/opt/sub2api-gate-release`; the ignored Worker binding config is root-only there, the private environment is root-only at `/mnt/data/sub2api-gate/private/.env`, and the duplicate user-owned environment file was removed after a byte-for-byte comparison. The release guard, sync image attestation, and server security preflight passed without stopping current services.
- The direct `/v1/*` cutover is already active and remains healthy on stable `127.0.0.1:8080`; no production database scrub, data migration, Worker publication, AOP association, or group migration has run. The remaining first production gate is TOTP verifier enrollment plus the source privacy migration from a private server TTY.
- Local administrator TOTP rotation hardening passed 193 Worker tests, 35 local
  migration-TOTP tests, 27 Wrangler preflight tests, and 41 deployment-config
  tests (one skip). The Worker session binding is HMAC-keyed and phase-bound;
  the final-source gate and the private-TTY runbook are hardened.
- On 2026-07-24, the security audit added explicit Cloudflare gates at every
  proxy location, split stable Compose into internal data and app-only egress
  networks, hardened the Cloudflare CIDR updater and trusted release guards,
  added reversible legacy sync/Redis/rpcbind controllers, and fixed a
  Worker-runtime attestation TOCTOU. The local AOP test now isolates its
  privileged PATH sanitization so the full suite remains deterministic.
- The 2026-07-24 live cc check found public root `200`, unauthenticated
  `/v1/models` `401`, a direct loopback-origin `/v1/models` probe `403`, and
  loopback-only `8080`/`3021`; the installed Cloudflare CIDRs exactly matched
  Cloudflare's current published IPv4 and IPv6 lists. UFW has default incoming
  deny and permits only `22`, `80`, `443`, `8443`, and `9993`.
- `rpcbind.service` and `rpcbind.socket` were stopped and disabled on cc after
  confirming no NFS mounts, no non-target dependencies, and only portmapper
  registrations. TCP/UDP `111` no longer listen; Nginx and Sub2API remained
  healthy afterward.
- The legacy sync service still runs as root without a systemd sandbox, and
  legacy PostgreSQL/Redis still have writable roots and Docker `json-file`
  logs. The new hardening controllers have not been deployed: the live trusted
  release is `dae2818` while the local worktree is intentionally dirty. Install
  a clean reviewed release before using those controllers; do not bypass their
  private-root-TTY, source-identity, and rollback gates.
- Remaining separately approved maintenance work: apply the 17 pending host
  upgrades (including Docker and ZeroTier) with the required reboot, decide
  whether public xray `8443`, ZeroTier `9993`, SSH root-key login/forwarding,
  and Cloudflare AOP are operationally required, then harden or remove them.
  The privacy scrub and data migration remain blocked on the administrator
  TOTP rotation/re-enrollment; do not bypass that gate.
- Final local verification on 2026-07-24: 705 Python tests passed with two
  expected skips, 195 Worker tests passed, `npm audit --audit-level=high`
  reported zero vulnerabilities, and the final-source local commit is
  `f805877`. The compatibility Worker source at `e5b6104` was independently
  tested (`195/195`), audited, dry-run validated, and published from the local
  Wrangler OAuth session. Public root and `/allow-ip` returned `200`; anonymous
  `/v1/models` returned `401`. cc, Nginx, legacy containers, databases, and
  legacy data were not changed.
- The Worker is now in the compatibility TOTP-rotation phase. Before staging a
  new seed, obtain one fresh browser login using the canonical seed. Then stage
  the new seed through private prompts and prove two fresh new-seed logins in
  distinct 30-second periods. Do not deploy final-source, rotate the local
  verifier, scrub privacy data, or start the 8081 cutover before those proofs.
- Local Cloudflare code publication is now guarded by
  `deploy/local-worker-publish.py`. It stages only the fixed reviewed
  compatibility or final-source commits in a temporary worktree, accepts only
  the operator-owned single-link mode-0600 local Wrangler config, uses local
  OAuth without an API token, and checks dependencies, Worker tests, config,
  name-only Secrets, and dry-run before explicit publish. It cannot write
  Secrets. Its unit coverage includes release/phase pinning, config boundaries,
  no-publish check mode, early Node rejection, Secret-list failure, and partial
  worktree cleanup; 54 related deployment tests passed on 2026-07-24.
- On 2026-07-25, `/v1` remained healthy (root `200`, anonymous `/v1/models`
  `401`) while administrator recovery was investigated locally. Legacy
  `wrangler secret put`/`bulk` created Secret-change versions from an older
  code snapshot; use the versioned upload/deploy flow for any future
  code-and-Secret release. Temporary diagnostic source, Secrets, and
  worktrees were removed. The private recovery credential file remains
  mode-0600, but an end-to-end `xin` login still returned `403`; do not claim
  administrator recovery or proceed to rotation, scrub, or cutover without a
  fresh successful login proof.
- Final local verification on 2026-08-05 passed 208 Worker tests and 795 Python
  tests with two expected skips, including 28 sync HTTP contract tests. The
  release-tool subset passed 52 tests; statement/branch coverage is
  91.23%/85.37% for `local-worker-publish.py` and 92.66%/86.00% for
  `recover-worker-admin.py`. `npm audit --audit-level=high`, both guarded local
  candidate checks, the current-worktree Wrangler dry-run, syntax checks,
  credential scanning, and `git diff --check` passed.
- The 2026-08-05 browser lab recorded maximum LCP/FCP 80 ms, CLS 0, Event
  Timing upper bound 48 ms, navigation 65.3 ms, and rendered HTML 126,527
  bytes. These are Playwright-local observations, not formal Core Web Vitals or
  field INP measurements.
- The 2026-08-05 work is a local candidate only. No production/remote write,
  Worker publication, Secret change, privacy scrub, database migration, AOP
  association, traffic cutover, or legacy deletion occurred. Administrator
  recovery still requires a private-TTY end-to-end `303` plus the strict Secure
  HttpOnly session-cookie proof before rotation, scrub, migration, or cutover.
- The local verification gate is `bash deploy/verify-local.sh`; it runs core
  Worker/sync coverage ratchets, release-tool coverage, isolated digest-pinned
  PostgreSQL/Redis dependency tests, browser UI contracts, and diff checks.
  The dependency test containers use synthetic credentials and exact-name
  cleanup. Worker V8 coverage tracks `admin.js`, `auth-state.js`, and
  `index.js`; `worker-entry.js` remains enforced by the real Workers-runtime
  contract tests because Miniflare isolates are outside the V8 aggregate.
- On 2026-08-07, the local-only Sub2API 0.1.171 candidate passed the isolated
  PostgreSQL 18 privacy migration, no-file-log/sync-health/least-privilege
  integration, Redis ACL runtime, and unified verification gate. Runtime,
  canary, version, Redis-policy, and test pins now use image digest
  `8469b859...3577d2` and source revision `f0e7a9c7...0475a6`.
  `usage_logs.session_id` and `batch_image_jobs.session_id` are unbounded
  nullable `varchar(255)` fields with no reviewed operational constraint, so
  the privacy migration clears them and never adds them to metadata allowlists.
  No production deployment, Worker publication, Secret change, migration,
  traffic cutover, or legacy deletion occurred; the private-TTY recovery and
  migration gates remain mandatory.
- On 2026-08-07, `deploy/release-policy.json` and the offline
  `deploy/verify-release-policy.py` gate were added and wired into
  `deploy/verify-local.sh`. They cross-check the Sub2API 0.1.171 image/version,
  source revision, PostgreSQL/Redis/sync identities, Compose/canary/runtime
  gates, migration policy, and deployment runbook; the gate has five regression
  tests and passed in the unified run. The complete local gate passed 208 Worker
  tests, 805 Python tests with four expected skips, 53 release-tool tests, two
  real dependency tests, and 24 browser tests. All available check-only
  production controllers passed except the intentional clean-worktree guard;
  the tree remains dirty and no production write has occurred.
- The read-only `deploy/check-release-candidate.sh` gate now composes release
  policy, clean-worktree, diff, private-file, and canonical-HEAD checks. It is
  required by CI after `verify-local.sh`; a clean temporary Git fixture passed
  it, while the current dirty checkout correctly fails. The latest unified gate
  passed 806 Python tests with four expected skips; its Git/Python/batch shell
  commands now use fixed system paths and an empty Git configuration. A clean
  fixture also passed with `PATH=/nonexistent`; no production write occurred
  before this release candidate commit.
- The complete candidate was committed locally as `37195c1` with the staged
  credential scan passing. `deploy/check-release-candidate.sh` now passes on the
  clean checkout; the commit has not been pushed and no production write has
  occurred. The release remains blocked only by target-host preparation and the
  required private-TTY administrator recovery proof.
- After the clean commit, Worker deploy check, administrator recovery candidate
  check, traffic/maintenance/retirement/privacy/sync/runtime check-only gates
  all passed without writes. The current environment still lacks
  `/opt/sub2api-gate-release`, `/mnt/data/sub2api-gate`, and the private
  production environment; administrator recovery remains a private-TTY gate.
