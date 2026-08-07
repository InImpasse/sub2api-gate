# Deployment preparation

Nothing in this directory deploys automatically.

`nginx/update-cloudflare-ips.sh` also defaults to `check` and does not contact
the network. Use `--apply` only when intentionally refreshing the three tracked
Cloudflare IP boundary files from Cloudflare's published lists.

## Local release gates

Run these before requesting deployment approval:

The reviewed Sub2API release and its PostgreSQL/Redis/sync image identities are
declared in `deploy/release-policy.json`. The consistency check is offline and
credential-free; it rejects a version or digest drift across Compose, canary,
runtime gates, migration policy, and this runbook.

The preflight rejects `.env` and `worker-allow-ip/wrangler.private.jsonc` when
either file is readable, writable, or executable by group or other users. Set
both files to mode `0600` before running it. The private environment parser is
shared with the Redis ACL generator and deliberately supports no shell or
Compose interpretation: keys must match `[A-Z][A-Z0-9_]*`, and values must be
single-line visible ASCII without whitespace, quotes, backslashes, `#`, or `$`.
Duplicate keys and `DOCKER_*`/`COMPOSE_*` control keys are rejected. Generate
passwords from a URL-safe alphabet rather than adding quoting or escaping.

Create the persistent tree with the exact runtime identities before generating
the Redis ACL or running preflight. Do not use a recursive `chown`; each service
owns only its own directory:

```bash
sudo install -d -o root -g root -m 0700 /mnt/data/sub2api-gate
sudo install -d -o root -g root -m 0700 /mnt/data/sub2api-gate/private
sudo install -d -o 1000 -g 1000 -m 0700 /mnt/data/sub2api-gate/app
sudo install -d -o 70 -g 70 -m 0700 /mnt/data/sub2api-gate/postgres
sudo install -d -o 999 -g 1000 -m 0700 /mnt/data/sub2api-gate/redis
sudo install -d -o 999 -g 1000 -m 0700 /mnt/data/sub2api-gate/redis/nonce
sudo install -d -o root -g root -m 0700 /mnt/data/sub2api-gate/safe-backup
sudo install -d -o root -g root -m 0700 /mnt/data/sub2api-gate/exports
```

PostgreSQL 18 uses its official major-version-aware layout. The host path stays
`/mnt/data/sub2api-gate/postgres`, it is mounted at `/var/lib/postgresql`, and
the cluster must exist at `postgres/18/docker`. In particular, the release gate
requires `postgres/18/docker/PG_VERSION`, `global/pg_control`, and `pg_wal`;
the legacy PostgreSQL 17-style `postgres/PG_VERSION` layout is rejected.

Every root-run production action must execute from the exact
`/opt/sub2api-gate-release` Git worktree. `/opt`, the release root, and every
entry below it must be root-owned, must not be group/world writable, and the
tree must not contain symlinks or nested mounts. Install releases from an exact
reviewed Git commit into that tree; never run privileged migration or cutover
code from `/home/ubuntu`, another operator-writable parent, or a copied working
directory. Private configuration remains outside the release tree under
`/mnt/data/sub2api-gate/private`.

`security-preflight.sh` checks actual free bytes on that filesystem and requires
`SUB2API_MIN_FREE_BYTES` to be at least 10 GiB. Raise it above the measured
space needed for the fresh PostgreSQL cluster, safe metadata export, and nonce
AOF; never lower it to make a migration fit. The preflight also refuses an
active host swap device because the application Redis is volatile and its
process memory must not be paged to disk. Every Compose service has core dumps
disabled. The same preflight reads every live Nginx process from `/proc` and
requires both its soft and hard core-file limits to be zero. Resolve any host
condition before rollout rather than bypassing the gate.

```bash
python3 ./deploy/verify-release-policy.py
bash ./deploy/security-preflight.sh check --env-file .env
bash ./deploy/prepare-sync-role.sh check
bash ./deploy/prepare-app-role.sh check
python3 ./deploy/traffic-canary.py check
python3 ./deploy/maintenance-cutover.py check
python3 ./deploy/retire-legacy-data.py check
python3 -m unittest discover -s sub2api-sync/tests -v
./deploy/migrate-sanitized-postgres.sh check
./deploy/migrate-redis-allowlist.py check
./deploy/migrate-app-metadata.py check
./deploy/export-safe-metadata.sh check
python3 ./deploy/verify-runtime-privacy.py check
./deploy/test-privacy-migration-pg18.sh
./deploy/test-sync-role-least-privilege-pg18.sh
./deploy/test-app-role-least-privilege-pg18.sh
./deploy/test-postgres-runtime-logging-pg18.sh
./deploy/test-postgres-portability-pg18.sh
./deploy/test-usage-metadata-pg18.sh
./deploy/test-default-group-migration-pg18.sh
./deploy/test-redis-runtime-acl.sh
./deploy/test-sync-nonce-redis.sh
./deploy/test-nginx-config.sh
python3 ./deploy/verify-nginx-core-dumps.py check
python3 ./deploy/sync-canary.py prepare-image
./deploy/test-sub2api-no-content-logging.sh
(cd worker-allow-ip && npm test)
(cd worker-allow-ip && npm audit --audit-level=high)
docker compose config --no-interpolate
docker compose -f docker-compose.traffic-canary.yml \
  --profile traffic-canary config --no-interpolate
docker compose --env-file .env.example \
  -f docker-compose.traffic-canary.yml \
  -f docker-compose.postgres-migration.yml \
  --profile traffic-canary config --quiet
docker compose --env-file .env.example \
  -f docker-compose.sync-canary.yml \
  -f docker-compose.redis-migration.yml \
  --profile sync-canary config --quiet
git diff --check
bash ./deploy/check-release-candidate.sh
```

`verify-local.sh` accepts a dirty development checkout. Run
`check-release-candidate.sh` only from the reviewed clean commit that will be
installed as the trusted release tree; it performs no deployment or remote
write.

## Private database role preparation

The app and sync role helpers never accept PostgreSQL URLs or role passwords
from the ambient environment. Their `check` mode is offline and does not read a
private file. Every apply requires the absolute mode-`0600` private environment
path:

```bash
sudo bash deploy/prepare-sync-role.sh --apply \
  --env-file /mnt/data/sub2api-gate/private/.env
sudo bash deploy/prepare-app-role.sh --apply \
  --env-file /mnt/data/sub2api-gate/private/.env
```

Run those commands only at their documented maintenance-controller stages.
The controller must pass the same `--env-file` argument and an empty
credential environment; it must never inject `SUB2API_DATABASE_URL`,
`SUB2API_TARGET_DATABASE_URL`, `SUB2API_SYNC_DATABASE_PASSWORD`, or
`SUB2API_APP_DATABASE_PASSWORD` into these child processes.

Each helper consumes the strict private parser's NUL-delimited records through
a pipe, validates that the target URL and its own role password are present,
and then invokes `pg-env-exec.py --target-private-env-file`. The executable
`pg-env-exec.py` interface rejects all ambient URL selectors; its pure parsing
functions remain available to internal validation code. Private parsing is
bounded to five seconds and role preparation to thirty seconds, with a
one-second TERM-to-KILL grace. PostgreSQL stdout and stderr are discarded
because a generated `ALTER ROLE` statement contains the password internally;
failure exposes only `sub2api_sync_role_prepare_failed` or
`sub2api_app_role_prepare_failed`.

The privacy migration is deliberately two-phase. The short
`002_remove_conversation_capture.sql` transaction installs and commits write
guards first, `verify_conversation_guards.sql` checks them without reading
content, and only then does `002_scrub_conversation_history.sql` clean existing
rows. `verify_no_conversation_content.sql` is the final read-only residue and
schema-drift gate. In `--apply` mode the runner first reads the administrator TOTP secret
and one-time code from the private controlling terminal, verifies them, and only
then reads database credentials or starts `psql`; never pass either value through arguments or environment variables.

The one-time verifier enrollment is an explicit trust-on-first-use ceremony:
Cloudflare never reveals an existing Worker Secret, so the tool cannot prove
which seed is registered remotely. From the private root TTY, independently
confirm the seed against the original administrator TOTP enrollment record,
then run `sudo python3 deploy/verify-migration-totp.py enroll --apply` and enter
that seed plus its current code. Never generate a self-consistent replacement
seed merely to satisfy this gate. If the registered seed is unavailable, stop
and use a separately reviewed Worker TOTP rotation; do not bypass enrollment.
The verifier, replay lock, and replay state remain under
`/mnt/data/sub2api-gate/private`. The private parent directory must be
root-owned mode `0700`; the verifier and replay state are root-owned mode
`0600` (the replay lock is also created mode `0600`).

The storage migration tools are also check-only by default. PostgreSQL is
streamed directly from a sanitized, stopped source into a fresh PostgreSQL 18
database and committed only after privacy, row-count, relationship, and usage
metadata checks pass. Before either a safe schema fingerprint or a logical
migration, the PostgreSQL portability gate rejects every FDW, foreign server,
user mapping, foreign table, and extension other than the exact `plpgsql`,
`pgcrypto`, and PostgreSQL 18 trusted `pg_trgm` allowlist. Sub2API 0.1.171 uses
`pg_trgm` only for local fuzzy-search indexes; it has no remote connection or
credential boundary. This prevents `pg_dump` from serializing foreign
connection options or credentials into the target cluster. The safe export
runs that gate inside the same exported snapshot, pipes the schema-only stream
directly into SHA-256, and persists only `schema_fingerprint.sha256`; function
bodies, defaults, policies, trigger arguments, and other schema text never
enter the backup directory.
Apply creates a root-owned mode-`0700` timestamped directory under
`/mnt/data/sub2api-gate/safe-backup`. Its atomically published `manifest.json`
binds the current Git commit, source PostgreSQL system identifier, every export
artifact hash, and the critical privacy/migration policy file hashes. The
mode-`0600` `COMPLETE` marker is written only after the manifest and checksums;
an incomplete, extra, linked, non-root-owned, or modified file is rejected.
The current Redis migration copies only unexpired HMAC
sync nonce markers into the dedicated Redis 8.8.0 nonce store; Sub2API session,
OAuth, scheduler, billing, and concurrency cache is deliberately rebuilt rather
than copied because reviewed 0.1.171 values can contain credentials or
request-derived identifiers. The application
directory starts empty; only a strictly validated model pricing document may
be projected into it. No tool copies an old PostgreSQL data directory, WAL,
Redis AOF, `config.yaml`, log, preview, or capture file.

Before starting Redis, generate its two-user ACL from the private mode-`0600`
environment file. Check mode never reads a secret or writes a file; `--apply`
requires the fixed `/mnt/data/sub2api-gate/redis` directory and writes only
SHA-256 password hashes to `users.acl`:

```bash
python3 deploy/configure-redis-acl.py check
sudo python3 deploy/configure-redis-acl.py --apply --env-file /path/to/private.env
```

The Sub2API application Redis is memory-only: its persistence directory is on
tmpfs and both AOF and RDB are disabled. It always starts empty; no application
cache is imported, copied, or expected to survive a container restart.
Source-audited `wait:account:*`
counters, `sticky_session:*` routing hashes, and `cyber_session_block:*`
SHA-256 references are available only in that volatile instance so Sub2API
0.1.171 can operate normally. Their values are respectively an expiring integer,
a numeric account ID, and the marker `1`; all are discarded during migration.
Raw prompts, requests, responses, moderation data, and image payload keyspaces
remain denied by ACL. The integration gate verifies the required runtime
operations against Redis 8.8.0 and proves that the entire application cache is
gone after forced and graceful restarts without creating an RDB or AOF file.
This intentionally trades restart continuity for privacy: sticky routing,
waiting counters, and temporary cyber-session blocks are rebuilt after a
restart. The application instance uses a `128 MiB` Redis `maxmemory` ceiling
inside a `256 MiB` container limit. The nonce-only instance uses `32 MiB` inside
a `128 MiB` container limit. Both use `noeviction`: hitting the ceiling fails a
write visibly instead of silently discarding authentication, concurrency, or
replay-protection state. Post-cutover observation must verify adequate headroom
before normal traffic is declared stable.

Review Worker credential generation with
`python3 deploy/generate-worker-secrets.py check`, then run
`python3 deploy/generate-worker-secrets.py --apply` only as root from the root-owned
`/opt/sub2api-gate-release` release tree in a private terminal. Its child commands
use a fixed minimal environment and fixed private Wrangler config; do not set a
config override or supply a Cloudflare token through the shell environment.
The tool lists remote Secret names, initializes only missing managed values in
one bulk stdin request, and verifies names afterward. Before uploading a new
`INVITE_ACCESS_HMAC_KEY`, it atomically creates the ignored
`.local/worker-secret-state/invite-access-hmac-migration.key`; the operator-owned
`0700` directory and single-link `0600` file contain only that 64-character HMAC
key. A failed or ambiguous upload retains the file for a safe retry. The tool
never replaces an existing AES, HMAC, administrator password, or `ADMIN_TOTP_SECRET`
value. Those values must not be set manually with `wrangler secret put`; rotation
requires a separate credential migration. Never put their values in tracked or
private JSON.
The ignored `worker-allow-ip/wrangler.private.jsonc` contains non-secret,
environment-specific binding IDs and provider hostname approvals only.
`ALLOWED_HOSTNAMES` is reserved for public Worker/Sub2API hosts;
`PROVIDER_ALLOWED_HOSTNAMES` is reserved for external API providers, and the
production private config must contain at least one valid provider hostname.
The preflight rejects an absent or empty list and any overlap; the Worker entry
also returns 503 before business logic when either list is invalid.

## Administrator TOTP rotation

### Local OAuth Worker publishing

When Cloudflare authentication is intentionally retained on the operator's
workstation rather than cc, publish reviewed Worker code through
`deploy/local-worker-publish.py`. It creates and removes an isolated worktree
at the fixed reviewed source commit, copies only the local mode-`0600` private
binding config, and verifies Node, locked dependencies, Worker tests, Wrangler
config, the TOTP Secret *names*, and a dry-run before an explicit publish. It
uses the local Wrangler OAuth home and never accepts, creates, reads, or logs a
Secret value.

The default is check-only. For a compatibility publish, invoke it from the
local repository with the exact locally installed Node 22-or-newer executable:

```bash
python3 -I deploy/local-worker-publish.py --apply \
  --totp-rotation-stage compatibility \
  --node /absolute/path/to/node
```

This controller cannot initialize, stage, promote, or delete Worker Secrets.
Those remain private interactive operations and require their own successful
browser-login proof. Do not replace this controller with a bare `wrangler
deploy`, and do not use it for final-source until the documented promoted-seed
proof has completed.

Use this procedure only when the registered migration verifier exists and the
old administrator Base32 seed is unavailable. Do not delete the verifier, its
replay-state file, or its lock file to make `enroll --apply` work. The supported
replacement is `rotate --apply`; it first validates the existing private
verifier, requires a different new seed, consumes the new code, and atomically
replaces the verifier and replay state. A failed rollback preserves root-only
recovery backups and stops. Do not retry or remove those backups manually.

This is a phase-bound compatibility Worker procedure. It accepts the canonical
`ADMIN_TOTP_SECRET` plus the optional pair `ADMIN_TOTP_SECRET_NEXT` and
`ADMIN_TOTP_ROTATION_PHASE`. With neither temporary Secret it accepts only the
canonical seed; phase `stage` requires two distinct decoded seeds; phase
`promoted` requires that the two decoded seeds are identical and accepts the
canonical seed only. Every other combination fails closed. New admin sessions
bind the phase and effective seed set, so each transition invalidates old
administrator cookies. The final single-seed release must remove all reads of
both temporary Secret names after canonical promotion has been proven. Never put
either seed, a code, password, Cookie, request body, or a secret-list response
in a repository, shell history, environment file, terminal transcript, or audit record.

Run every secret operation only as root from the root-owned
`/opt/sub2api-gate-release` worktree in a private interactive terminal. The
deployment environment is deliberately sanitized, so Wrangler authentication
must be available under root's protected home directory; do not supply an API
token, config override, or secret through the shell environment. Define local
paths without placing secret values in variables:

```bash
cd /opt/sub2api-gate-release
worker_dir="$PWD/worker-allow-ip"
wrangler_config="$worker_dir/wrangler.private.jsonc"
node_bin=/usr/bin/node
wrangler_cmd=("$node_bin" "$worker_dir/node_modules/wrangler/bin/wrangler.js")
```

1. Establish the baseline Worker Secret set before the compatibility deployment.
   This initializes only missing managed Secrets and never overwrites
   `ADMIN_TOTP_SECRET`; it must succeed before the rotation controller can
   inspect or publish the Worker:

   ```bash
   /usr/bin/python3 -I deploy/generate-worker-secrets.py --apply
   "${wrangler_cmd[@]}" secret list --format json --config "$wrangler_config" \
     | "$node_bin" deploy/verify-worker-secret-list.mjs \
       "$worker_dir/required-secrets.json" --forbid-totp-rotation-staging
   ```

   Run this only in the private terminal. The name verifier emits only the
   validation result; do not record the secret-list response. Stop if either
   command fails or if either temporary rotation Secret already exists.

2. Publish the clean reviewed compatibility Worker while both
   `ADMIN_TOTP_SECRET_NEXT` and `ADMIN_TOTP_ROTATION_PHASE` are absent. The
   compatibility apply gate verifies their absence and publishes only after the
   release and security gates pass:

   ```bash
   /bin/bash deploy/deploy-worker.sh --apply --totp-rotation-stage compatibility
   ```

   In a private browser, confirm any existing administrator cookie is sent back
   to the sign-in page, then make one fresh administrator login with the current
   canonical seed. Do not test an intentionally wrong code; failed login
   attempts are rate limited.

3. Stage the new Base32 seed and `stage` phase through Wrangler's private
   prompts. Never redirect the input or supply a value on the command line:

   ```bash
   "${wrangler_cmd[@]}" secret put ADMIN_TOTP_SECRET_NEXT --config "$wrangler_config"
   "${wrangler_cmd[@]}" secret put ADMIN_TOTP_ROTATION_PHASE --config "$wrangler_config"
   "${wrangler_cmd[@]}" secret list --format json --config "$wrangler_config" \
     | "$node_bin" deploy/verify-worker-secret-list.mjs \
       "$worker_dir/required-secrets.json" --require-totp-rotation-staging
   ```

   The two Secret writes are not atomic; a transient mismatch intentionally
   fails closed. The `stage` phase requires the new seed to decode differently
   from the canonical seed, so an alternate Base32 spelling is not a rotation.
   The list verifier reports only whether the required names are present; it
   cannot prove a Secret value. After propagation, make fresh new-seed
   administrator logins in two distinct 30-second periods. Each must reach the
   administrator page. Immediately sign out after each proof. The old seed may
   remain valid only during this compatibility stage; do not spend rate-limit
   budget testing it when the operator no longer has that seed.

4. Promote the already-proven new seed by entering phase `promoted` and then
   setting the canonical Secret through the same private prompts:

   ```bash
   "${wrangler_cmd[@]}" secret put ADMIN_TOTP_ROTATION_PHASE --config "$wrangler_config"
   "${wrangler_cmd[@]}" secret put ADMIN_TOTP_SECRET --config "$wrangler_config"
   "${wrangler_cmd[@]}" secret list --format json --config "$wrangler_config" \
     | "$node_bin" deploy/verify-worker-secret-list.mjs \
       "$worker_dir/required-secrets.json" --require-totp-rotation-staging
   ```

   The `promoted` phase requires both Secrets to decode to the same new seed and
   authenticates the canonical seed once. If the canonical update does not
   complete, restore phase `stage` before retrying. Existing sessions are
   invalidated because their phase-bound binding changes. Wait for propagation
   and prove a fresh new-seed login again. This is the forward-only point: do
   not continue unless that login succeeds.

5. Create a separate clean, reviewed final Worker release that removes all
   reads of both temporary Secret names, their phase validation, and their
   session-binding inputs. Run the full Worker tests, then publish it with:

   ```bash
   /bin/bash deploy/deploy-worker.sh --apply --totp-rotation-stage final-source
   ```

   The final-source gate requires both temporary names still exist, scans all
   JS/TS source, and proves no temporary read remains. It rejects dynamic
   `env[...]` access, dynamic/CommonJS imports, and imports escaping the source
   root. Prove another fresh new-seed login.

6. Delete both staging Secrets and prove their names are gone without printing
   the returned list. The final Worker must still accept the new seed:

   ```bash
   "${wrangler_cmd[@]}" secret delete ADMIN_TOTP_SECRET_NEXT --config "$wrangler_config"
   "${wrangler_cmd[@]}" secret delete ADMIN_TOTP_ROTATION_PHASE --config "$wrangler_config"
   "${wrangler_cmd[@]}" secret list --format json --config "$wrangler_config" \
     | "$node_bin" deploy/verify-worker-secret-list.mjs \
       "$worker_dir/required-secrets.json" --forbid-totp-rotation-staging
   ```

   Make one fresh new-seed login after propagation before proceeding.

   Record only UTC time, operator, release commit, Wrangler version, Secret
   name-check result, and each successful fresh-login result. A Secret-name
   check is evidence of presence or removal only; the private browser login is
   the evidence that the Worker loaded the new seed.

7. Only after the final Worker proof, rotate the local migration verifier from
   a private root TTY. The acknowledgement flag records the external Worker
   proof; it is not a substitute for it:

   ```bash
   /usr/bin/python3 -I deploy/verify-migration-totp.py rotate check
   /usr/bin/python3 -I deploy/verify-migration-totp.py rotate --apply --worker-totp-verified
   ```

   The rotation consumes its supplied current code. Wait for a strictly newer
   30-second TOTP period, then run `privacy --apply` directly. That command
   performs and consumes its own migration TOTP verification. If a standalone
   `verify` is run after rotation, wait one additional period before privacy.
   Recollect the full legacy container IDs immediately before the privacy
   command; never reuse an earlier ID. Stop on any failed Worker proof, secret
   name check, local rotation error, or retained recovery backup.

Per-hostname Authenticated Origin Pull setup is also check-only by default:

```bash
deploy/configure-cloudflare-aop.py check \
  --stage upload \
  --zone-id 00000000000000000000000000000000 \
  --hostname api.example.com
```

Legacy one-step `--apply` is forbidden. After explicit production approval,
replace the placeholders and run the four state transitions from the same
private TTY:

```bash
sudo deploy/configure-cloudflare-aop.py --apply --stage upload \
  --zone-id 00000000000000000000000000000000 \
  --hostname api.example.com
sudo deploy/install-nginx-aop.sh --apply --stage optional \
  --hostname api.example.com \
  --ca-file /etc/nginx/sub2api-gate/aop/client-ca.pem
sudo deploy/configure-cloudflare-aop.py --apply --stage associate \
  --zone-id 00000000000000000000000000000000 \
  --hostname api.example.com
sudo deploy/install-nginx-aop.sh --apply --stage probe \
  --hostname api.example.com
sudo deploy/install-nginx-aop.sh --apply --stage required \
  --hostname api.example.com \
  --ca-file /etc/nginx/sub2api-gate/aop/client-ca.pem
```

The upload stage first proves the exact hostname has no existing per-host AOP
association. It generates private keys only under `/dev/shm`, writes the CA
public certificate to `/etc/nginx/sub2api-gate/aop/client-ca.pem`, persists a
root-only control record, and uploads the client certificate without associating
the hostname. The record contains only its strict version/phase, zone,
hostname, certificate ID, CA fingerprint, and reviewed-policy fingerprint; it
never contains the API token or private key. An existing Nginx AOP install
state, active optional/required configuration, CA, or control state blocks a
second upload.

Only after the origin is running `ssl_verify_client optional` does the
associate stage proceed. It holds the shared Nginx operation lock while the
installer verifies the same hostname and CA, then uses the fixed Cloudflare
hostname PUT and polls the fixed hostname GET until the exact certificate is
`enabled` and `active`. The public installer probe remains a separate step and
is required before `ssl_verify_client on`.

Every remote write is preceded by a durable `*_in_flight` state. A timeout,
5xx, malformed/missing response, unconfirmed active state, or post-write state
fsync failure becomes `*_unknown`. The tool never sends a compensating PUT or
DELETE after an ambiguous response. Stop and reconcile `upload_unknown`
against Cloudflare manually; `associate_unknown` may be retried only with the
same zone, hostname, CA, and policy, and its GET readback must confirm the exact
certificate before the state becomes `associated`.

## Required file mapping

- `nginx/00-connection-upgrade-map.conf` -> `/etc/nginx/conf.d/00-connection-upgrade-map.conf`
- `nginx/cloudflare-source-geo.conf` -> `/etc/nginx/conf.d/00-cloudflare-source-geo.conf`
- `nginx/sub2api-sync-limit.conf` -> `/etc/nginx/conf.d/00-sub2api-sync-limit.conf`
- `nginx/systemd/nginx-core-limit.conf` -> `/etc/systemd/system/nginx.service.d/20-sub2api-gate-core.conf`
- `nginx/snippets/cloudflare-real-ip.conf` -> `/etc/nginx/snippets/cloudflare-real-ip.conf`
- `nginx/snippets/cloudflare-only.conf` -> `/etc/nginx/snippets/cloudflare-only.conf`
- `nginx/snippets/sub2api-upstream-stable.conf` -> `/etc/nginx/snippets/sub2api-upstream-active.conf`
- `nginx/sub2api-sync-location.conf` -> `/etc/nginx/snippets/sub2api-sync-location.conf`
- `sub2api-sync/` is built as the `sub2api-sync` Compose service; the legacy
  root systemd service must be disabled after container health is confirmed.

The systemd drop-in sets `LimitCORE=0` for the bare-metal Nginx master and all
workers it creates. Installing it requires `systemctl daemon-reload` followed
by a controlled Nginx restart; a configuration reload alone does not change
the already-running master's hard limit. Do that only in the approved rollout
window, then run `python3 deploy/verify-nginx-core-dumps.py verify`. The verifier
is read-only, requires at least one stable Nginx process, and fails if any
master or worker reports a non-zero soft or hard limit.

Do not replace the live TLS vhost wholesale. Certificate paths and the
production hostname differ from the tracked template. Replace only the live
`location = /v1/responses` and `location ^~ /v1/` blocks with the direct block
from `nginx/sub2api.conf`, and add the named upstream once in the `http`
context. The resulting configuration must contain:

```bash
python3 deploy/install-nginx-direct-v1.py check
# Only after explicit production approval, from a private root TTY:
sudo python3 deploy/install-nginx-direct-v1.py --apply \
  --site-config /etc/nginx/conf.d/sub2api.conf \
  --server-name api.example.com \
  --verify-url https://api.example.com/v1/responses \
  --model reviewed-canary-model
```

```nginx
upstream sub2api_backend {
    include /etc/nginx/snippets/sub2api-upstream-active.conf;
    keepalive 64;
}

location ^~ /v1/ {
    proxy_pass http://sub2api_backend;
    access_log off;
    error_log /dev/null crit;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
}
```

It must not contain `mirror`, response-preview access logs, or a `3021`
upstream. The connection map keeps ordinary HTTP/SSE requests reusable and
only sends `Connection: upgrade` for an actual Upgrade request. Port `3021` is
reserved for the small provisioning endpoint. The source `geo` map evaluates
the original `$realip_remote_addr` so Cloudflare edge restriction remains in
force after the visitor address is restored. The restored `$remote_addr` is the
key for sync rate limiting and the only client address forwarded upstream.
Access and error logs are disabled for the complete API vhost, not only
`/v1/*`.

## Legacy Redis hardening

Before the privacy migration, the live legacy Redis cache can be hardened in
place without migrating its old `redis_data` contents. This is a separate,
source-only operation: it rotates the legacy Redis password, replaces the
password-bearing shell command with a SHA-256 ACL verifier, disables RDB/AOF,
uses a tmpfs `/data`, removes container logs, and adds a read-only root
filesystem, dropped capabilities, and `no-new-privileges`.

The controller is intentionally fixed to the current source project
`/home/ubuntu/sub2api-deploy` and the `sub2api`/`sub2api-redis` containers. It
accepts only their full, freshly collected IDs, pins Docker to the local Unix
socket, and creates root-only recovery files before modifying the legacy
Compose file or environment. It never imports, copies, or deletes the old
`redis_data` directory; that directory is retained as root-only residue for
the later, separately approved retirement stage.

Check the controller offline first. The check reads no private file or Docker
metadata:

```bash
sudo python3 deploy/harden-legacy-redis.py check
```

Run the apply operation only from a private root TTY in the trusted
`/opt/sub2api-gate-release` tree, after collecting the current full IDs from
the local Docker daemon. All three standard streams must be TTYs, so do not
redirect output or run it through a pipe. `--apply` rejects any other source
path; `/opt`, the release root, `deploy/`, the controller, and the exact
`deploy/require-clean-worktree.sh` guard must be root-owned and not
group/world-writable, and the guard must be executable. The source directory,
its Compose file, and `.env` must already be root-owned; the Compose file and
`.env` must use mode `0600`. Every directory from `/` through the pinned legacy
source path must be root-owned, non-symlinked, and not group/world-writable.
This deliberately blocks the current `/home/ubuntu/sub2api-deploy` layout
until a separately approved relocation or parent-directory hardening is
complete; this controller never changes `/home/ubuntu` ownership or relocates
the source tree. The clean-worktree guard must pass, and `/usr/bin/docker` must
be a root-owned non-group/world-writable regular executable. Docker is forced
to the local Unix socket and an empty root-only config. It prompts for the old
and new Redis passwords without placing either in command arguments or the
environment:

```bash
sudo python3 deploy/harden-legacy-redis.py --apply \
  --source-app-container sub2api \
  --source-app-id <fresh-64-hex-app-id> \
  --source-redis-container sub2api-redis \
  --source-redis-id <fresh-64-hex-redis-id>
```

Do not run it concurrently with Worker publication, sync canary, traffic
canary, or `maintenance-cutover.py`. A failed apply restores the original
Compose and environment, starts the legacy services again, verifies health,
removes the generated ACL, and preserves root-only recovery state only if a
rollback itself cannot be proven complete.

## Migrated-target traffic canary

`docker-compose.canary.yml` is still only the empty-data preflight on `18081`.
It cannot be promoted or passed to the Nginx switcher. The independent
`docker-compose.traffic-canary.yml` is the only stack allowed to bind `8081`.
It starts PostgreSQL 18 from the already logically migrated target directory,
an empty memory-only Redis 8.8.0 application cache, and Sub2API 0.1.171 from the
credential-free app metadata directory. It contains no sync service, publishes
neither PostgreSQL nor Redis, uses no `AUTO_SETUP`, and discards every
container's stdout/stderr. All three containers set the core-file ulimit to
zero; the release-wide preflight must also confirm that host swap is disabled.

The controller is offline and credential-free in its default mode:

```bash
python3 deploy/traffic-canary.py check
docker compose -f docker-compose.traffic-canary.yml \
  --profile traffic-canary config --no-interpolate
```

Only after the approved logical migration has committed, the target
`sub2api_app` role has been prepared, and the legacy services are still running,
start the traffic canary from a private root TTY. The three legacy names must
identify the containers actually serving loopback `8080`; do not substitute
the empty preflight containers:

```bash
sudo python3 deploy/traffic-canary.py --apply \
  --env-file /path/to/private.env \
  --wrangler-config /path/to/wrangler.private.jsonc \
  --legacy-sub2api-container legacy-sub2api \
  --legacy-postgres-container legacy-postgres \
  --legacy-redis-container legacy-redis
```

Before Docker starts, `--apply` requires the exact root-owned `/mnt/data` tree,
the PostgreSQL 18 `postgres/18/docker/PG_VERSION` and control file, the reviewed app `.installed`
marker, the hashed Redis ACL, private mode-`0600` environment and Wrangler
files, and a clean worktree. It runs the complete offline security preflight
with those two explicit paths, including host swap and free-space gates, and
pins Docker operations to the trusted local `/var/run/docker.sock` so a remote
context cannot be mistaken for the Nginx origin. It refuses pre-existing target
containers and then starts only
the target PostgreSQL and empty volatile Redis, compares the target PostgreSQL
cluster system identifier and Redis run ID with the live legacy services, runs
the privacy-residue/trigger and least-privilege app-role gates, and only then
starts Sub2API on `127.0.0.1:8081`. A failed start removes the canary containers
and network but never deletes or rewrites the bind-mounted migrated data.

Run the direct metadata-only API canary before changing Nginx. Its response body
is drained and discarded; the API key is read only from the private TTY:

```bash
python3 deploy/run-v1-responses-canary.py --apply \
  --url http://127.0.0.1:8081/v1/responses \
  --model reviewed-canary-model
sudo python3 deploy/traffic-canary.py verify \
  --legacy-sub2api-container legacy-sub2api \
  --legacy-postgres-container legacy-postgres \
  --legacy-redis-container legacy-redis
sudo bash deploy/switch-nginx-upstream.sh --apply --stage canary \
  --verify-url https://api.example.com/v1/responses \
  --approved-hostname api.example.com \
  --model reviewed-canary-model \
  --legacy-sub2api-container legacy-sub2api \
  --legacy-postgres-container legacy-postgres \
  --legacy-redis-container legacy-redis
```

The switcher repeats the live target-versus-legacy identity gate while holding
the shared Nginx operation lock, before it probes `8081` or modifies the active
upstream. This is the enforcement point that prevents the `18081` empty stack,
an arbitrary process on `8081`, or a target attached to the legacy physical
data from receiving traffic.

After a successful switch, keep the traffic-canary Compose project running on
`8081`; it is the managed production target for this release. Check it without
requiring the stopped legacy containers with
`sudo python3 deploy/traffic-canary.py status`. Do not run the base Compose
PostgreSQL/Redis services concurrently against the same bind paths, and do not
run `docker compose down` while Nginx points to `8081`. This release deliberately
does not automate a rename or `8081 -> 8080` promotion: that requires a separate
reviewed second-app-instance rollout so the serving target is never recreated
under traffic. Before the forward-only cleanup, rollback means first atomically
switching Nginx to the still-running legacy `8080` service and passing its
synthetic canary, then stopping the traffic-canary project without `--volumes`.
After legacy content is destroyed, recovery is forward-only.

## Bounded maintenance cutover

`maintenance-cutover.py` is the only controller for the first sanitized-data
cutover. Its default `check` mode is offline and does not read a private file,
connect Docker, inspect `/mnt/data`, contact a database, prompt for a secret, or
change a service:

```bash
python3 deploy/maintenance-cutover.py check
```

The private mode-`0600` environment must be supplied by an absolute path and
must include the source and target
PostgreSQL URLs plus the source and one-time target Redis migration values shown
in `.env.example`. The target URLs are fixed to loopback migration ports:
PostgreSQL `127.0.0.1:15432` and nonce Redis `127.0.0.1:16379`. The source
PostgreSQL URL must use the selected container's canonical RFC1918 IPv4 address
on port `5432` with `sslmode=disable`; it is never opened through a published
host port. `source-postgres-exec.py` verifies the exact full app and PostgreSQL
container IDs, their state, their shared Docker network, and the app's
`DATABASE_HOST`, `DATABASE_PORT`, and `DATABASE_DBNAME`. The host must be that
exact PostgreSQL endpoint's alias or address. Reviewed PostgreSQL 18 clients
then run inside that selected container over its Unix socket without putting a
password or URL in child argv or environment. A Redis loopback URL must match
the exact published binding; a Redis bridge address must equal the selected
exact container IP. The controller performs PostgreSQL database-identity
queries and Redis `AUTH`, `PING`, and `INFO server` before stopping either
writer. If an old service does not expose this reviewed local boundary, apply
fails during the zero-downtime preflight; do not add a public database or Redis
listener.

After the source privacy scrub and residue gate pass, create the safe metadata
export with `export-safe-metadata.sh --apply --env-file
/absolute/private/sub2api.env`. Immediately before maintenance, create and
verify the retirement identity record described below, then pass the export's
exact timestamped directory to the controller. Run apply from a private root
TTY with the same explicit paths, names, and full 64-character Docker IDs:

```bash
sudo python3 deploy/maintenance-cutover.py --apply \
  --env-file /absolute/private/sub2api.env \
  --wrangler-config /absolute/private/wrangler.private.jsonc \
  --safe-export-dir /mnt/data/sub2api-gate/safe-backup/export-YYYYMMDDTHHMMSSZ \
  --legacy-sub2api-container legacy-sub2api \
  --legacy-sub2api-id 64_HEX_CHARACTERS \
  --legacy-postgres-container legacy-postgres \
  --legacy-postgres-id 64_HEX_CHARACTERS \
  --legacy-redis-container legacy-redis \
  --legacy-redis-id 64_HEX_CHARACTERS \
  --legacy-app-path /absolute/legacy/app-data \
  --legacy-postgres-path /absolute/legacy/postgres-data \
  --legacy-redis-path /absolute/legacy/redis-data \
  --legacy-nginx-log-path /var/log/nginx \
  --verify-url https://api.example.com/v1/responses \
  --approved-hostname api.example.com \
  --model reviewed-canary-model
```

Apply requires absolute private env and Wrangler paths, a clean worktree, the
full security preflight, private TTY, and interactive migration TOTP. Before
any local command runs, argument parsing validates that the synthetic canary
uses the exact approved lowercase hostname, HTTPS `/v1/responses`, and a bounded
model identifier; controller preflight repeats this check. The later synthetic
API canary reads its API key from the same private TTY; neither secret is
accepted in argv. Before the
maintenance clock starts, the controller verifies the export's exact file set,
Git and policy hashes, then compares its PostgreSQL system identifier with the
live source cluster. It structurally verifies the active `/etc/nginx` tree has
no mirror/capture directive and that `/v1/*` uses the switchable named
`sub2api_backend` upstream. It then revalidates the retirement record,
legacy app/PG/Redis identities, fixed sync unit, `8080` and `3021` health,
source endpoints, target storage, and the two temporary loopback-only migration
services. The 180-second clock starts immediately before it stops the fixed
`sub2api-sync.service` and exact legacy Sub2API container. A stricter 60-second
traffic-interruption deadline stays active through the sanitized migration,
target health checks, and atomic Nginx switch to `8081`; it is cleared only
after the switched target is healthy. The interactive API canary follows after
traffic is restored. Legacy PostgreSQL and Redis remain running so the
sanitized logical streams can read them.

Only unexpired, allowlisted HMAC nonce markers enter the temporary nonce Redis.
The migration ACL is memory-backed, owned for UID/GID `999:1000`, mounted only
during migration, and reachable only on `127.0.0.1:16379`. It is removed before
the nonce store restarts with its runtime ACL and no published port. PostgreSQL
is similarly reachable on `127.0.0.1:15432` only for the logical stream and
role preparation; the controller recreates that container from the base
Compose definition without the port before starting Sub2API.

Any command failure, health failure, deadline, `SIGINT`, `SIGTERM`, or `SIGHUP` enters the
same fail-closed rollback. Rollback checks the exact legacy IDs before starting
PostgreSQL, Redis, and Sub2API, verifies `8080`, starts the unchanged fixed sync
unit and verifies `3021`, and only then atomically restores the stable Nginx
upstream. Once stable is confirmed it stops both target projects without
`--volumes`, confirms every target container is absent, removes the one-time
ACL, and empties only the fixed new target app, PostgreSQL, and nonce directories
so a later attempt starts fresh. Unsafe owners, symlinks, mounts, hard links, or
changed identities stop that reset and are reported together with the original
failure. The reset parses `/proc/self/mountinfo` before traversal and again
immediately before deletion, so same-device bind mounts are rejected as well as
cross-device mounts. Before any target starts, the controller atomically
publishes a root-only mode-`0600` version-2 recovery record at
`/mnt/data/sub2api-gate/safe-backup/maintenance-cutover-state.json`. It contains
only Git/container identities, phase flags, the private environment file's
non-content filesystem identity, and the sync unit path plus its content
SHA-256. It never contains a password, URL credential, database row, Redis
value, request, or response. Every rollback rechecks the unchanged private-file
identity, current systemd FragmentPath, and unit content before starting or
stopping any service. Normal success or a verified rollback fsyncs removal of
the record. `SIGKILL`, kernel failure, host power loss, and
Docker daemon loss cannot execute an in-process rollback; after the host and
Docker daemon are available, use the exact recorded legacy identities and the
same private environment to run:

```bash
sudo python3 deploy/maintenance-cutover.py --recover \
  --env-file /absolute/private/sub2api.env \
  --legacy-sub2api-container legacy-sub2api \
  --legacy-sub2api-id 64_HEX_CHARACTERS \
  --legacy-postgres-container legacy-postgres \
  --legacy-postgres-id 64_HEX_CHARACTERS \
  --legacy-redis-container legacy-redis \
  --legacy-redis-id 64_HEX_CHARACTERS
```

Recovery requires a root private TTY, a clean unchanged Git release, the same
unchanged private environment file identity, the unchanged sync unit content,
and interactive TOTP. It accepts either active upstream
stage, restores and health-checks the exact legacy services, atomically selects
stable `8080`, isolates the temporary targets, resets only the reviewed fresh
target directories, and then removes the recovery record. Repeated termination
signals are deferred until that rollback completes. Never delete or edit the
record to bypass `--recover`.

## Forward-only legacy data retirement

Legacy physical app, PostgreSQL, and Redis directories are removed only through
`retire-legacy-data.py`. Its default `check` mode is offline: it does not resolve
operator paths, access Docker, run a health request, write evidence, delete a
file, or issue discard. The tool has no production test-mode environment
override.

Record the legacy identities **before the maintenance window**, while the
named Nginx upstream's active include is still pinned to stable
`127.0.0.1:8080` and all three legacy containers are
running. This stage must not wait for, start, or inspect the migrated target:

```bash
sudo install -d -o root -g root -m 0700 /run/sub2api-gate
sudo python3 deploy/retire-legacy-data.py --apply --stage record \
  --legacy-app-path /absolute/legacy/app-data \
  --legacy-postgres-path /absolute/legacy/postgres-data \
  --legacy-redis-path /absolute/legacy/redis-data \
  --legacy-nginx-log-path /var/log/nginx \
  --legacy-sub2api-container legacy-sub2api \
  --legacy-postgres-container legacy-postgres \
  --legacy-redis-container legacy-redis
```

The root-only `0600` evidence file has the fixed production location
`/run/sub2api-gate/legacy-data-retirement.json`. It records only machine and
storage metadata: the local Docker daemon identity, three exact names and full
container IDs, the legacy app container ID, PostgreSQL system identifier,
Redis run ID, each explicit absolute path and its device/inode/owner/mode, and
the hosting mount target/device/filesystem identity. It contains no database
row, Redis value, credential, request, response, or conversation content. The
record stage refuses symlinks, overlapping directories, mount roots, nested
mounts, the repository, protected system trees, and every path equal to, below,
or above `/mnt/data/sub2api-gate`. Each directory must be the exact bind source
used at the reviewed container destination; Docker-managed named-volume
internals are deliberately outside this deletion tool.

The maintenance controller must repeat the same explicit arguments and run the
read-only identity gate immediately before stopping writers:

```bash
sudo python3 deploy/retire-legacy-data.py verify-record \
  --legacy-app-path /absolute/legacy/app-data \
  --legacy-postgres-path /absolute/legacy/postgres-data \
  --legacy-redis-path /absolute/legacy/redis-data \
  --legacy-nginx-log-path /var/log/nginx \
  --legacy-sub2api-container legacy-sub2api \
  --legacy-postgres-container legacy-postgres \
  --legacy-redis-container legacy-redis
```

`verify-record` does not write the record. It requires stable `8080`, the same
local daemon, live legacy runtime IDs, full container IDs and bind mounts, and
unchanged directory and filesystem identities. A mismatch cancels the
maintenance window; never restart an old application merely to recreate
evidence after writers have been stopped.

Final retirement is allowed only after Nginx is pinned to the healthy migrated
target on `8081`, the target privacy/schema/least-privilege/runtime gates pass,
all three recorded legacy container names and IDs are absent, and the separate
Docker-log evidence plus historical Sub2API/Nginx log cleanup has passed. Run
it with the same explicit identities and paths:

```bash
sudo python3 deploy/retire-legacy-data.py --apply --stage retire \
  --confirm-forward-only \
  --legacy-app-path /absolute/legacy/app-data \
  --legacy-postgres-path /absolute/legacy/postgres-data \
  --legacy-redis-path /absolute/legacy/redis-data \
  --legacy-nginx-log-path /var/log/nginx \
  --legacy-sub2api-container legacy-sub2api \
  --legacy-postgres-container legacy-postgres \
  --legacy-redis-container legacy-redis
```

The private terminal must also type `RETIRE LEGACY DATA FORWARD ONLY` exactly.
Before that prompt the tool completes every read-only gate and rechecks all
directory and filesystem identities. It removes only the three recorded exact
directories using file-descriptor-relative, symlink-resistant deletion,
atomically records progress after each directory, and invokes `fstrim` once per
revalidated hosting filesystem where discard is supported. `fstrim` is a
best-effort discard request. Neither directory removal nor discard guarantees
forensic-grade erasure on cloud volumes, snapshots, SSD firmware, or storage
provider backups; that stronger requirement needs an encrypted volume and key
destruction lifecycle.

## Provisioning sync canary

The provisioning service has its own Compose project in
`docker-compose.sync-canary.yml`; it is never part of the traffic-canary
Compose file and never participates in `/v1/*`. It joins only the migrated
target's internal data network, uses the fixed `sub2api_sync` PostgreSQL role,
and publishes the canary on `127.0.0.1:3022`. Its Redis accepts only persisted
HMAC nonce markers from the target `/mnt/data/sub2api-gate/redis/nonce`
directory. Both sync containers run as UID/GID 65532 with a read-only root,
discarded Docker logs, no capabilities, no Docker socket, and zero core dumps.

The default controller mode is offline and reads no private file:

```bash
python3 deploy/sync-canary.py check
python3 deploy/sync-canary.py prepare-image
python3 deploy/sync-canary.py start
docker compose -f docker-compose.sync-canary.yml \
  --profile sync-canary config --no-interpolate --quiet
```

Before the maintenance window, build and attest the sync image from a clean
worktree. `prepare-image` resolves only the two digest-pinned base manifests,
disables networking for every Dockerfile build step, runs the client as UID
65532 in a networkless read-only container, and requires exactly PostgreSQL
18.4. It then records the image ID together with the current Git commit in
root-owned mode-0600 `/run/sub2api-gate/sync-image.json`. The record contains no
credential. A reboot removes it and intentionally requires a fresh preparation.

```bash
sudo install -d -o root -g root -m 0700 /run/sub2api-gate
sudo python3 deploy/sync-canary.py prepare-image --apply
```

The command in the local release-gate list intentionally exercises the
non-mutating dry-run. The root `--apply` command above is the only supported
release build path; the runtime Compose files contain no sync build definition.

Only after that preparation and after the migrated-target traffic canary is
healthy, run the canary from a private root TTY. The controller rejects a
missing, replaced, or differently built image and a Git revision mismatch
before starting or stopping a service. It always passes `--no-build --pull
never` to Compose. It also requires the exact root-owned `/mnt/data` nonce
layout, validates the target Compose network and least-privilege role, then
prompts for the HMAC secret without placing it in an argument or file of its
own. Its random read-only `status` probe must succeed, and replaying the same
signed request must return 401 before the canary passes.

```bash
sudo python3 deploy/sync-canary.py start --apply \
  --env-file /path/to/private.env
sudo python3 deploy/sync-canary.py verify \
  --env-file /path/to/private.env
```

Promotion stops only the fixed legacy `sub2api-sync.service`, confirms loopback
3021 is free, starts the reviewed container on `127.0.0.1:3021`, repeats the
signed status and Redis replay probes, disables the legacy unit, and finally
stops the 3022 canary. Any failure before the new service is verified stops the
new container and attempts to restart the legacy service. It does not invoke
Nginx, edit an upstream, or stop the Sub2API traffic containers.

```bash
sudo python3 deploy/sync-canary.py promote --apply \
  --env-file /path/to/private.env
```

Before forward-only legacy data destruction, an explicitly approved rollback
stops the stable sync container, enables and starts the legacy unit, and
requires a signed status probe. If that probe fails, the controller restores
the stable container on 3021. Rollback never changes `/v1/*`.

```bash
sudo python3 deploy/sync-canary.py rollback --apply \
  --env-file /path/to/private.env
```

## Confirmed rollout order

The ignored `worker-allow-ip/wrangler.private.jsonc` must remain mode `0600`
and use strict JSON syntax (no comments or trailing commas). The local
preflight parses it structurally, disables invocation logs, verifies the
Durable Object rate limiter and SQLite `AUTH_STATE` v2 migration, and rejects
any Worker route outside an approved hostname's `/allow-ip*` path so `/v1/*`
cannot be intercepted. Production entry fails closed with HTTP 503 when the
`AUTH_STATE` binding is absent; it never falls back to eventually consistent
KV authentication state.

Run these steps only after a separate, explicit production approval. Stop at
the first failed checkpoint; never skip ahead.

1. Require a clean worktree, mode-`0600` private files, pinned image digests,
   the complete `/mnt/data/sub2api-gate` directory tree, the configured free
   space threshold, no active host swap, disabled container core dumps, and all
   required Worker Secret names. Run the complete local gate set again.
2. Back up the live Nginx configuration. Atomically replace only the `/v1/*`
   location with the direct named `sub2api_backend` upstream, whose active
   include initially points to `127.0.0.1:8080`; remove mirror/capture,
   run `nginx -t`, reload, and verify that rollback restores the prior config.
3. Confirm Sub2API file logging is off and its Docker log driver is `none`.
   When no verifier exists, enroll the existing administrator TOTP once from
   the private server TTY with `sudo python3
   deploy/verify-migration-totp.py enroll --apply`, after the out-of-band
   existing-seed confirmation described above. When a verifier exists but its
   old seed is unavailable, complete the independently audited
   [Administrator TOTP rotation](#administrator-totp-rotation) first; never
   delete local verifier/replay files to re-enroll. After enrollment or a
   proven rotation, run `run-database-migration.sh privacy --apply --env-file
   /absolute/path/to/private.env`: the short guard transaction
   commits before batched history cleanup. If cleanup fails, keep the guards
   installed and resolve the schema conflict before continuing. Run
   `verify-runtime-privacy.py --verify` from the private database environment;
   it must confirm both fail-closed settings and the enabled protection trigger.
4. Only after the residue gate passes, create the fixed-column, read-only safe
   metadata export from the sanitized source with `export-safe-metadata.sh
   --apply --env-file /absolute/path/to/private.env`. The tool reads only the
   explicit `SUB2API_SOURCE_DATABASE_URL`; it does not use the target app URL.
   Its manifest binds the source cluster ID, database OID, and database name;
   maintenance rechecks the same tuple before stopping any writer.
   Do not create a full database, WAL, Redis AOF, application-directory, or
   content backup.
5. Run `docker-compose.canary.yml` only as an isolated empty-data preflight. Its
   PostgreSQL and Redis are tmpfs services on a private Compose network. Verify
   the pinned 0.1.171 binary, startup, health, and no-file/no-Docker-log controls,
   through loopback port `18081`, then stop it. It has no production account or
   API key and must never be used as an Nginx upstream or as a `/v1/responses`
   acceptance canary. Port `8081` remains reserved for the later migrated-target
   traffic canary, so the switch tooling cannot accidentally select this stack.
6. While stable `8080` and all legacy containers are still running, create the
   fixed root-only legacy data identity record described above. Configure only
   reviewed loopback/bridge source endpoints in the private environment, then
   run `maintenance-cutover.py --apply` with the exact safe-export directory
   plus the same paths, names, and full container IDs. Do not run the individual
   migration or upstream-switch tools
   around it; the controller owns their ordering and the shared Nginx lock.
7. The controller completes its zero-downtime endpoint, target, privacy, and
   identity preflight, then starts the maximum 180-second window. It stops the
   fixed sync writer and exact legacy app while leaving legacy PostgreSQL/Redis
   readable, streams sanitized PostgreSQL, restores only allowlisted unexpired
   HMAC nonces, migrates optional validated pricing, prepares the app role, and
   removes both temporary loopback migration ports before starting Sub2API.
8. The same controller proves the target app/container, PostgreSQL cluster, and
   Redis identities differ from stopped legacy, switches Nginx to fixed `8081`,
   and runs the metadata-only `/v1/responses` canary. A failure or deadline runs
   the ordered rollback and fresh-target reset described above. On success keep
   the verified traffic stack on `8081`, run `verify-runtime-privacy.py --verify`
   again, and do not attach old physical PostgreSQL, WAL, Redis AOF, log,
   preview, capture, or `config.yaml` paths. No automatic port promotion is
   part of this release.
9. Run sync as a non-root, read-only canary on `127.0.0.1:3022`, using its
   least-privilege database role and Redis nonce store. After `/healthz` and
   provisioning tests pass, replace the legacy service and return to loopback
   port `3021`. This phase must never touch the `/v1/*` request path.
10. Run the explicit AOP `upload` stage without associating the hostname,
    install the emitted CA in Nginx `optional` mode, then run `associate`. Only
    after the fixed hostname GET confirms the exact certificate as active may
    the installer record a real public probe and switch to `required`. Keep the
    unknown Host/SNI vhost at `444` and retain the installer's automatic config
    restore path.
11. Run Worker tests and the real local Wrangler dry-run, initialize only
    missing managed Secrets, verify all required Secret names, and publish the
    Worker atomically. Observe before starting any forward-only credential work.
12. Run the TOTP-protected invite credential migration, securely distribute
    one-time access keys, and start the seven-day UUID deadline. Then run
    `node deploy/migrate-cloudflare-comments.mjs --apply` as the same deployment
    operator from the same private terminal. The tool reads the HMAC only from
    the operator-owned temporary file, never from argv or the environment, and
    logically erases/unlinks it only after the complete Rules List replacement
    is remotely verified. If
    legacy comments remain but that file is missing, stop and perform a
    separately reviewed HMAC credential rotation; never generate over the
    existing remote Secret. Finally run the transactional
    `default -> openai-default` migration and build usage indexes concurrently.
13. Before removing the stopped legacy Sub2API container, use the already
    created fixed root-only runtime evidence directory and record its exact local-Docker
    identity and validated `LogPath`. The record command never reads container
    environment/config data and never prints the path. Remove the container,
    then pass the same explicit name to cleanup and the final residue gate:

    ```bash
    sudo install -d -o root -g root -m 0700 /run/sub2api-gate
    sudo bash deploy/cleanup-conversation-logs.sh --apply --stage record \
      --legacy-container legacy-sub2api
    # Remove exactly legacy-sub2api through the reviewed container rollout.
    sudo bash deploy/cleanup-conversation-logs.sh --apply --stage cleanup \
      --legacy-container legacy-sub2api
    sudo bash deploy/cleanup-conversation-logs.sh verify \
      --legacy-container legacy-sub2api
    ```

    `--apply` and `verify` fail unless the recorded daemon/root still match,
    both the exact legacy name and container ID are absent, and Docker removed
    the recorded `LogPath` and container-specific log directory with the
    container. The script never removes Docker
    internals itself. It only deletes the reviewed Sub2API/Nginx log patterns,
    waits under normal traffic, and checks that they were not recreated. Only
    after every target gate passes, remove the exact legacy PostgreSQL and Redis
    containers without deleting storage, then run `retire-legacy-data.py
    --apply --stage retire` with the paths and names from the pre-maintenance
    record. It refuses any surviving legacy name or full ID, repeats the live
    sanitized-target/privacy/health gate, checks Nginx `8081`, and requests
    filesystem discard only after the three exact directories are gone. Do not
    retain them as a long-term rollback copy; after this point recovery is
    forward-only. Discard does not guarantee forensic-grade erasure.
14. After every phase, run a real synthetic `/v1/responses` request and discard
    its body. Record only status, request ID, token/cost metadata, and latency;
    verify the path remains `Cloudflare -> Nginx -> Sub2API` with no Worker or
    sync hop.

## Post-deploy gates

- `default` has no active group and no active API keys.
- `openai-default` owns every migrated key and subscription reference.
- `request_logs` has no capture columns.
- `content_moderation_logs`, `ops_error_logs`, and `ops_system_logs` payload fields remain empty after a controlled error request.
- `/v1/*` latency does not include the sync service and no request or response body is mirrored.
- Usage rows still expose tokens, cost, model, latency, endpoint, and request ID only.

The Worker commands require the ignored `worker-allow-ip/wrangler.private.jsonc`.
Secrets remain Cloudflare Worker Secrets and must not be placed in any repo
file. Check/dry-run reports that remote Secrets are unverified and makes no
secret-list request. After explicit approval, the apply path verifies only the
required remote secret names, suppresses the returned list, and fails before
publishing if any name is missing.

The Worker enforces five failed admin logins per 15-minute HMAC-keyed window.
Keep a Cloudflare rate-limit rule on public/admin POST endpoints as an outer
abuse control, but do not add a Worker or sync hop to `/v1/*`. The WAF allowlist
continues to protect API traffic without changing the direct origin path.
