#!/usr/bin/env bash
set -euo pipefail

export WRANGLER_SEND_METRICS=false

mode="${1:-check}"
case "$mode" in
  check|--apply) ;;
  *) echo "usage: $0 [check|--apply]" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
worker_dir="$repo_dir/worker-allow-ip"
wrangler_config="${SUB2API_WRANGLER_CONFIG:-$worker_dir/wrangler.private.jsonc}"
secret_manifest="$worker_dir/required-secrets.json"
wrangler_bin="$worker_dir/node_modules/.bin/wrangler"
required_wrangler_version="4.112.0"

[ -f "$wrangler_config" ] || { echo "private Wrangler config is missing: $wrangler_config" >&2; exit 1; }
[ -x "$wrangler_bin" ] || { echo "local Wrangler binary is missing; install locked dependencies first" >&2; exit 1; }
command -v node >/dev/null 2>&1 || { echo "Node.js 22 or newer is required" >&2; exit 1; }
command -v npm >/dev/null 2>&1 || { echo "npm is required for the Worker dependency audit" >&2; exit 1; }
if ! node -e 'const major = Number(process.versions.node.split(".")[0]); process.exit(Number.isInteger(major) && major >= 22 ? 0 : 1)'; then
  echo "Node.js 22 or newer is required" >&2
  exit 1
fi
wrangler_version="$("$wrangler_bin" --version 2>/dev/null)" || {
  echo "could not verify the locked local Wrangler version" >&2
  exit 1
}
if [ "$wrangler_version" != "$required_wrangler_version" ]; then
  echo "locked local Wrangler $required_wrangler_version is required" >&2
  exit 1
fi
echo "auditing locked Worker dependencies for high or critical vulnerabilities"
npm --prefix "$worker_dir" audit --audit-level=high --package-lock-only --ignore-scripts
node "$repo_dir/deploy/validate-wrangler-config.mjs" "$wrangler_config" "$secret_manifest"

if [ "$mode" != "--apply" ]; then
  echo "Worker deployment check only; no Worker will be published"
  echo "Remote Worker Secrets were not verified in check mode"
  exec "$wrangler_bin" deploy --dry-run --config "$wrangler_config"
fi

"$repo_dir/deploy/require-clean-worktree.sh" check
"$repo_dir/deploy/security-preflight.sh" check --wrangler-config "$wrangler_config"
echo "verifying required Cloudflare Worker secret names"
"$wrangler_bin" secret list --format json --config "$wrangler_config" \
  | node "$repo_dir/deploy/verify-worker-secret-list.mjs" "$secret_manifest"
echo "explicit --apply accepted; publishing Worker"
exec "$wrangler_bin" deploy --config "$wrangler_config"
