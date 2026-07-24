#!/bin/bash
set -euo pipefail

readonly SAFE_COMMAND_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
readonly ENV_BINARY="/usr/bin/env"
readonly PYTHON_BINARY="/usr/bin/python3"
readonly READLINK="/usr/bin/readlink"
readonly STAT="/usr/bin/stat"
readonly FIXED_NODE_BINARY="/usr/bin/node"
readonly FIXED_NPM_BINARY="/usr/bin/npm"
readonly TRUSTED_RELEASE_ROOT="/opt/sub2api-gate-release"
readonly TRUSTED_RELEASE_PARENT="/opt"
readonly TRUSTED_CONTROLLER="$TRUSTED_RELEASE_ROOT/deploy/deploy-worker.sh"
readonly TRUSTED_RELEASE_GUARD="$TRUSTED_RELEASE_ROOT/deploy/require-clean-worktree.sh"
readonly TRUSTED_RUNTIME_ATTESTOR="$TRUSTED_RELEASE_ROOT/deploy/worker-runtime-attestation.py"

export WRANGLER_SEND_METRICS=false
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH PYTHONHOME PYTHONPATH PYTHONSTARTUP \
  GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM \
  GIT_CONFIG_NOSYSTEM
IFS=$' \t\n'

usage() {
  echo "usage: $0 [check|--apply] [--totp-rotation-stage compatibility|stage|promoted|final-source]" >&2
  exit 2
}

mode="check"
rotation_stage="compatibility"
mode_seen=false
stage_seen=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    check|--apply)
      [ "$mode_seen" = false ] || usage
      mode="$1"
      mode_seen=true
      ;;
    --totp-rotation-stage)
      [ "$stage_seen" = false ] || usage
      [ "$#" -ge 2 ] || usage
      rotation_stage="$2"
      stage_seen=true
      shift
      ;;
    *) usage ;;
  esac
  shift
done

script_reference="${BASH_SOURCE[0]}"
script_directory="${script_reference%/*}"
if [ "$script_directory" = "$script_reference" ]; then
  script_directory='.'
fi
controller_directory="$(CDPATH= builtin cd -P -- "$script_directory" && builtin pwd -P)"
controller_basename="${script_reference##*/}"
controller_path="$controller_directory/$controller_basename"
repo_dir="$(CDPATH= builtin cd -P -- "$controller_directory/.." && builtin pwd -P)"
worker_dir="$repo_dir/worker-allow-ip"
default_wrangler_config="$worker_dir/wrangler.private.jsonc"
wrangler_config="${SUB2API_WRANGLER_CONFIG:-$default_wrangler_config}"
secret_manifest="$worker_dir/required-secrets.json"
wrangler_entry="$worker_dir/node_modules/wrangler/bin/wrangler.js"
required_wrangler_version="4.112.0"
node_bin="${SUB2API_NODE_BINARY:-$(command -v node || true)}"
npm_bin="${SUB2API_NPM_BINARY:-$(command -v npm || true)}"

production_failure() {
  echo "Worker production publishing requires the trusted production release tree" >&2
  exit 1
}

require_trusted_release_path() {
  local path="$1"
  local kind="$2"
  local require_executable="$3"
  local require_single_link="$4"
  local metadata owner group permissions links mode_value

  [ ! -L "$path" ] && [ -e "$path" ] || production_failure
  case "$kind" in
    directory) [ -d "$path" ] || production_failure ;;
    regular) [ -f "$path" ] || production_failure ;;
    *) production_failure ;;
  esac
  metadata="$("$STAT" -c "%u:%g:%a:%h" -- "$path")" || production_failure
  IFS=: read -r owner group permissions links <<<"$metadata"
  [[ "$owner" = 0 && "$group" = 0 && "$permissions" =~ ^[0-7]{3,4}$ && "$links" =~ ^[0-9]+$ ]] || production_failure
  mode_value=$((8#$permissions))
  (( (mode_value & 8#022) == 0 )) || production_failure
  if [ "$require_single_link" = true ] && [ "$links" -ne 1 ]; then
    production_failure
  fi
  if [ "$require_executable" = true ] && (( (mode_value & 8#100) == 0 )); then
    production_failure
  fi
}

require_trusted_release_tree() {
  local source_path

  [ "$repo_dir" = "$TRUSTED_RELEASE_ROOT" ] || production_failure
  source_path="$("$READLINK" -f -- "$controller_path")" || production_failure
  [ "$source_path" = "$TRUSTED_CONTROLLER" ] || production_failure
  require_trusted_release_path / directory false false
  require_trusted_release_path "$TRUSTED_RELEASE_PARENT" directory false false
  require_trusted_release_path "$TRUSTED_RELEASE_ROOT" directory false false
  require_trusted_release_path "$TRUSTED_RELEASE_ROOT/deploy" directory false false
  require_trusted_release_path "$TRUSTED_CONTROLLER" regular false true
  require_trusted_release_path "$TRUSTED_RELEASE_GUARD" regular true true
  require_trusted_release_path "$TRUSTED_RUNTIME_ATTESTOR" regular false true
}

require_trusted_private_wrangler_config() {
  local metadata

  [ ! -L "$wrangler_config" ] && [ -f "$wrangler_config" ] || {
    echo "trusted private Wrangler config must be a root-owned single-link mode-0600 regular file" >&2
    exit 1
  }
  metadata="$("$STAT" -c "%u:%g:%a:%h" -- "$wrangler_config")" || {
    echo "trusted private Wrangler config must be a root-owned single-link mode-0600 regular file" >&2
    exit 1
  }
  [ "$metadata" = "0:0:600:1" ] || {
    echo "trusted private Wrangler config must be a root-owned single-link mode-0600 regular file" >&2
    exit 1
  }
}

if [ "$mode" = "--apply" ]; then
  if [ "$EUID" -ne 0 ] || [ "$repo_dir" != "$TRUSTED_RELEASE_ROOT" ]; then
    echo "Worker production publishing requires root from the trusted production release tree" >&2
    exit 1
  fi
  if [ ! -t 0 ] || [ ! -t 1 ] || [ ! -t 2 ]; then
    echo "Worker production publishing requires a private interactive TTY" >&2
    exit 1
  fi
  if [ "${SUB2API_WRANGLER_CONFIG+x}" = x ]; then
    echo "Worker production publishing does not accept a Wrangler config override" >&2
    exit 1
  fi
  if [ "${SUB2API_NODE_BINARY+x}" = x ] || [ "${SUB2API_NPM_BINARY+x}" = x ]; then
    echo "Worker production publishing does not accept runtime overrides" >&2
    exit 1
  fi

  PATH="$SAFE_COMMAND_PATH"
  export PATH
  HOME=/root
  export HOME
  unset SUB2API_WRANGLER_CONFIG DOCKER_CONFIG DOCKER_CONTEXT DOCKER_HOST \
    SUB2API_NODE_BINARY SUB2API_NPM_BINARY \
    NODE_OPTIONS NPM_CONFIG_USERCONFIG NPM_CONFIG_PREFIX NPM_CONFIG_REGISTRY \
    WRANGLER_CONFIG_PATH CLOUDFLARE_API_TOKEN
  node_bin="$FIXED_NODE_BINARY"
  npm_bin="$FIXED_NPM_BINARY"

  require_trusted_release_tree
  require_trusted_private_wrangler_config
  "$ENV_BINARY" -i \
    PATH="$SAFE_COMMAND_PATH" \
    HOME=/root \
    WRANGLER_SEND_METRICS=false \
    CLOUDFLARE_INCLUDE_PROCESS_ENV=false \
    CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV=false \
    "$TRUSTED_RELEASE_GUARD" check
  "$ENV_BINARY" -i \
    PATH="$SAFE_COMMAND_PATH" \
    HOME=/root \
    "$PYTHON_BINARY" -I "$TRUSTED_RUNTIME_ATTESTOR" verify
fi

run_publish_command() {
  if [ "$mode" = "--apply" ]; then
    "$ENV_BINARY" -i \
      PATH="$SAFE_COMMAND_PATH" \
      HOME=/root \
      WRANGLER_SEND_METRICS=false \
      CLOUDFLARE_INCLUDE_PROCESS_ENV=false \
      CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV=false \
      "$@"
  else
    "$@"
  fi
}
case "$rotation_stage" in
  compatibility)
    rotation_secret_requirement="--forbid-totp-rotation-staging"
    ;;
  stage|promoted|final-source)
    rotation_secret_requirement="--require-totp-rotation-staging"
    ;;
  *)
    echo "unsupported Worker TOTP rotation stage" >&2
    exit 2
    ;;
esac

[ -f "$wrangler_config" ] || { echo "private Wrangler config is missing: $wrangler_config" >&2; exit 1; }
[ -f "$wrangler_entry" ] && [ ! -L "$wrangler_entry" ] || { echo "attested Wrangler entry is missing; prepare the Worker runtime first" >&2; exit 1; }
[ -x "$node_bin" ] || { echo "Node.js 22 or newer is required" >&2; exit 1; }
[ -x "$npm_bin" ] || { echo "npm is required for the Worker dependency audit" >&2; exit 1; }
if ! run_publish_command "$node_bin" -e 'const major = Number(process.versions.node.split(".")[0]); process.exit(Number.isInteger(major) && major >= 22 ? 0 : 1)'; then
  echo "Node.js 22 or newer is required" >&2
  exit 1
fi
wrangler_version="$(run_publish_command "$node_bin" "$wrangler_entry" --version 2>/dev/null)" || {
  echo "could not verify the locked local Wrangler version" >&2
  exit 1
}
if [ "$wrangler_version" != "$required_wrangler_version" ]; then
  echo "locked local Wrangler $required_wrangler_version is required" >&2
  exit 1
fi
echo "auditing locked Worker dependencies for high or critical vulnerabilities"
run_publish_command "$npm_bin" --prefix "$worker_dir" audit --audit-level=high --package-lock-only --ignore-scripts
run_publish_command "$node_bin" "$repo_dir/deploy/validate-wrangler-config.mjs" "$wrangler_config" "$secret_manifest"

if [ "$rotation_stage" = "final-source" ]; then
  echo "verifying final Worker source does not read TOTP rotation Secrets"
  run_publish_command "$node_bin" "$repo_dir/deploy/verify-final-worker-totp-source.mjs" "$worker_dir/src"
fi

if [ "$mode" != "--apply" ]; then
  echo "Worker deployment check only; no Worker will be published"
  echo "Remote Worker Secrets were not verified in check mode"
  exec "$node_bin" "$wrangler_entry" deploy --dry-run --config "$wrangler_config"
fi

run_publish_command bash "$repo_dir/deploy/security-preflight.sh" check \
  --env-file "/mnt/data/sub2api-gate/private/.env" \
  --wrangler-config "$wrangler_config"
echo "verifying Cloudflare Worker secret names for TOTP rotation stage: $rotation_stage"
run_publish_command "$node_bin" "$wrangler_entry" secret list --format json --config "$wrangler_config" \
  | run_publish_command "$node_bin" "$repo_dir/deploy/verify-worker-secret-list.mjs" "$secret_manifest" "$rotation_secret_requirement"
echo "explicit --apply accepted; publishing Worker"
exec "$ENV_BINARY" -i PATH="$SAFE_COMMAND_PATH" HOME=/root WRANGLER_SEND_METRICS=false \
  CLOUDFLARE_INCLUDE_PROCESS_ENV=false CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV=false \
  "$FIXED_NODE_BINARY" "$wrangler_entry" deploy --config "$wrangler_config"
