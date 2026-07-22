#!/bin/bash
set -euo pipefail

test_mode="${SUB2API_UPSTREAM_TEST_MODE:-0}"
case "$test_mode" in
  0|1) ;;
  *) echo "SUB2API_UPSTREAM_TEST_MODE must be 0 or 1" >&2; exit 1 ;;
esac
if [ "$test_mode" = "0" ]; then
  PATH="/usr/sbin:/usr/bin:/sbin:/bin"
  export PATH
fi

mode="${1:-check}"
case "$mode" in
  check|--apply) shift || true ;;
  *)
    echo "usage: $0 [check|--apply] --stage stable|canary [--verify-url URL --model MODEL --approved-hostname HOST] [--legacy-sub2api-container NAME --legacy-postgres-container NAME --legacy-redis-container NAME]" >&2
    exit 2
    ;;
esac

stage=""
verify_url=""
model=""
approved_hostname=""
legacy_sub2api_container=""
legacy_postgres_container=""
legacy_redis_container=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --stage)
      [ "$#" -ge 2 ] || { echo "--stage requires a value" >&2; exit 2; }
      stage="$2"
      shift 2
      ;;
    --verify-url)
      [ "$#" -ge 2 ] || { echo "--verify-url requires a value" >&2; exit 2; }
      verify_url="$2"
      shift 2
      ;;
    --model)
      [ "$#" -ge 2 ] || { echo "--model requires a value" >&2; exit 2; }
      model="$2"
      shift 2
      ;;
    --approved-hostname)
      [ "$#" -ge 2 ] || { echo "--approved-hostname requires a value" >&2; exit 2; }
      approved_hostname="$2"
      shift 2
      ;;
    --legacy-sub2api-container)
      [ "$#" -ge 2 ] || { echo "--legacy-sub2api-container requires a value" >&2; exit 2; }
      legacy_sub2api_container="$2"
      shift 2
      ;;
    --legacy-postgres-container)
      [ "$#" -ge 2 ] || { echo "--legacy-postgres-container requires a value" >&2; exit 2; }
      legacy_postgres_container="$2"
      shift 2
      ;;
    --legacy-redis-container)
      [ "$#" -ge 2 ] || { echo "--legacy-redis-container requires a value" >&2; exit 2; }
      legacy_redis_container="$2"
      shift 2
      ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

case "$stage" in
  stable) target_port=8080 ;;
  canary) target_port=8081 ;;
  *) echo "--stage must be stable or canary" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
source_file="$repo_dir/nginx/snippets/sub2api-upstream-$stage.conf"
expected_line="server 127.0.0.1:$target_port;"
if [ ! -f "$source_file" ] || [ -L "$source_file" ] \
   || [ "$(cat -- "$source_file")" != "$expected_line" ]; then
  echo "tracked upstream stage is missing or does not contain the fixed loopback target" >&2
  exit 1
fi

nginx_root="${SUB2API_NGINX_ROOT:-/etc/nginx}"
if [ "$test_mode" = "1" ] && [ "$nginx_root" = "/etc/nginx" ]; then
  echo "test mode may not target the production Nginx root" >&2
  exit 1
fi
if [ "$nginx_root" != "/etc/nginx" ] && [ "$test_mode" != "1" ]; then
  echo "SUB2API_NGINX_ROOT override is allowed only in explicit test mode" >&2
  exit 1
fi
case "$nginx_root" in
  /*) ;;
  *) echo "Nginx root must be an absolute path" >&2; exit 1 ;;
esac
if [ "$nginx_root" = "/" ]; then
  echo "Nginx root is unsafe" >&2
  exit 1
fi

snippets_dir="$nginx_root/snippets"
active_file="$snippets_dir/sub2api-upstream-active.conf"
state_root="$nginx_root/sub2api-gate"
backup_root="$state_root/backups"
operation_lock="$state_root/nginx-operation.lock"

expected_uid="$(id -u)"
if [ "$test_mode" != "1" ]; then
  expected_uid=0
fi

require_trusted_directory() {
  local path="$1"
  local label="$2"
  local resolved_path path_uid path_mode_text path_mode
  if [ ! -d "$path" ] || [ -L "$path" ]; then
    echo "$label is missing or unsafe" >&2
    return 1
  fi
  resolved_path="$(realpath -e -- "$path")" || {
    echo "$label could not be resolved" >&2
    return 1
  }
  if [ "$resolved_path" != "$path" ]; then
    echo "$label must not traverse symlinks" >&2
    return 1
  fi
  path_uid="$(stat -c '%u' -- "$path")" || return 1
  path_mode_text="$(stat -c '%a' -- "$path")" || return 1
  path_mode=$((8#$path_mode_text))
  if [ "$path_uid" -ne "$expected_uid" ] || ((path_mode & 0022)); then
    echo "$label has unsafe ownership or permissions" >&2
    return 1
  fi
}

require_trusted_directory_if_present() {
  local path="$1"
  local label="$2"
  if [ -e "$path" ] || [ -L "$path" ]; then
    require_trusted_directory "$path" "$label"
  fi
}

ensure_trusted_directory() {
  local path="$1"
  local label="$2"
  local create_mode="$3"
  if [ ! -e "$path" ] && [ ! -L "$path" ]; then
    if ! mkdir -m "$create_mode" -- "$path"; then
      [ -e "$path" ] || [ -L "$path" ] || {
        echo "$label could not be created" >&2
        return 1
      }
    fi
  fi
  require_trusted_directory "$path" "$label"
}

require_trusted_file() {
  local path="$1"
  local label="$2"
  local path_uid path_mode_text path_mode
  if [ -L "$path" ] || [ ! -f "$path" ]; then
    echo "$label must be a regular non-symlink file" >&2
    return 1
  fi
  path_uid="$(stat -c '%u' -- "$path")" || return 1
  path_mode_text="$(stat -c '%a' -- "$path")" || return 1
  path_mode=$((8#$path_mode_text))
  if [ "$path_uid" -ne "$expected_uid" ] || ((path_mode & 0022)); then
    echo "$label has unsafe ownership or permissions" >&2
    return 1
  fi
}

require_trusted_file_if_present() {
  local path="$1"
  local label="$2"
  if [ -e "$path" ] || [ -L "$path" ]; then
    require_trusted_file "$path" "$label"
  fi
}

validate_active_target() {
  require_trusted_file "$active_file" "active Nginx upstream"
  if ! cmp -s "$active_file" "$repo_dir/nginx/snippets/sub2api-upstream-stable.conf" \
     && ! cmp -s "$active_file" "$repo_dir/nginx/snippets/sub2api-upstream-canary.conf"; then
    echo "active upstream contains an unreviewed target" >&2
    return 1
  fi
}

validate_apply_paths() {
  require_trusted_directory "$nginx_parent" "Nginx root parent"
  require_trusted_directory "$nginx_root" "Nginx root"
  require_trusted_directory "$snippets_dir" "Nginx snippets directory"
  require_trusted_directory_if_present "$state_root" "Nginx state directory"
  require_trusted_directory_if_present "$backup_root" "Nginx backup directory"
  require_trusted_file_if_present "$operation_lock" "Nginx operation lock"
  validate_active_target
}

acquire_operation_lock() {
  local lock_path_identity lock_fd_identity
  require_trusted_file_if_present "$operation_lock" "Nginx operation lock"
  exec {nginx_lock_fd}>>"$operation_lock" || {
    echo "could not open the shared Nginx operation lock" >&2
    return 1
  }
  require_trusted_file "$operation_lock" "Nginx operation lock"
  lock_path_identity="$(stat -Lc '%d:%i' -- "$operation_lock")" || return 1
  lock_fd_identity="$(stat -Lc '%d:%i' -- "/proc/$$/fd/$nginx_lock_fd")" || return 1
  if [ "$lock_path_identity" != "$lock_fd_identity" ]; then
    echo "Nginx operation lock changed while it was opened" >&2
    return 1
  fi
  if ! "$flock_bin" -n "$nginx_lock_fd"; then
    echo "another Nginx apply operation is already in progress" >&2
    return 1
  fi
}

if [ "$mode" != "--apply" ]; then
  echo "Nginx upstream check only: stage=$stage target=127.0.0.1:$target_port"
  echo "no health request was sent, no file was changed, and Nginx was not reloaded"
  exit 0
fi

if [ -z "$verify_url" ] || [ -z "$model" ] || [ -z "$approved_hostname" ]; then
  echo "--apply requires --verify-url, --model, and --approved-hostname for the end-to-end canary" >&2
  exit 2
fi
if [ "$stage" = "canary" ] && {
  [ -z "$legacy_sub2api_container" ] \
    || [ -z "$legacy_postgres_container" ] \
    || [ -z "$legacy_redis_container" ];
}; then
  echo "canary --apply requires all three legacy container identities" >&2
  exit 2
fi
if [ "$test_mode" != "1" ] && [ "$(id -u)" -ne 0 ]; then
  echo "--apply must run as root" >&2
  exit 1
fi
if [ "$test_mode" != "1" ] && { [ ! -t 0 ] || [ ! -t 2 ]; }; then
  echo "--apply requires a private interactive terminal for the synthetic canary" >&2
  exit 1
fi
if [ "$test_mode" = "1" ] && [ -n "${SUB2API_RELEASE_GUARD:-}" ]; then
  "$SUB2API_RELEASE_GUARD" check
else
  "$repo_dir/deploy/require-clean-worktree.sh" check
fi

if [ "$test_mode" = "1" ]; then
  nginx_bin="$(command -v nginx)"
  systemctl_bin="$(command -v systemctl)"
  curl_bin="$(command -v curl)"
  flock_bin="$(command -v flock)"
  canary_runner="${SUB2API_UPSTREAM_CANARY_RUNNER:?test mode requires SUB2API_UPSTREAM_CANARY_RUNNER}"
  traffic_canary_verifier="${SUB2API_TRAFFIC_CANARY_VERIFIER:?test mode requires SUB2API_TRAFFIC_CANARY_VERIFIER}"
else
  nginx_bin="/usr/sbin/nginx"
  systemctl_bin="/usr/bin/systemctl"
  curl_bin="/usr/bin/curl"
  flock_bin="/usr/bin/flock"
  canary_runner="$repo_dir/deploy/run-v1-responses-canary.py"
  traffic_canary_verifier="$repo_dir/deploy/traffic-canary.py"
fi
for executable in "$nginx_bin" "$systemctl_bin" "$curl_bin" "$flock_bin" "$canary_runner" "$traffic_canary_verifier"; do
  if [ ! -x "$executable" ]; then
    echo "required upstream switch executable is unavailable" >&2
    exit 1
  fi
done

umask 077
if [ "$test_mode" = "1" ]; then
  nginx_parent="$(dirname -- "$nginx_root")"
else
  nginx_parent="/etc"
fi
validate_apply_paths
ensure_trusted_directory "$state_root" "Nginx state directory" 0700
acquire_operation_lock
validate_apply_paths
ensure_trusted_directory "$backup_root" "Nginx backup directory" 0700
validate_apply_paths

if [ "$stage" = "canary" ]; then
  "$traffic_canary_verifier" verify \
    --legacy-sub2api-container "$legacy_sub2api_container" \
    --legacy-postgres-container "$legacy_postgres_container" \
    --legacy-redis-container "$legacy_redis_container"
fi

"$curl_bin" --silent --show-error --fail --noproxy '*' \
  --connect-timeout 2 --max-time 5 --output /dev/null \
  "http://127.0.0.1:$target_port/health"

backup_dir="$(mktemp -d "$backup_root/$(date -u +%Y%m%dT%H%M%SZ)-upstream-XXXXXX")"
chmod 0700 "$backup_dir"
require_trusted_directory "$backup_dir" "Nginx upstream backup"
cp -a -- "$active_file" "$backup_dir/active"

restore_needed=0
restore() {
  restore_failed=0
  rm -f -- "$active_file.tmp.$$" || restore_failed=1
  cp -a -- "$backup_dir/active" "$active_file.tmp.$$" || restore_failed=1
  mv -f -- "$active_file.tmp.$$" "$active_file" || restore_failed=1
  if "$nginx_bin" -t >/dev/null 2>&1; then
    "$systemctl_bin" reload nginx >/dev/null 2>&1 || restore_failed=1
  else
    restore_failed=1
  fi
  if [ "$restore_failed" -eq 0 ]; then
    echo "upstream switch failed; previous target was restored and reloaded" >&2
  else
    echo "upstream switch failed; automatic restoration could not be confirmed" >&2
  fi
}
on_exit() {
  status=$?
  trap - EXIT INT TERM
  if [ "$restore_needed" -eq 1 ]; then
    set +e
    restore
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT TERM

restore_needed=1
install -m 0644 "$source_file" "$active_file.tmp.$$"
mv -f -- "$active_file.tmp.$$" "$active_file"
if ! "$nginx_bin" -t; then
  echo "new upstream configuration failed Nginx validation" >&2
  exit 1
fi
if ! "$systemctl_bin" reload nginx; then
  echo "Nginx reload failed after upstream switch" >&2
  exit 1
fi

"$canary_runner" --apply \
  --url "$verify_url" \
  --model "$model" \
  --approved-hostname "$approved_hostname"

restore_needed=0
trap - EXIT INT TERM
echo "Nginx upstream switched to $stage after health, syntax, reload, and end-to-end canary checks"
