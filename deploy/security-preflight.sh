#!/usr/bin/env bash
set -eu

PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export PATH
repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
env_file="${SUB2API_ENV_FILE:-$repo_dir/.env}"
wrangler_config="${SUB2API_WRANGLER_CONFIG:-$repo_dir/worker-allow-ip/wrangler.private.jsonc}"
secret_manifest="$repo_dir/worker-allow-ip/required-secrets.json"
private_env_parser="$repo_dir/deploy/private_env.py"

run_sanitized() {
  /usr/bin/env -i \
    PATH="$PATH" \
    PYTHONNOUSERSITE=1 \
    "$@"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    check)
      ;;
    --env-file)
      shift
      [ "$#" -gt 0 ] || { echo "--env-file requires a path" >&2; exit 2; }
      env_file="$1"
      ;;
    --wrangler-config)
      shift
      [ "$#" -gt 0 ] || { echo "--wrangler-config requires a path" >&2; exit 2; }
      wrangler_config="$1"
      ;;
    *)
      echo "usage: $0 [check] [--env-file PATH] [--wrangler-config PATH]" >&2
      exit 2
      ;;
  esac
  shift
done

[ -f "$env_file" ] || { echo "environment file is missing: $env_file" >&2; exit 1; }
[ -f "$wrangler_config" ] || { echo "private Wrangler config is missing: $wrangler_config" >&2; exit 1; }

failed=0
require_private_file() {
  path="$1"
  label="$2"
  mode="$(stat -c '%a' -- "$path")" || {
    echo "could not inspect permissions for $label" >&2
    failed=1
    return
  }
  if [ "$mode" != "600" ]; then
    echo "$label must use mode 0600" >&2
    failed=1
  fi
}

require_private_file "$wrangler_config" "private Wrangler config"

declare -A values=()
declare -A url_hostnames=()
declare -A url_origins=()
declare -a private_env_fields=()
coproc PRIVATE_ENV_READER { run_sanitized python3 "$private_env_parser" --emit-nul "$env_file"; }
private_env_pid="$PRIVATE_ENV_READER_PID"
private_env_fd="${PRIVATE_ENV_READER[0]}"
while IFS= read -r -d '' private_env_field <&"$private_env_fd"; do
  private_env_fields+=("$private_env_field")
done
exec {private_env_fd}<&-
if ! wait "$private_env_pid"; then
  exit 1
fi
if [ "$(( ${#private_env_fields[@]} % 2 ))" -ne 0 ]; then
  echo "private environment parser returned an invalid record" >&2
  exit 1
fi
for ((index = 0; index < ${#private_env_fields[@]}; index += 2)); do
  values["${private_env_fields[$index]}"]="${private_env_fields[$((index + 1))]}"
done
unset private_env_fields private_env_field

require_value() {
  key="$1"
  minimum="$2"
  value="${values[$key]-}"
  if [ -z "$value" ] || [[ "$value" == *replace-with-* ]] || [[ "$value" == *YOUR_* ]]; then
    echo "$key is missing or still uses a placeholder" >&2
    failed=1
  elif [ "${#value}" -lt "$minimum" ]; then
    echo "$key is shorter than $minimum characters" >&2
    failed=1
  fi
}

require_https_url() {
  key="$1"
  value="${values[$key]-}"
  if [[ ! "$value" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[^[:space:]?#]*)?$ ]]; then
    echo "$key must be an HTTPS URL without credentials, query, or fragment" >&2
    failed=1
    return
  fi
  authority="${value#https://}"
  authority="${authority%%/*}"
  hostname="${authority%%:*}"
  if ! valid_hostname "$hostname"; then
    echo "$key must contain a valid fully qualified hostname" >&2
    failed=1
  fi
  if [[ "$authority" == *:* ]]; then
    echo "$key must not contain an explicit port" >&2
    failed=1
  fi
  if [[ "$hostname" == "example.com" ]] || [[ "$hostname" == *.example.com ]]; then
    echo "$key still uses an example hostname" >&2
    failed=1
  fi
  url_hostnames["$key"]="${hostname,,}"
  url_origins["$key"]="https://${hostname,,}"
}

valid_hostname() {
  hostname="$1"
  [ "${#hostname}" -le 253 ] || return 1
  case "$hostname" in
    localhost|*.localhost|*.local|*..*|.*|*.|*:*|*\[*|*\]*) return 1 ;;
  esac
  IFS='.' read -r -a labels <<< "$hostname"
  [ "${#labels[@]}" -ge 2 ] || return 1
  [[ "${labels[${#labels[@]} - 1]}" =~ ^[0-9]+$ ]] && return 1
  for label in "${labels[@]}"; do
    [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || return 1
  done
}

require_hostname_list() {
  key="$1"
  raw="${values[$key]-}"
  count=0
  IFS=',' read -r -a hosts <<< "$raw"
  for host in "${hosts[@]}"; do
    host="${host#"${host%%[![:space:]]*}"}"
    host="${host%"${host##*[![:space:]]}"}"
    if ! valid_hostname "$host"; then
      echo "$key contains an invalid hostname" >&2
      failed=1
      return
    fi
    count=$((count + 1))
  done
  if [ "$count" -eq 0 ]; then
    echo "$key must contain at least one hostname" >&2
    failed=1
  fi
}

reject_url_hostname_in_list() {
  url_key="$1"
  list_key="$2"
  target="${url_hostnames[$url_key]-}"
  raw="${values[$list_key]-}"
  found=0
  IFS=',' read -r -a hosts <<< "$raw"
  for host in "${hosts[@]}"; do
    host="${host#"${host%%[![:space:]]*}"}"
    host="${host%"${host##*[![:space:]]}"}"
    if [ "${host,,}" = "$target" ]; then
      found=1
    fi
  done
  if [ "$found" -ne 0 ]; then
    echo "public Sub2API hostname must not be present in SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS" >&2
    failed=1
  fi
}

require_exact_data_root() {
  expected="$1"
  data_root="${values[SUB2API_DATA_ROOT]-}"
  if [ "$data_root" != "$expected" ]; then
    echo "SUB2API_DATA_ROOT must be exactly $expected" >&2
    failed=1
    return
  fi

  require_private_path "$data_root" "0:0" "700"
  require_private_path "$data_root/app" "1000:1000" "700"
  require_private_path "$data_root/postgres" "70:70" "700"
  require_private_path "$data_root/redis" "999:1000" "700"
  require_private_path "$data_root/redis/nonce" "999:1000" "700"
  require_private_path "$data_root/safe-backup" "0:0" "700"
  require_private_path "$data_root/exports" "0:0" "700"
  require_private_path "$data_root/redis/users.acl" "999:1000" "400"
  require_private_path "$data_root/redis/nonce-users.acl" "999:1000" "400"
}

require_private_path() {
  path="$1"
  expected_owner="$2"
  expected_mode="$3"
  if [ ! -e "$path" ] || [ -L "$path" ]; then
    echo "required private storage path is missing or is a symlink: $path" >&2
    failed=1
    return
  fi
  if [ "$path" = "$data_root/redis/users.acl" ] \
    || [ "$path" = "$data_root/redis/nonce-users.acl" ]; then
    if [ ! -f "$path" ]; then
      echo "required Redis ACL is not a regular file" >&2
      failed=1
      return
    fi
  elif [ ! -d "$path" ]; then
    echo "required private storage path is not a directory: $path" >&2
    failed=1
    return
  fi
  resolved="$(realpath -e -- "$path")" || {
    echo "could not resolve private storage path: $path" >&2
    failed=1
    return
  }
  case "$resolved" in
    "$data_root"|"$data_root"/*) ;;
    *)
      echo "private storage path resolves outside SUB2API_DATA_ROOT: $path" >&2
      failed=1
      return
      ;;
  esac
  actual="$(stat -c '%u:%g:%a' -- "$resolved")" || {
    echo "could not inspect private storage ownership: $path" >&2
    failed=1
    return
  }
  if [ "$actual" != "$expected_owner:$expected_mode" ]; then
    echo "private storage path $path must use owner $expected_owner and mode $expected_mode" >&2
    failed=1
  fi
}

require_storage_free_space() {
  minimum="${values[SUB2API_MIN_FREE_BYTES]-10737418240}"
  if [[ ! "$minimum" =~ ^[0-9]+$ ]] || [ "$minimum" -lt 10737418240 ]; then
    echo "SUB2API_MIN_FREE_BYTES must be an integer of at least 10737418240" >&2
    failed=1
    return
  fi
  if [ ! -d "$data_root" ]; then
    return
  fi
  available="$(df --output=avail --block-size=1 -- "$data_root" 2>/dev/null | awk 'NR == 2 { print $1 }')"
  if [[ ! "$available" =~ ^[0-9]+$ ]]; then
    echo "could not determine free space below SUB2API_DATA_ROOT" >&2
    failed=1
  elif [ "$available" -lt "$minimum" ]; then
    echo "SUB2API_DATA_ROOT has less free space than SUB2API_MIN_FREE_BYTES" >&2
    failed=1
  fi
}

require_no_active_swap() {
  if [ ! -r /proc/swaps ]; then
    echo "could not verify that host swap is disabled" >&2
    failed=1
    return
  fi
  active_swap_count="$(awk 'NR > 1 && NF > 0 { count += 1 } END { print count + 0 }' /proc/swaps)"
  if [ "$active_swap_count" -ne 0 ]; then
    echo "active host swap is forbidden because application Redis uses privacy-sensitive tmpfs" >&2
    failed=1
  fi
}

require_value POSTGRES_PASSWORD 24
require_value SUB2API_APP_DATABASE_PASSWORD 24
require_value REDIS_PASSWORD 24
require_value SUB2API_SYNC_REDIS_PASSWORD 24
require_value SUB2API_SYNC_DATABASE_PASSWORD 24
require_value SUB2API_SYNC_SECRET 32
require_value JWT_SECRET 32
require_value TOTP_ENCRYPTION_KEY 32
require_hostname_list SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS
require_https_url SUB2API_LOGIN_URL
require_https_url SUB2API_PUBLIC_BASE_URL
if [ -n "${url_origins[SUB2API_LOGIN_URL]-}" ] \
  && [ "${url_origins[SUB2API_LOGIN_URL]}" != "${url_origins[SUB2API_PUBLIC_BASE_URL]-}" ]; then
  echo "SUB2API_LOGIN_URL and SUB2API_PUBLIC_BASE_URL must use the same origin" >&2
  failed=1
fi
reject_url_hostname_in_list SUB2API_LOGIN_URL SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS
reject_url_hostname_in_list SUB2API_PUBLIC_BASE_URL SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS
require_exact_data_root "/mnt/data/sub2api-gate"
cutover_state="${values[SUB2API_DATA_ROOT]-}/safe-backup/maintenance-cutover-state.json"
if [ -e "$cutover_state" ] || [ -L "$cutover_state" ]; then
  echo "unfinished maintenance recovery state exists; run maintenance-cutover.py --recover" >&2
  failed=1
fi
require_storage_free_space
require_no_active_swap
if ! /usr/bin/env -i \
  PATH="$PATH" \
  PYTHONNOUSERSITE=1 \
  SUB2API_DATA_ROOT="${values[SUB2API_DATA_ROOT]-}" \
  python3 "$repo_dir/deploy/verify-runtime-privacy.py" check >/dev/null; then
  echo "PostgreSQL log residue preflight failed" >&2
  failed=1
fi
if ! run_sanitized python3 "$repo_dir/deploy/verify-nginx-core-dumps.py" verify >/dev/null 2>&1; then
  echo "Nginx core-dump preflight failed" >&2
  failed=1
fi

if [ "${values[BIND_HOST]-127.0.0.1}" != "127.0.0.1" ]; then
  echo "BIND_HOST must remain 127.0.0.1 so Sub2API cannot bypass the Nginx and Cloudflare boundary" >&2
  failed=1
fi
if [ "${values[SERVER_PORT]-8080}" != "8080" ]; then
  echo "SERVER_PORT must remain 8080 so it matches the fixed Nginx upstream" >&2
  failed=1
fi
if [ "${values[SERVER_MODE]-release}" != "release" ]; then
  echo "SERVER_MODE must be release" >&2
  failed=1
fi
if [ "${values[RUN_MODE]-standard}" != "standard" ]; then
  echo "RUN_MODE must be standard" >&2
  failed=1
fi

secret_names=(
  POSTGRES_PASSWORD
  SUB2API_APP_DATABASE_PASSWORD
  REDIS_PASSWORD
  SUB2API_SYNC_REDIS_PASSWORD
  SUB2API_SYNC_DATABASE_PASSWORD
  SUB2API_SYNC_SECRET
  JWT_SECRET
  TOTP_ENCRYPTION_KEY
)
for ((left = 0; left < ${#secret_names[@]}; left += 1)); do
  for ((right = left + 1; right < ${#secret_names[@]}; right += 1)); do
    left_name="${secret_names[$left]}"
    right_name="${secret_names[$right]}"
    if [ -n "${values[$left_name]-}" ] && [ "${values[$left_name]}" = "${values[$right_name]-}" ]; then
      echo "$left_name and $right_name must use distinct values" >&2
      failed=1
    fi
  done
done

if [ "${values[SUB2API_SYNC_DATABASE_USER]-sub2api_sync}" != "sub2api_sync" ]; then
  echo "SUB2API_SYNC_DATABASE_USER must be the fixed least-privilege role sub2api_sync" >&2
  failed=1
elif [ "sub2api_sync" = "${values[POSTGRES_USER]-sub2api}" ]; then
  echo "POSTGRES_USER must be distinct from the sub2api_sync role" >&2
  failed=1
fi

if [[ "${values[SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS]-}" == *"your-resource"* ]] \
  || [[ "${values[SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS]-}" == *"example.com"* ]]; then
  echo "SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS still contains an example hostname" >&2
  failed=1
fi

if ! grep -Fq 'weishaw/sub2api@sha256:469790e0389bf31379978687149280a4e135393ad98a9a401951b6be9b1df444' "$repo_dir/docker-compose.yml" \
  || ! grep -Eq 'postgres@sha256:[0-9a-f]{64}' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005' "$repo_dir/docker-compose.yml"; then
  echo "Compose images must use the reviewed Sub2API 0.1.162, PostgreSQL 18, and Redis 8.8.0 digests" >&2
  failed=1
fi
sync_image='sub2api-gate/sub2api-sync:pg18.4-r1'
sync_postgres_base='postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15'
sync_python_base='python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df'
sync_dockerfile="$repo_dir/sub2api-sync/Dockerfile"
sync_compose="$repo_dir/docker-compose.sync-canary.yml"
sync_controller="$repo_dir/deploy/sync-canary.py"
if ! grep -Fq "FROM $sync_postgres_base AS postgres-client" "$sync_dockerfile" \
  || ! grep -Fq "FROM $sync_python_base" "$sync_dockerfile" \
  || ! grep -Fq 'psql (PostgreSQL) 18.4' "$sync_dockerfile" \
  || ! grep -Fq 'io.sub2api-gate.sync-release="pg18.4-r1"' "$sync_dockerfile" \
  || grep -Eq '(^|[[:space:]])(apk[[:space:]]+add|apt-get|dnf[[:space:]]|yum[[:space:]])' "$sync_dockerfile"; then
  echo "sync image must use the reviewed offline PostgreSQL 18 and Python bases" >&2
  failed=1
fi
if [ "$(grep -Fxc "    image: $sync_image" "$repo_dir/docker-compose.yml")" -ne 1 ] \
  || [ "$(grep -Fxc "  image: $sync_image" "$sync_compose")" -ne 1 ] \
  || [ "$(grep -Fxc '    pull_policy: never' "$repo_dir/docker-compose.yml")" -ne 1 ] \
  || [ "$(grep -Fc 'pull_policy: never' "$sync_compose")" -ne 1 ] \
  || grep -Eq '^[[:space:]]+build:' "$sync_compose" \
  || grep -Fq '"--build"' "$sync_controller" \
  || ! grep -Fq '"--no-build"' "$sync_controller" \
  || ! grep -Fq '"prepare-image"' "$sync_controller" \
  || ! grep -Fq 'require_prebuilt_sync_image' "$sync_controller"; then
  echo "sync runtime must use the prebuilt exact image without build or pull" >&2
  failed=1
fi
for postgres_logging_setting in \
  logging_collector=off \
  log_destination=stderr \
  log_statement=none \
  log_min_error_statement=panic \
  log_parameter_max_length_on_error=0 \
  log_min_duration_sample=-1 \
  log_transaction_sample_rate=0; do
  if ! grep -Fq -- "- $postgres_logging_setting" "$repo_dir/docker-compose.yml"; then
    echo "Compose PostgreSQL runtime logging controls are incomplete" >&2
    failed=1
    break
  fi
done
if ! grep -Fq "Sub2API 0.1.162" "$repo_dir/docker-compose.yml" \
  || ! grep -Fq "v=8.8.0" "$repo_dir/docker-compose.yml" \
  || [ "$(grep -Fc 'create_host_path: false' "$repo_dir/docker-compose.yml")" -lt 5 ] \
  || ! grep -Fq 'x-required-data-root: ${SUB2API_DATA_ROOT:?' "$repo_dir/docker-compose.yml" \
  || grep -Fq 'source: ${SUB2API_DATA_ROOT' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'source: /mnt/data/sub2api-gate/app' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'source: /mnt/data/sub2api-gate/postgres' "$repo_dir/docker-compose.yml" \
  || [ "$(grep -Fxc '        target: /var/lib/postgresql' "$repo_dir/docker-compose.yml")" -ne 1 ] \
  || [ "$(grep -Fxc '      - PGDATA=/var/lib/postgresql/18/docker' "$repo_dir/docker-compose.yml")" -ne 1 ] \
  || grep -Fq 'target: /var/lib/postgresql/data' "$repo_dir/docker-compose.yml" \
  || grep -Fq 'PGDATA=/var/lib/postgresql/data' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'source: /mnt/data/sub2api-gate/redis/nonce' "$repo_dir/docker-compose.yml"; then
  echo "Compose startup version checks or fail-closed bind mounts are missing" >&2
  failed=1
fi
if ! grep -Fq -- '--aclfile' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'SUB2API_SYNC_REDIS_USERNAME=sub2api_sync' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'SUB2API_SYNC_REDIS_HOST=redis-nonce' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'IMAGE_STORAGE_ENABLED=false' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'DATABASE_USER=sub2api_app' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq 'AUTO_SETUP=false' "$repo_dir/docker-compose.yml" \
  || grep -Fq 'AUTO_SETUP=true' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq -- '--appendfsync' "$repo_dir/docker-compose.yml" \
  || [ "$(grep -Fc -- '--maxmemory' "$repo_dir/docker-compose.yml")" -lt 2 ] \
  || [ "$(grep -Fc -- '--maxmemory-policy' "$repo_dir/docker-compose.yml")" -lt 2 ] \
  || ! grep -Fq '      - 128mb' "$repo_dir/docker-compose.yml" \
  || ! grep -Fq '      - 32mb' "$repo_dir/docker-compose.yml" \
  || [ "$(grep -Fc '      - noeviction' "$repo_dir/docker-compose.yml")" -lt 2 ] \
  || ! grep -Fq '    mem_limit: 256m' "$repo_dir/docker-compose.yml" \
  || [ "$(grep -Fc '    mem_limit: 128m' "$repo_dir/docker-compose.yml")" -lt 2 ] \
  || ! grep -Fq '      - "always"' "$repo_dir/docker-compose.yml" \
  || [ "$(grep -Fc '      - ""' "$repo_dir/docker-compose.yml")" -lt 2 ] \
  || ! grep -Fq '/data:rw,noexec,nosuid,nodev,size=128m' "$repo_dir/docker-compose.yml"; then
  echo "Compose Redis ACL, persistence, or image-storage privacy controls are missing" >&2
  failed=1
fi
if [ -f "${values[SUB2API_DATA_ROOT]-}/redis/users.acl" ]; then
  if grep -Eq '(^|[[:space:]])(>|nopass)' "${values[SUB2API_DATA_ROOT]}/redis/users.acl" \
    || [ "$(grep -Ec '^user default .*#[0-9a-f]{64}([[:space:]]|$)' "${values[SUB2API_DATA_ROOT]}/redis/users.acl")" -ne 1 ] \
    || grep -Eq '^user (sub2api_sync|sub2api_migration) ' "${values[SUB2API_DATA_ROOT]}/redis/users.acl"; then
    echo "application Redis ACL must contain only the hashed runtime user" >&2
    failed=1
  fi
fi
if [ -f "${values[SUB2API_DATA_ROOT]-}/redis/nonce-users.acl" ]; then
  if grep -Eq '(^|[[:space:]])(>|nopass)' "${values[SUB2API_DATA_ROOT]}/redis/nonce-users.acl" \
    || [ "$(grep -Ec '^user sub2api_sync .*#[0-9a-f]{64}([[:space:]]|$)' "${values[SUB2API_DATA_ROOT]}/redis/nonce-users.acl")" -ne 1 ] \
    || ! grep -Fqx 'user default off' "${values[SUB2API_DATA_ROOT]}/redis/nonce-users.acl" \
    || grep -Eq '^user (sub2api_migration|default) .*#' "${values[SUB2API_DATA_ROOT]}/redis/nonce-users.acl"; then
    echo "nonce Redis ACL must contain only the hashed nonce runtime user" >&2
    failed=1
  fi
fi

if ! run_sanitized node "$repo_dir/deploy/validate-wrangler-config.mjs" \
  "$wrangler_config" "$secret_manifest" "${url_hostnames[SUB2API_LOGIN_URL]-}"; then
  failed=1
fi

# validate-wrangler-config.mjs above validates every required binding, migration,
# secret declaration, URL, route, and compatibility flag as parsed JSON. Do not
# duplicate that policy with line-oriented matching: private JSON is commonly
# pretty-printed and key ordering is not security-relevant.

if [ "$failed" -ne 0 ]; then
  echo "security preflight failed; no service or external API was contacted" >&2
  exit 1
fi

echo "security preflight passed; no service or external API was contacted"
echo "remote Worker Secrets were not verified in check mode"
