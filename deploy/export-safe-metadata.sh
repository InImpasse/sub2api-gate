#!/usr/bin/env bash
set -euo pipefail

mode="${1:-check}"
env_file=""
source_app_container=""
source_app_id=""
source_postgres_container=""
source_postgres_id=""
safe_export_deadline_seconds=600
safe_export_min_free_bytes=10737418240
safe_export_max_output_bytes=4294967296
safe_export_metadata_reserve_bytes=1048576

usage() {
  echo "usage: $0 [check|--apply] [--env-file ABSOLUTE_PATH --source-app-container NAME --source-app-id FULL_ID --source-postgres-container NAME --source-postgres-id FULL_ID]" >&2
  exit 2
}

case "$mode" in
  check|--apply) ;;
  *) usage ;;
esac
if [ "$#" -gt 0 ]; then
  shift
fi
while [ "$#" -gt 0 ]; do
  case "$1" in
    --env-file)
      shift
      [ "$#" -gt 0 ] || usage
      [ -z "$env_file" ] || usage
      env_file="$1"
      ;;
    --source-app-container)
      shift
      [ "$#" -gt 0 ] || usage
      [ -z "$source_app_container" ] || usage
      source_app_container="$1"
      ;;
    --source-app-id)
      shift
      [ "$#" -gt 0 ] || usage
      [ -z "$source_app_id" ] || usage
      source_app_id="$1"
      ;;
    --source-postgres-container)
      shift
      [ "$#" -gt 0 ] || usage
      [ -z "$source_postgres_container" ] || usage
      source_postgres_container="$1"
      ;;
    --source-postgres-id)
      shift
      [ "$#" -gt 0 ] || usage
      [ -z "$source_postgres_id" ] || usage
      source_postgres_id="$1"
      ;;
    *) usage ;;
  esac
  shift
done
if [ -n "$env_file" ]; then
  case "$env_file" in
    /*) ;;
    *) echo "private environment file path must be absolute" >&2; exit 2 ;;
  esac
fi

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
source_pg_exec="$repo_dir/deploy/source-postgres-exec.py"
runtime_logging_gate="$repo_dir/deploy/verify-postgres-runtime-logging.sql"
portability_gate="$repo_dir/deploy/verify-postgres-portability.sql"
privacy_gate="$repo_dir/migrations/verify_no_conversation_content.sql"
policy_files=(
  deploy/locked-postgres-stream.py
  deploy/migrate-sanitized-postgres.sh
  deploy/pg-env-exec.py
  deploy/prepare-app-role.sh
  deploy/prepare-sync-role.sh
  deploy/run-database-migration.sh
  deploy/source-postgres-exec.py
  deploy/verify-migration-totp.py
  deploy/verify-postgres-portability.sql
  deploy/verify-postgres-runtime-logging.sql
  deploy/verify-sanitized-target.sql
  migrations/000_prepare_app_role.sql
  migrations/000_prepare_sync_role.sql
  migrations/002_remove_conversation_capture.sql
  migrations/002_scrub_conversation_history.sql
  migrations/003_sync_least_privilege.sql
  migrations/005_app_least_privilege.sql
  migrations/verify_conversation_guards.sql
  migrations/verify_no_conversation_content.sql
)

echo "safe export includes schema, group relationships, and usage metadata only"
echo "conversation, audit, moderation, system/error log, credentials, and request or response bodies are excluded"
echo "all files use one REPEATABLE READ READ ONLY exported snapshot"
if [ "$mode" != "--apply" ]; then
  echo "check only; no connection was opened; no database connection was opened"
  echo "apply uses SUB2API_SOURCE_DATABASE_URL from the private environment file"
  echo "private environment file was not read"
  echo "rerun with --apply after reviewing the fixed export queries"
  exit 0
fi

export_started_at=$SECONDS
export_remaining_seconds() {
  local remaining=$((safe_export_deadline_seconds - (SECONDS - export_started_at)))
  if [ "$remaining" -le 0 ]; then
    echo "safe metadata export deadline exceeded" >&2
    return 1
  fi
  printf '%s\n' "$remaining"
}

run_export_bounded() {
  local remaining
  remaining="$(export_remaining_seconds)" || return 1
  timeout --foreground -s TERM -k 5 "$remaining" "$@"
}

command -v timeout >/dev/null 2>&1 || {
  echo "required export command is unavailable: timeout" >&2
  exit 1
}
run_export_bounded "$repo_dir/deploy/require-clean-worktree.sh" check
[ "$(id -u)" -eq 0 ] || { echo "safe metadata export apply requires root" >&2; exit 1; }
[ -n "$env_file" ] && [ -n "$source_app_container" ] \
  && [ -n "$source_app_id" ] && [ -n "$source_postgres_container" ] \
  && [ -n "$source_postgres_id" ] || {
  echo "safe metadata export --apply requires --env-file and exact source container identities" >&2
  exit 1
}
database_exec=(
  python3 "$source_pg_exec"
  --env-file "$env_file"
  --source-app-container "$source_app_container"
  --source-app-id "$source_app_id"
  --source-postgres-container "$source_postgres_container"
  --source-postgres-id "$source_postgres_id"
  --source-app-state running
)

for command_name in python3 docker realpath sha256sum stat timeout prlimit df du awk ps sleep; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required export command is unavailable: $command_name" >&2
    exit 1
  fi
done

git_head="$(git -C "$repo_dir" rev-parse --verify 'HEAD^{commit}')"
case "$git_head" in
  *[!0-9a-f]*|"") echo "release Git identity is invalid" >&2; exit 1 ;;
esac
if [ "${#git_head}" -ne 40 ] && [ "${#git_head}" -ne 64 ]; then
  echo "release Git identity is invalid" >&2
  exit 1
fi
for relative_path in "${policy_files[@]}"; do
  if [ ! -f "$repo_dir/$relative_path" ] || [ -L "$repo_dir/$relative_path" ]; then
    echo "safe export policy file is unavailable" >&2
    exit 1
  fi
done

require_private_directory() {
  path="$1"
  expected="$2"
  label="$3"
  if [ ! -d "$path" ] || [ -L "$path" ]; then
    echo "$label must be a pre-created real directory" >&2
    exit 1
  fi
  resolved="$(realpath -e -- "$path")"
  if [ "$resolved" != "$path" ]; then
    echo "$label must not resolve through a symlink" >&2
    exit 1
  fi
  actual="$(stat -c '%u:%g:%a' -- "$path")"
  if [ "$actual" != "$expected" ]; then
    echo "$label must be owned by root:root with mode 0700" >&2
    exit 1
  fi
}

data_root="$(realpath -e -- /mnt/data/sub2api-gate)"
if [ "$data_root" != "/mnt/data/sub2api-gate" ]; then
  echo "SUB2API_DATA_ROOT must resolve to /mnt/data/sub2api-gate" >&2
  exit 1
fi
require_private_directory "$data_root" "0:0:700" "SUB2API_DATA_ROOT"
backup_root="$data_root/safe-backup"
require_private_directory "$backup_root" "0:0:700" "safe-backup"

require_fresh_capacity() {
  local available
  available="$(df --output=avail --block-size=1 -- "$backup_root" \
    | awk 'NR == 2 { print $1 }')"
  case "$available" in
    ""|*[!0-9]*) echo "safe export free-space check failed" >&2; return 1 ;;
  esac
  if [ "$available" -lt "$safe_export_min_free_bytes" ]; then
    echo "safe export free-space threshold is not satisfied" >&2
    return 1
  fi
  export_remaining_seconds >/dev/null
}

require_fresh_capacity
reviewed_source_database_identity="$(
  run_export_bounded "${database_exec[@]}" identity 2>/dev/null
)" || {
  echo "safe metadata export source identity gate failed" >&2
  exit 1
}

if ! SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c lock_timeout=1000 -c statement_timeout=10000 -c idle_in_transaction_session_timeout=10000' \
  run_export_bounded "${database_exec[@]}" \
    psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
    < "$runtime_logging_gate" >/dev/null 2>/dev/null; then
  echo "safe metadata export PostgreSQL logging gate failed" >&2
  exit 1
fi

umask 077
lock_dir="$backup_root/.export-lock"
if ! mkdir "$lock_dir"; then
  echo "another safe metadata export is active" >&2
  exit 1
fi
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
partial_dir="$backup_root/.partial-$timestamp-$$"
final_dir="$backup_root/export-$timestamp"
if [ -e "$partial_dir" ] || [ -e "$final_dir" ]; then
  rmdir "$lock_dir"
  echo "refusing to overwrite an existing safe metadata export" >&2
  exit 1
fi
mkdir -m 0700 "$partial_dir"

current_output_bytes() {
  local size
  size="$(du --apparent-size --summarize --block-size=1 -- "$partial_dir" \
    | awk '{ print $1 }')"
  case "$size" in
    ""|*[!0-9]*) echo "safe export output-size check failed" >&2; return 1 ;;
  esac
  printf '%s\n' "$size"
}

require_output_bound() {
  local size
  size="$(current_output_bytes)" || return 1
  if [ "$size" -gt "$safe_export_max_output_bytes" ]; then
    echo "safe export output-size limit exceeded" >&2
    return 1
  fi
  export_remaining_seconds >/dev/null
}

remaining_artifact_bytes() {
  local current remaining
  current="$(current_output_bytes)" || return 1
  remaining=$((safe_export_max_output_bytes - current - safe_export_metadata_reserve_bytes))
  if [ "$remaining" -le 0 ]; then
    echo "safe export output-size limit exceeded" >&2
    return 1
  fi
  printf '%s\n' "$remaining"
}

snapshot_pid=""
snapshot_read_fd=""
snapshot_write_fd=""
export_complete=0

snapshot_holder_finished() {
  local state
  if [ -z "$snapshot_pid" ]; then
    return 0
  fi
  state="$(ps -o stat= -p "$snapshot_pid" 2>/dev/null | awk 'NR == 1 { print $1 }')"
  case "$state" in
    ""|Z*) return 0 ;;
    *) return 1 ;;
  esac
}

snapshot_holder_reap() {
  local phase attempt result
  for phase in TERM KILL; do
    for attempt in {1..50}; do
      if snapshot_holder_finished; then
        if wait "$snapshot_pid" 2>/dev/null; then
          result=0
        else
          result=$?
        fi
        snapshot_pid=""
        return "$result"
      fi
      sleep 0.1
    done
    kill -"$phase" "$snapshot_pid" 2>/dev/null || true
  done
  # A process stuck in uninterruptible kernel sleep must not hold the cleanup
  # path forever. Disown it after both bounded termination phases; the outer
  # export deadline still owns the nested timeout process.
  disown "$snapshot_pid" 2>/dev/null || true
  snapshot_pid=""
  return 1
}

snapshot_holder_stop() {
  local action="${1:-rollback}"
  if [ -n "$snapshot_write_fd" ]; then
    if [ "$action" = "commit" ]; then
      printf 'COMMIT;\n\\q\n' >&"$snapshot_write_fd" 2>/dev/null || true
    else
      printf 'ROLLBACK;\n\\q\n' >&"$snapshot_write_fd" 2>/dev/null || true
    fi
    exec {snapshot_write_fd}>&-
    snapshot_write_fd=""
  fi
  if [ -n "$snapshot_read_fd" ]; then
    exec {snapshot_read_fd}<&-
    snapshot_read_fd=""
  fi
  if [ -n "$snapshot_pid" ]; then
    snapshot_holder_reap
  fi
}

cleanup() {
  local status=$?
  snapshot_holder_stop rollback || true
  if [ "$export_complete" -ne 1 ] && [ -d "$partial_dir" ]; then
    case "$partial_dir" in
      "$backup_root"/.partial-*) find -P "$partial_dir" -depth -delete 2>/dev/null || true ;;
    esac
  fi
  rmdir "$lock_dir" 2>/dev/null || true
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

require_fresh_capacity
require_output_bound

coproc SNAPSHOT_HOLDER {
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c lock_timeout=1000 -c statement_timeout=300000 -c idle_in_transaction_session_timeout=600000' \
    run_export_bounded "${database_exec[@]}" \
      psql --no-psqlrc --quiet --tuples-only --no-align -v ON_ERROR_STOP=1 \
      2>/dev/null
}
snapshot_pid="$SNAPSHOT_HOLDER_PID"
snapshot_read_fd="${SNAPSHOT_HOLDER[0]}"
snapshot_write_fd="${SNAPSHOT_HOLDER[1]}"
if ! {
  printf '%s\n' 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;' &&
  # Run both fail-closed gates inside the exported transaction so concurrent
  # content writes or DDL cannot appear after a separate preflight check.
  cat "$privacy_gate" 2>/dev/null &&
  cat "$portability_gate" 2>/dev/null &&
  printf '%s\n' 'SELECT pg_export_snapshot();'
  printf '%s\n' "SELECT system_identifier::text || '|' || d.oid::text || '|' || pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_database(), 'UTF8'), 'hex') FROM pg_catalog.pg_control_system() CROSS JOIN pg_catalog.pg_database AS d WHERE d.datname = pg_catalog.current_database();"
} >&"$snapshot_write_fd"; then
  echo "PostgreSQL privacy, portability, or snapshot gate failed" >&2
  exit 1
fi
if ! IFS= read -r snapshot_id <&"$snapshot_read_fd"; then
  echo "PostgreSQL privacy, portability, or snapshot gate failed" >&2
  exit 1
fi
case "$snapshot_id" in
  *[!0-9A-Fa-f-]*|""|-*|*-) echo "PostgreSQL returned an invalid snapshot identifier" >&2; exit 1 ;;
esac
if [ "${snapshot_id//[^-]/}" != "--" ]; then
  echo "PostgreSQL returned an invalid snapshot identifier" >&2
  exit 1
fi
if ! IFS= read -r source_database_identity <&"$snapshot_read_fd"; then
  echo "PostgreSQL source database identity gate failed" >&2
  exit 1
fi
IFS='|' read -r source_system_identifier source_postgres_database_oid \
  source_postgres_database_name_hex <<EOF
$source_database_identity
EOF
case "$source_system_identifier" in
  ""|*[!0-9]*) echo "PostgreSQL returned an invalid source database identity" >&2; exit 1 ;;
esac
if [ "${#source_system_identifier}" -lt 10 ] || [ "${#source_system_identifier}" -gt 24 ]; then
  echo "PostgreSQL returned an invalid source database identity" >&2
  exit 1
fi
case "$source_postgres_database_oid" in
  ""|*[!0-9]*) echo "PostgreSQL returned an invalid source database identity" >&2; exit 1 ;;
esac
if [ "${#source_postgres_database_oid}" -gt 10 ] \
  || [ "$source_postgres_database_oid" -gt 4294967295 ]; then
  echo "PostgreSQL returned an invalid source database identity" >&2
  exit 1
fi
case "$source_postgres_database_name_hex" in
  ""|*[!0-9a-f]*) echo "PostgreSQL returned an invalid source database identity" >&2; exit 1 ;;
esac
if [ "${#source_postgres_database_name_hex}" -lt 2 ] \
  || [ "${#source_postgres_database_name_hex}" -gt 126 ] \
  || [ "$(( ${#source_postgres_database_name_hex} % 2 ))" -ne 0 ]; then
  echo "PostgreSQL returned an invalid source database identity" >&2
  exit 1
fi
if [ "$source_database_identity" != "$reviewed_source_database_identity" ]; then
  echo "source PostgreSQL identity changed after the binding gate" >&2
  exit 1
fi

require_fresh_capacity
schema_fingerprint="$(
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c lock_timeout=1000 -c statement_timeout=300000 -c idle_in_transaction_session_timeout=30000' \
    run_export_bounded "${database_exec[@]}" pg_dump \
      --schema-only \
      --snapshot="$snapshot_id" \
      --no-owner \
      --no-privileges \
      --no-comments \
      --no-security-labels \
      --no-publications \
      --no-subscriptions \
      --no-tablespaces \
      2>/dev/null \
    | run_export_bounded sha256sum \
    | awk 'NR == 1 { print $1 }'
)" || {
  echo "safe schema fingerprint generation failed" >&2
  exit 1
}
case "$schema_fingerprint" in
  ""|*[!0-9a-f]*) echo "safe schema fingerprint is invalid" >&2; exit 1 ;;
esac
if [ "${#schema_fingerprint}" -ne 64 ]; then
  echo "safe schema fingerprint is invalid" >&2
  exit 1
fi
printf '%s\n' "$schema_fingerprint" > "$partial_dir/schema_fingerprint.sha256"
require_output_bound

export_csv() {
  local destination="$1"
  local query="$2"
  local artifact_limit
  require_fresh_capacity
  artifact_limit="$(remaining_artifact_bytes)"
  {
    printf '%s\n' 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'
    printf "SET TRANSACTION SNAPSHOT '%s';\n" "$snapshot_id"
    printf '\\copy (%s) TO STDOUT WITH (FORMAT CSV, HEADER true)\n' "$query"
    printf '%s\n' 'COMMIT;'
  } | SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c lock_timeout=1000 -c statement_timeout=300000 -c idle_in_transaction_session_timeout=30000' \
      run_export_bounded prlimit --fsize="$artifact_limit:$artifact_limit" -- \
      "${database_exec[@]}" \
        psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
      > "$partial_dir/$destination" 2>/dev/null
  require_output_bound
}

export_csv groups.csv \
  'SELECT id,name,platform,status,subscription_type,created_at,updated_at FROM public.groups'
export_csv user_allowed_groups.csv \
  'SELECT user_id,group_id,created_at FROM public.user_allowed_groups'
export_csv user_subscriptions.csv \
  'SELECT id,user_id,group_id,status,starts_at,expires_at,created_at,updated_at FROM public.user_subscriptions'
export_csv api_key_metadata.csv \
  'SELECT id,user_id,group_id,status,quota,quota_used,expires_at,created_at,updated_at FROM public.api_keys'
export_csv usage_metadata.csv \
  'SELECT id,request_id,model,requested_model,input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens,total_cost,actual_cost,duration_ms,stream,request_type,inbound_endpoint,created_at FROM public.usage_logs'

if ! snapshot_holder_stop commit; then
  echo "PostgreSQL snapshot holder did not exit cleanly" >&2
  exit 1
fi

(
  cd "$partial_dir"
  run_export_bounded sha256sum \
    schema_fingerprint.sha256 \
    groups.csv \
    user_allowed_groups.csv \
    user_subscriptions.csv \
    api_key_metadata.csv \
    usage_metadata.csv \
    > SHA256SUMS.partial
  mv SHA256SUMS.partial SHA256SUMS
)
completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

artifact_names=(
  schema_fingerprint.sha256
  groups.csv
  user_allowed_groups.csv
  user_subscriptions.csv
  api_key_metadata.csv
  usage_metadata.csv
)
{
  printf '{\n'
  printf '  "version": 3,\n'
  printf '  "completed_at": "%s",\n' "$completed_at"
  printf '  "git_head": "%s",\n' "$git_head"
  printf '  "source_postgres_identity": {\n'
  printf '    "system_identifier": "%s",\n' "$source_system_identifier"
  printf '    "database_oid": "%s",\n' "$source_postgres_database_oid"
  printf '    "database_name_hex": "%s"\n' "$source_postgres_database_name_hex"
  printf '  },\n'
  printf '  "artifacts": {\n'
  for index in "${!artifact_names[@]}"; do
    name="${artifact_names[$index]}"
    digest="$(run_export_bounded sha256sum "$partial_dir/$name" | awk '{print $1}')"
    suffix=,
    if [ "$index" -eq "$((${#artifact_names[@]} - 1))" ]; then suffix=""; fi
    printf '    "%s": "%s"%s\n' "$name" "$digest" "$suffix"
  done
  printf '  },\n'
  printf '  "policy_files": {\n'
  for index in "${!policy_files[@]}"; do
    name="${policy_files[$index]}"
    digest="$(run_export_bounded sha256sum "$repo_dir/$name" | awk '{print $1}')"
    suffix=,
    if [ "$index" -eq "$((${#policy_files[@]} - 1))" ]; then suffix=""; fi
    printf '    "%s": "%s"%s\n' "$name" "$digest" "$suffix"
  done
  printf '  }\n'
  printf '}\n'
} > "$partial_dir/manifest.json.partial"
chmod 0600 "$partial_dir/manifest.json.partial"
mv "$partial_dir/manifest.json.partial" "$partial_dir/manifest.json"

printf 'completed_at=%s\n' "$completed_at" \
  > "$partial_dir/COMPLETE.partial"
chmod 0600 "$partial_dir/COMPLETE.partial"
mv "$partial_dir/COMPLETE.partial" "$partial_dir/COMPLETE"
require_output_bound
require_fresh_capacity
run_export_bounded sync -f "$partial_dir"
export_remaining_seconds >/dev/null
mv "$partial_dir" "$final_dir"
run_export_bounded sync -f "$backup_root"
export_complete=1

echo "safe metadata export written atomically to $final_dir"
