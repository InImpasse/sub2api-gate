#!/usr/bin/env bash
set -euo pipefail

mode="${1:-check}"
case "$mode" in
  check|--apply) ;;
  *) echo "usage: $0 [check|--apply]" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
pg_env_exec="$repo_dir/deploy/pg-env-exec.py"
runtime_logging_gate="$repo_dir/deploy/verify-postgres-runtime-logging.sql"
portability_gate="$repo_dir/deploy/verify-postgres-portability.sql"
privacy_gate="$repo_dir/migrations/verify_no_conversation_content.sql"
policy_files=(
  deploy/migrate-sanitized-postgres.sh
  deploy/pg-env-exec.py
  deploy/verify-postgres-portability.sql
  deploy/verify-postgres-runtime-logging.sql
  deploy/verify-sanitized-target.sql
  migrations/002_remove_conversation_capture.sql
  migrations/002_scrub_conversation_history.sql
  migrations/verify_conversation_guards.sql
  migrations/verify_no_conversation_content.sql
)

echo "safe export includes schema, group relationships, and usage metadata only"
echo "conversation, audit, moderation, system/error log, credentials, and request or response bodies are excluded"
echo "all files use one REPEATABLE READ READ ONLY exported snapshot"
if [ "$mode" != "--apply" ]; then
  echo "check only; no connection was opened; no database connection was opened"
  echo "rerun with --apply after reviewing the fixed export queries"
  exit 0
fi

"$repo_dir/deploy/require-clean-worktree.sh" check
[ "$(id -u)" -eq 0 ] || { echo "safe metadata export apply requires root" >&2; exit 1; }
: "${SUB2API_DATABASE_URL:?SUB2API_DATABASE_URL is required with --apply}"
: "${SUB2API_DATA_ROOT:?SUB2API_DATA_ROOT is required with --apply}"

for command_name in python3 psql pg_dump realpath sha256sum stat; do
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

if [ "$SUB2API_DATA_ROOT" != "/mnt/data/sub2api-gate" ]; then
  echo "SUB2API_DATA_ROOT must be exactly /mnt/data/sub2api-gate" >&2
  exit 1
fi
data_root="$(realpath -e -- "$SUB2API_DATA_ROOT")"
if [ "$data_root" != "/mnt/data/sub2api-gate" ]; then
  echo "SUB2API_DATA_ROOT must resolve to /mnt/data/sub2api-gate" >&2
  exit 1
fi
require_private_directory "$data_root" "0:0:700" "SUB2API_DATA_ROOT"
backup_root="$data_root/safe-backup"
require_private_directory "$backup_root" "0:0:700" "safe-backup"

if ! SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
  python3 "$pg_env_exec" SUB2API_DATABASE_URL \
    psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
    --file "$runtime_logging_gate" >/dev/null 2>/dev/null; then
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

snapshot_pid=""
snapshot_read_fd=""
snapshot_write_fd=""
export_complete=0
cleanup() {
  status=$?
  if [ -n "$snapshot_write_fd" ]; then
    printf 'ROLLBACK;\n\\q\n' >&"$snapshot_write_fd" 2>/dev/null || true
  fi
  if [ -n "$snapshot_pid" ]; then
    wait "$snapshot_pid" 2>/dev/null || true
  fi
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

coproc SNAPSHOT_HOLDER {
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=300000' \
    python3 "$pg_env_exec" SUB2API_DATABASE_URL \
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
  printf '%s\n' 'SELECT system_identifier::text FROM pg_control_system();'
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
if ! IFS= read -r source_system_identifier <&"$snapshot_read_fd"; then
  echo "PostgreSQL source cluster identity gate failed" >&2
  exit 1
fi
case "$source_system_identifier" in
  ""|*[!0-9]*) echo "PostgreSQL returned an invalid source cluster identity" >&2; exit 1 ;;
esac
if [ "${#source_system_identifier}" -lt 10 ] || [ "${#source_system_identifier}" -gt 24 ]; then
  echo "PostgreSQL returned an invalid source cluster identity" >&2
  exit 1
fi

# The wrapper expands the URL into individual libpq environment fields and
# keeps database credentials out of the process argument vector.
python3 "$pg_env_exec" SUB2API_DATABASE_URL pg_dump \
  --schema-only \
  --snapshot="$snapshot_id" \
  --no-owner \
  --no-privileges \
  --no-comments \
  --no-security-labels \
  --no-publications \
  --no-subscriptions \
  --no-tablespaces \
  > "$partial_dir/schema.sql" 2>/dev/null

export_csv() {
  destination="$1"
  query="$2"
  {
    printf '%s\n' 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;'
    printf "SET TRANSACTION SNAPSHOT '%s';\n" "$snapshot_id"
    printf '\\copy (%s) TO STDOUT WITH (FORMAT CSV, HEADER true)\n' "$query"
    printf '%s\n' 'COMMIT;'
  } | SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=300000' \
      python3 "$pg_env_exec" SUB2API_DATABASE_URL \
        psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
      > "$partial_dir/$destination" 2>/dev/null
}

export_csv groups.csv \
  'SELECT id,name,platform,status,subscription_type,created_at,updated_at FROM groups'
export_csv user_allowed_groups.csv \
  'SELECT user_id,group_id,created_at FROM user_allowed_groups'
export_csv user_subscriptions.csv \
  'SELECT id,user_id,group_id,status,starts_at,expires_at,created_at,updated_at FROM user_subscriptions'
export_csv api_key_metadata.csv \
  'SELECT id,user_id,group_id,status,quota,quota_used,expires_at,created_at,updated_at FROM api_keys'
export_csv usage_metadata.csv \
  'SELECT id,request_id,model,requested_model,input_tokens,output_tokens,cache_creation_tokens,cache_read_tokens,total_cost,actual_cost,duration_ms,stream,request_type,inbound_endpoint,created_at FROM usage_logs'

printf 'COMMIT;\n\\q\n' >&"$snapshot_write_fd"
exec {snapshot_write_fd}>&-
snapshot_write_fd=""
wait "$snapshot_pid"
snapshot_pid=""
exec {snapshot_read_fd}>&-
snapshot_read_fd=""

(
  cd "$partial_dir"
  sha256sum \
    schema.sql \
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
  schema.sql
  groups.csv
  user_allowed_groups.csv
  user_subscriptions.csv
  api_key_metadata.csv
  usage_metadata.csv
)
{
  printf '{\n'
  printf '  "version": 1,\n'
  printf '  "completed_at": "%s",\n' "$completed_at"
  printf '  "git_head": "%s",\n' "$git_head"
  printf '  "source_postgres_system_identifier": "%s",\n' "$source_system_identifier"
  printf '  "artifacts": {\n'
  for index in "${!artifact_names[@]}"; do
    name="${artifact_names[$index]}"
    digest="$(sha256sum "$partial_dir/$name" | awk '{print $1}')"
    suffix=,
    if [ "$index" -eq "$((${#artifact_names[@]} - 1))" ]; then suffix=""; fi
    printf '    "%s": "%s"%s\n' "$name" "$digest" "$suffix"
  done
  printf '  },\n'
  printf '  "policy_files": {\n'
  for index in "${!policy_files[@]}"; do
    name="${policy_files[$index]}"
    digest="$(sha256sum "$repo_dir/$name" | awk '{print $1}')"
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
sync -f "$partial_dir"
mv "$partial_dir" "$final_dir"
sync -f "$backup_root"
export_complete=1

echo "safe metadata export written atomically to $final_dir"
