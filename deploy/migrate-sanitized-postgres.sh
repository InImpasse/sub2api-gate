#!/usr/bin/env bash
set -euo pipefail

mode="${1:-check}"
env_file=""
source_app_container=""
source_app_id=""
source_postgres_container=""
source_postgres_id=""
deadline_seconds=180

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
privacy_gate="$repo_dir/migrations/verify_no_conversation_content.sql"
target_gate="$repo_dir/deploy/verify-sanitized-target.sql"
runtime_logging_gate="$repo_dir/deploy/verify-postgres-runtime-logging.sql"
portability_gate="$repo_dir/deploy/verify-postgres-portability.sql"
pg_env_exec="$repo_dir/deploy/pg-env-exec.py"
source_pg_exec="$repo_dir/deploy/source-postgres-exec.py"
locked_stream="$repo_dir/deploy/locked-postgres-stream.py"

echo "sanitized PostgreSQL migration uses a direct logical stdout pipe"
echo "the pinned source PostgreSQL container is read through its Unix socket"
echo "physical data directories, WAL, and content dump files are never copied"
sha256sum \
  "$privacy_gate" \
  "$target_gate" \
  "$runtime_logging_gate" \
  "$portability_gate" \
  "$pg_env_exec" \
  "$source_pg_exec" \
  "$locked_stream"

if [ "$mode" != "--apply" ]; then
  echo "check only; no connection was opened; no database connection was opened"
  echo "private environment file was not read"
  echo "rerun with --apply only after privacy cleanup and a reviewed write stop"
  exit 0
fi

[ -n "$env_file" ] && [ -n "$source_app_container" ] \
  && [ -n "$source_app_id" ] && [ -n "$source_postgres_container" ] \
  && [ -n "$source_postgres_id" ] || {
  echo "sanitized PostgreSQL migration --apply requires --env-file and exact source container identities" >&2
  exit 1
}
if [ "${SUB2API_MIGRATION_WRITES_STOPPED:-}" != "YES" ]; then
  echo "set SUB2API_MIGRATION_WRITES_STOPPED=YES only after all source writers are stopped" >&2
  exit 1
fi

for command_name in python3 psql docker timeout sha256sum; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required migration command is unavailable: $command_name" >&2
    exit 1
  fi
done

started_at=$SECONDS
remaining_seconds() {
  local remaining=$((deadline_seconds - (SECONDS - started_at)))
  if [ "$remaining" -le 0 ]; then
    echo "migration deadline exceeded before the next checkpoint" >&2
    return 1
  fi
  printf '%s\n' "$remaining"
}

run_bounded() {
  local remaining work_budget
  remaining="$(remaining_seconds)" || return 1
  if [ "$remaining" -le 5 ]; then
    echo "migration deadline exceeded before the next bounded command" >&2
    return 1
  fi
  work_budget=$((remaining - 4))
  timeout --foreground -s TERM -k 4 "$work_budget" "$@"
}

source_database_exec=(
  python3 "$source_pg_exec"
  --env-file "$env_file"
  --source-app-container "$source_app_container"
  --source-app-id "$source_app_id"
  --source-postgres-container "$source_postgres_container"
  --source-postgres-id "$source_postgres_id"
  --source-app-state stopped
)
target_database_exec=(
  python3 "$pg_env_exec"
  --target-private-env-file "$env_file"
)

run_source_bounded() {
  local SUB2API_PGOPTIONS="$1"
  shift
  export SUB2API_PGOPTIONS
  run_bounded "${source_database_exec[@]}" "$@"
}

run_target_bounded() {
  local SUB2API_PGOPTIONS="$1"
  shift
  export SUB2API_PGOPTIONS
  run_bounded "${target_database_exec[@]}" "$@"
}

run_source_sql_file() {
  local sql_file="$1"
  local pgoptions="$2"
  run_source_bounded "$pgoptions" \
    psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 < "$sql_file"
}

run_target_sql_file() {
  local sql_file="$1"
  local pgoptions="$2"
  run_target_bounded "$pgoptions" \
    psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 < "$sql_file"
}

checkpoint() {
  remaining_seconds >/dev/null
  echo "checkpoint: $1"
}

run_bounded "$repo_dir/deploy/require-clean-worktree.sh" check
checkpoint "local prerequisites verified"

target_psql_version="$(
  run_target_bounded '' psql --version 2>/dev/null
)" || {
  echo "target PostgreSQL client version check failed" >&2
  exit 1
}
case "$target_psql_version" in
  "psql (PostgreSQL) 18"|"psql (PostgreSQL) 18."*) ;;
  *) echo "PostgreSQL 18 psql is required for the target" >&2; exit 1 ;;
esac

readonly_options='-c default_transaction_read_only=on -c lock_timeout=1000 -c statement_timeout=10000 -c idle_in_transaction_session_timeout=10000'
if ! run_source_sql_file "$runtime_logging_gate" "$readonly_options" \
  >/dev/null 2>/dev/null \
  || ! run_target_sql_file "$runtime_logging_gate" "$readonly_options" \
  >/dev/null 2>/dev/null; then
  echo "sanitized_postgres_runtime_logging_gate_failed" >&2
  exit 1
fi
checkpoint "source and target PostgreSQL logging gates passed"

if ! run_target_sql_file "$portability_gate" "$readonly_options" \
  >/dev/null 2>/dev/null; then
  echo "sanitized_postgres_portability_gate_failed" >&2
  exit 1
fi
checkpoint "target PostgreSQL portability gate passed"

parse_database_identity() {
  local identity="$1"
  local label="$2"
  local extra=""
  IFS='|' read -r identity_system_id identity_database_oid \
    identity_database_name_hex extra <<EOF
$identity
EOF
  case "$identity_system_id" in
    ''|*[!0-9]*) echo "$label PostgreSQL identity is invalid" >&2; return 1 ;;
  esac
  if [ "${#identity_system_id}" -lt 10 ] || [ "${#identity_system_id}" -gt 24 ]; then
    echo "$label PostgreSQL identity is invalid" >&2
    return 1
  fi
  case "$identity_database_oid" in
    ''|*[!0-9]*) echo "$label PostgreSQL identity is invalid" >&2; return 1 ;;
  esac
  if [ "${#identity_database_oid}" -gt 10 ] \
    || [ "$identity_database_oid" -gt 4294967295 ]; then
    echo "$label PostgreSQL identity is invalid" >&2
    return 1
  fi
  case "$identity_database_name_hex" in
    ''|*[!0-9a-f]*) echo "$label PostgreSQL identity is invalid" >&2; return 1 ;;
  esac
  if [ -n "$extra" ] || [ "${#identity_database_name_hex}" -lt 2 ] \
    || [ "${#identity_database_name_hex}" -gt 126 ] \
    || [ "$(( ${#identity_database_name_hex} % 2 ))" -ne 0 ]; then
    echo "$label PostgreSQL identity is invalid" >&2
    return 1
  fi
}

source_identity="$(run_source_bounded "$readonly_options" identity 2>/dev/null)" || {
  echo "source PostgreSQL identity check failed" >&2
  exit 1
}
case "$source_identity" in
  *$'\n'*|*$'\r'*) echo "source PostgreSQL identity is invalid" >&2; exit 1 ;;
esac
parse_database_identity "$source_identity" source || exit 1
source_cluster_id="$identity_system_id"
source_database_oid="$identity_database_oid"
source_database_name_hex="$identity_database_name_hex"

target_identity="$({
  run_target_bounded "$readonly_options" \
    psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
    --command "SELECT system_identifier::text || '|' || d.oid::text || '|' || pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_database(), 'UTF8'), 'hex') FROM pg_catalog.pg_control_system() CROSS JOIN pg_catalog.pg_database AS d WHERE d.datname = pg_catalog.current_database()"
} | tr -d '\r\n')"
parse_database_identity "$target_identity" target || exit 1
target_cluster_id="$identity_system_id"
if [ "$source_cluster_id" = "$target_cluster_id" ]; then
  echo "source and target must be different physical PostgreSQL clusters" >&2
  exit 1
fi
readonly source_database_oid source_database_name_hex
checkpoint "source and target physical PostgreSQL clusters differ"

target_version="$({
  run_target_bounded "$readonly_options" \
    psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
    --command "SHOW server_version_num"
} | tr -d '[:space:]')"
case "$target_version" in
  18????) ;;
  *) echo "target PostgreSQL server must be version 18" >&2; exit 1 ;;
esac

target_object_count="$({
  run_target_bounded "$readonly_options" \
    psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
    --command "WITH user_objects AS (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','S','f') UNION ALL SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' UNION ALL SELECT t.oid FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND t.typtype IN ('c','d','e','m','r') AND t.typisdefined) SELECT count(*) FROM user_objects"
} | tr -d '[:space:]')"
if [ "$target_object_count" != "0" ]; then
  echo "target PostgreSQL database is not fresh and empty" >&2
  exit 1
fi
checkpoint "fresh PostgreSQL 18 target verified"

remaining="$(remaining_seconds)" || exit 1
if [ "$remaining" -le 10 ]; then
  echo "migration deadline exceeded before the locked source snapshot" >&2
  exit 1
fi
stream_budget=$((remaining - 5))
stream_status=0
run_bounded python3 "$locked_stream" \
  --deadline-seconds "$stream_budget" \
  --env-file "$env_file" \
  --source-app-container "$source_app_container" \
  --source-app-id "$source_app_id" \
  --source-postgres-container "$source_postgres_container" \
  --source-postgres-id "$source_postgres_id" \
  --source-system-id "$source_cluster_id" \
  --source-database-oid "$source_database_oid" \
  --source-database-name-hex "$source_database_name_hex" \
  >/dev/null 2>/dev/null || stream_status=$?
case "$stream_status" in
  0) ;;
  10) echo "sanitized_postgres_source_lock_failed" >&2; exit 1 ;;
  11) echo "sanitized_postgres_source_privacy_gate_failed" >&2; exit 1 ;;
  12) echo "sanitized_postgres_portability_gate_failed" >&2; exit 1 ;;
  13) echo "sanitized_postgres_source_snapshot_failed" >&2; exit 1 ;;
  15) echo "sanitized_postgres_source_client_guard_failed" >&2; exit 1 ;;
  16|124|137) echo "sanitized_postgres_deadline_exceeded" >&2; exit 1 ;;
  *) echo "sanitized_postgres_stream_failed" >&2; exit 1 ;;
esac
checkpoint "locked snapshot, logical stream, privacy, relationship, and usage gates committed"

echo "sanitized PostgreSQL migration completed within the 180 second deadline"
