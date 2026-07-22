#!/usr/bin/env bash
set -euo pipefail

mode="${1:-check}"
case "$mode" in
  check|--apply) ;;
  *) echo "usage: $0 [check|--apply]" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
privacy_gate="$repo_dir/migrations/verify_no_conversation_content.sql"
target_gate="$repo_dir/deploy/verify-sanitized-target.sql"
runtime_logging_gate="$repo_dir/deploy/verify-postgres-runtime-logging.sql"
portability_gate="$repo_dir/deploy/verify-postgres-portability.sql"
pg_env_exec="$repo_dir/deploy/pg-env-exec.py"
deadline_seconds=180

echo "sanitized PostgreSQL migration uses a direct logical stdout pipe"
echo "physical data directories, WAL, and content dump files are never copied"
sha256sum \
  "$privacy_gate" \
  "$target_gate" \
  "$runtime_logging_gate" \
  "$portability_gate" \
  "$pg_env_exec"

if [ "$mode" != "--apply" ]; then
  echo "check only; no connection was opened; no database connection was opened"
  echo "rerun with --apply only after privacy cleanup and a reviewed write stop"
  exit 0
fi

"$repo_dir/deploy/require-clean-worktree.sh" check

if [ "${SUB2API_MIGRATION_WRITES_STOPPED:-}" != "YES" ]; then
  echo "set SUB2API_MIGRATION_WRITES_STOPPED=YES only after all source writers are stopped" >&2
  exit 1
fi
: "${SUB2API_SOURCE_DATABASE_URL:?SUB2API_SOURCE_DATABASE_URL is required with --apply}"
: "${SUB2API_TARGET_DATABASE_URL:?SUB2API_TARGET_DATABASE_URL is required with --apply}"
if [ "$SUB2API_SOURCE_DATABASE_URL" = "$SUB2API_TARGET_DATABASE_URL" ]; then
  echo "source and target PostgreSQL URLs must differ" >&2
  exit 1
fi

for command_name in python3 psql pg_dump timeout sha256sum; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required migration command is unavailable: $command_name" >&2
    exit 1
  fi
done
if ! pg_dump --version | grep -Eq 'PostgreSQL\) 18([. ]|$)'; then
  echo "PostgreSQL 18 pg_dump is required" >&2
  exit 1
fi

started_at=$SECONDS
remaining_seconds() {
  local remaining=$((deadline_seconds - (SECONDS - started_at)))
  if [ "$remaining" -le 0 ]; then
    echo "migration deadline exceeded before the next checkpoint" >&2
    exit 1
  fi
  printf '%s\n' "$remaining"
}

run_bounded() {
  local remaining
  remaining="$(remaining_seconds)"
  timeout -s TERM -k 5 "$remaining" "$@"
}

run_pg_bounded() {
  local url_environment_name="$1"
  shift
  export SUB2API_PGOPTIONS="${SUB2API_PGOPTIONS:-}"
  run_bounded python3 "$pg_env_exec" "$url_environment_name" "$@"
}

checkpoint() {
  remaining_seconds >/dev/null
  echo "checkpoint: $1"
}

checkpoint "local prerequisites verified"

verify_runtime_logging() {
  local url_environment_name="$1"
  if ! SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded "$url_environment_name" \
      psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
      --file "$runtime_logging_gate" >/dev/null 2>/dev/null; then
    echo "sanitized_postgres_runtime_logging_gate_failed" >&2
    exit 1
  fi
}

verify_runtime_logging SUB2API_SOURCE_DATABASE_URL
verify_runtime_logging SUB2API_TARGET_DATABASE_URL
checkpoint "source and target PostgreSQL logging gates passed"

verify_portability() {
  local url_environment_name="$1"
  if ! SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded "$url_environment_name" \
      psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
      --file "$portability_gate" >/dev/null 2>/dev/null; then
    echo "sanitized_postgres_portability_gate_failed" >&2
    exit 1
  fi
}

verify_portability SUB2API_SOURCE_DATABASE_URL
verify_portability SUB2API_TARGET_DATABASE_URL
checkpoint "source and target PostgreSQL portability gates passed"

SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=30000' \
  run_pg_bounded SUB2API_SOURCE_DATABASE_URL \
    psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 --file "$privacy_gate"
checkpoint "source privacy residue gate passed"

source_shape="$({
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded SUB2API_SOURCE_DATABASE_URL \
      psql --no-psqlrc --tuples-only --no-align --field-separator='|' \
      -v ON_ERROR_STOP=1 \
      --command "SELECT (SELECT count(*) FROM pg_namespace WHERE nspname NOT LIKE 'pg_%' AND nspname NOT IN ('information_schema','public')), (SELECT count(*) FROM pg_largeobject_metadata)"
} | tr -d '[:space:]')"
if [ "$source_shape" != "0|0" ]; then
  echo "source PostgreSQL contains an unreviewed user schema or large object" >&2
  exit 1
fi
checkpoint "source schema and large-object boundary passed"

count_tables=(
  users
  api_keys
  groups
  user_allowed_groups
  user_subscriptions
  usage_logs
)
declare -A source_counts=()
for table_name in "${count_tables[@]}"; do
  table_exists="$({
    SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
      run_pg_bounded SUB2API_SOURCE_DATABASE_URL \
        psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
        --command "SELECT to_regclass('public.$table_name') IS NOT NULL"
  } | tr -d '[:space:]')"
  if [ "$table_exists" = "t" ]; then
    table_count="$({
      SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=30000' \
        run_pg_bounded SUB2API_SOURCE_DATABASE_URL \
          psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
          --command "SELECT count(*) FROM public.$table_name"
    } | tr -d '[:space:]')"
    case "$table_count" in
      ''|*[!0-9]*) echo "source row count is invalid for $table_name" >&2; exit 1 ;;
    esac
    source_counts["$table_name"]="$table_count"
  elif [ "$table_exists" = "f" ]; then
    source_counts["$table_name"]="null"
  else
    echo "source relation check is invalid for $table_name" >&2
    exit 1
  fi
done

expected_row_counts='{'
separator=''
for table_name in "${count_tables[@]}"; do
  expected_row_counts+="$separator\"$table_name\":${source_counts[$table_name]}"
  separator=','
done
expected_row_counts+='}'

if [ "${source_counts[usage_logs]}" = "null" ]; then
  expected_usage_aggregate='null'
else
  expected_usage_aggregate="$({
    SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=30000' \
      run_pg_bounded SUB2API_SOURCE_DATABASE_URL \
        psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
        --command "SELECT jsonb_build_object('rows', count(*)::text, 'request_ids', count(request_id)::text, 'input_tokens', COALESCE(sum(input_tokens), 0)::text, 'output_tokens', COALESCE(sum(output_tokens), 0)::text, 'total_cost', COALESCE(sum(total_cost), 0)::text, 'actual_cost', COALESCE(sum(actual_cost), 0)::text)::text FROM public.usage_logs"
  } | tr -d '\r\n')"
fi
case "$expected_usage_aggregate" in
  *"'"*|*\\*|*$'\n'*|"")
    echo "source usage metadata aggregate is invalid" >&2
    exit 1
    ;;
esac
checkpoint "source row-count and usage metadata manifests captured"

source_identity="$({
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded SUB2API_SOURCE_DATABASE_URL \
      psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
      --command "SELECT current_database() || ':' || COALESCE(inet_server_addr()::text, 'local') || ':' || COALESCE(inet_server_port()::text, '0')"
} | tr -d '\r\n')"
target_identity="$({
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded SUB2API_TARGET_DATABASE_URL \
      psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
      --command "SELECT current_database() || ':' || COALESCE(inet_server_addr()::text, 'local') || ':' || COALESCE(inet_server_port()::text, '0')"
} | tr -d '\r\n')"
if [ -z "$source_identity" ] || [ "$source_identity" = "$target_identity" ]; then
  echo "source and target PostgreSQL databases must be distinct" >&2
  exit 1
fi

source_cluster_id="$({
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded SUB2API_SOURCE_DATABASE_URL \
      psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
      --command "SELECT system_identifier::text FROM pg_control_system()"
} | tr -d '[:space:]')"
target_cluster_id="$({
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded SUB2API_TARGET_DATABASE_URL \
      psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
      --command "SELECT system_identifier::text FROM pg_control_system()"
} | tr -d '[:space:]')"
case "$source_cluster_id:$target_cluster_id" in
  ''|:*|*:|*[!0-9:]*)
    echo "source or target PostgreSQL cluster identity is invalid" >&2
    exit 1
    ;;
esac
if [ "$source_cluster_id" = "$target_cluster_id" ]; then
  echo "source and target must be different physical PostgreSQL clusters" >&2
  exit 1
fi
checkpoint "source and target physical cluster identities differ"

target_version="$({
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded SUB2API_TARGET_DATABASE_URL \
      psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
      --command "SHOW server_version_num"
} | tr -d '[:space:]')"
case "$target_version" in
  18????) ;;
  *) echo "target PostgreSQL server must be version 18" >&2; exit 1 ;;
esac

target_object_count="$({
  SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
    run_pg_bounded SUB2API_TARGET_DATABASE_URL \
      psql --no-psqlrc --tuples-only --no-align -v ON_ERROR_STOP=1 \
      --command "WITH user_objects AS (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','m','S','f') UNION ALL SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' UNION ALL SELECT t.oid FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND t.typtype IN ('c','d','e','m','r') AND t.typisdefined) SELECT count(*) FROM user_objects"
} | tr -d '[:space:]')"
if [ "$target_object_count" != "0" ]; then
  echo "target PostgreSQL database is not fresh and empty" >&2
  exit 1
fi
checkpoint "fresh PostgreSQL 18 target verified"

export SUB2API_SOURCE_DATABASE_URL SUB2API_TARGET_DATABASE_URL
export SUB2API_PRIVACY_VERIFY_SQL="$privacy_gate"
export SUB2API_TARGET_VERIFY_SQL="$target_gate"
export SUB2API_PG_ENV_EXEC="$pg_env_exec"
export SUB2API_EXPECTED_ROW_COUNTS="$expected_row_counts"
export SUB2API_EXPECTED_USAGE_AGGREGATE="$expected_usage_aggregate"
remaining="$(remaining_seconds)"
if ! timeout -s TERM -k 5 "$remaining" \
  bash -e -o pipefail -c \
  '{ python3 "$SUB2API_PG_ENV_EXEC" SUB2API_SOURCE_DATABASE_URL pg_dump --format=plain --encoding=UTF8 --no-owner --no-privileges --no-comments --no-security-labels --no-tablespaces --no-publications --no-subscriptions --no-large-objects --serializable-deferrable 2>/dev/null; printf "\n"; cat "$SUB2API_PRIVACY_VERIFY_SQL"; printf "\nSET LOCAL sub2api_gate.expected_row_counts = '\''%s'\'';\n" "$SUB2API_EXPECTED_ROW_COUNTS"; printf "SET LOCAL sub2api_gate.expected_usage_aggregate = '\''%s'\'';\n" "$SUB2API_EXPECTED_USAGE_AGGREGATE"; cat "$SUB2API_TARGET_VERIFY_SQL"; } | python3 "$SUB2API_PG_ENV_EXEC" SUB2API_TARGET_DATABASE_URL psql --no-psqlrc --quiet --single-transaction -v ON_ERROR_STOP=1 >/dev/null 2>/dev/null'; then
  echo "sanitized_postgres_stream_failed" >&2
  exit 1
fi
# Security-equivalent stream shape: pg_dump | PGDATABASE=target psql. The
# wrapper expands each URL into libpq environment fields without putting it in argv.
checkpoint "logical stream, privacy, row-count, relationship, and usage gates committed"

SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=30000' \
  run_pg_bounded SUB2API_TARGET_DATABASE_URL \
    psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 --file "$privacy_gate"
checkpoint "post-commit target privacy residue gate passed"

unset SUB2API_SOURCE_DATABASE_URL SUB2API_TARGET_DATABASE_URL
echo "sanitized PostgreSQL migration completed within the 180 second deadline"
