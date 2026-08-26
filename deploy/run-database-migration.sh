#!/bin/bash
set -euo pipefail

readonly SAFE_COMMAND_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
readonly PYTHON3='/usr/bin/python3'
readonly SHA256SUM='/usr/bin/sha256sum'
readonly TIMEOUT='/usr/bin/timeout'
readonly READLINK='/usr/bin/readlink'
readonly STAT='/usr/bin/stat'
readonly BASH='/bin/bash'
readonly TRUSTED_RELEASE_ROOT='/opt/sub2api-gate-release'
readonly TRUSTED_RELEASE_PARENT='/opt'
readonly TRUSTED_CONTROLLER="$TRUSTED_RELEASE_ROOT/deploy/run-database-migration.sh"
readonly TRUSTED_CLEAN_WORKTREE="$TRUSTED_RELEASE_ROOT/deploy/require-clean-worktree.sh"

export PATH="$SAFE_COMMAND_PATH"
export LANG='C'
export LC_ALL='C'
export TZ='UTC'
unset BASH_ENV ENV CDPATH LD_PRELOAD LD_LIBRARY_PATH PYTHONHOME PYTHONPATH PYTHONSTARTUP \
  GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY \
  GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM \
  GIT_CONFIG_NOSYSTEM
IFS=$' \t\n'

release_failure() {
  echo 'database migration apply requires the trusted production release tree' >&2
  exit 1
}

require_trusted_path() {
  local path="$1"
  local kind="$2"
  local ownership owner group permissions mode_value

  [ ! -L "$path" ] && [ -e "$path" ] || release_failure
  case "$kind" in
    directory) [ -d "$path" ] || release_failure ;;
    regular) [ -f "$path" ] || release_failure ;;
    *) release_failure ;;
  esac
  ownership="$("$STAT" -c '%u:%g:%a' -- "$path")" || release_failure
  IFS=: read -r owner group permissions <<<"$ownership"
  case "$owner:$group:$permissions" in
    0:0:[0-7][0-7][0-7][0-7]|0:0:[0-7][0-7][0-7]) ;;
    *) release_failure ;;
  esac
  mode_value=$((8#$permissions))
  (( (mode_value & 18) == 0 )) || release_failure
}

require_production_apply_context() {
  local source_path

  if [ "$EUID" -ne 0 ]; then
    echo 'database migration apply requires root' >&2
    exit 1
  fi
  if ! { [ -t 0 ] && [ -t 1 ] && [ -t 2 ]; }; then
    echo 'database migration apply requires a private interactive TTY' >&2
    exit 1
  fi
  source_path="$("$READLINK" -f -- "${BASH_SOURCE[0]}")" || release_failure
  [ "$repo_dir" = "$TRUSTED_RELEASE_ROOT" ] \
    && [ "$source_path" = "$TRUSTED_CONTROLLER" ] || release_failure
  for trusted_path in / "$TRUSTED_RELEASE_PARENT" "$TRUSTED_RELEASE_ROOT" \
    "$TRUSTED_RELEASE_ROOT/deploy" "$TRUSTED_CONTROLLER" "$TRUSTED_CLEAN_WORKTREE" \
    "$TRUSTED_RELEASE_ROOT/deploy/active-postgres-exec.py"; do
    case "$trusted_path" in
      /|"$TRUSTED_RELEASE_PARENT"|"$TRUSTED_RELEASE_ROOT"|"$TRUSTED_RELEASE_ROOT/deploy")
        require_trusted_path "$trusted_path" directory
        ;;
      *) require_trusted_path "$trusted_path" regular ;;
    esac
  done
  "$BASH" "$TRUSTED_CLEAN_WORKTREE" check
}

script_source="${BASH_SOURCE[0]}"
script_directory="${script_source%/*}"
if [ "$script_directory" = "$script_source" ]; then
  script_directory='.'
fi
repo_dir="$(cd -P -- "$script_directory/.." && pwd -P)"
target="${1:-}"
mode="${2:-check}"
pg_env_exec="$repo_dir/deploy/pg-env-exec.py"
source_pg_exec="$repo_dir/deploy/source-postgres-exec.py"
active_pg_exec="$repo_dir/deploy/active-postgres-exec.py"
runtime_logging_gate="$repo_dir/deploy/verify-postgres-runtime-logging.sql"
env_file=""
source_app_container=""
source_app_id=""
source_postgres_container=""
source_postgres_id=""
active_app_id=""
active_postgres_id=""
privacy_deadline_seconds=300

usage() {
  echo "usage: $0 <privacy|sync-role|default-group|usage-indexes|verify-content|audit-default-group> [check|--apply] [--env-file ABSOLUTE_PATH --source-app-container NAME --source-app-id FULL_ID --source-postgres-container NAME --source-postgres-id FULL_ID | --active-app-id FULL_ID --active-postgres-id FULL_ID]" >&2
  exit 2
}

if [ "$#" -gt 2 ]; then
  shift 2
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
      --active-app-id)
        shift
        [ "$#" -gt 0 ] || usage
        [ -z "$active_app_id" ] || usage
        active_app_id="$1"
        ;;
      --active-postgres-id)
        shift
        [ "$#" -gt 0 ] || usage
        [ -z "$active_postgres_id" ] || usage
        active_postgres_id="$1"
        ;;
      *) usage ;;
    esac
    shift
  done
fi

case "$mode" in
  check|--apply) ;;
  *) usage ;;
esac

case "$target" in
  privacy)
    files="deploy/verify-migration-totp.py deploy/source-postgres-exec.py migrations/002_remove_conversation_capture.sql migrations/verify_conversation_guards.sql migrations/002_scrub_conversation_history.sql migrations/verify_no_conversation_content.sql"
    ;;
  sync-role)
    files="deploy/active-postgres-exec.py migrations/003_sync_least_privilege.sql migrations/verify_sync_role_least_privilege.sql"
    ;;
  default-group)
    files="migrations/audit_default_group.sql migrations/001_default_to_openai_default.sql"
    ;;
  usage-indexes)
    files="migrations/004_usage_cursor_indexes.sql"
    ;;
  verify-content)
    files="migrations/verify_no_conversation_content.sql"
    ;;
  audit-default-group)
    files="migrations/audit_default_group.sql"
    ;;
  *) usage ;;
esac

if [ -n "$env_file" ]; then
  case "$env_file" in
    /*) ;;
    *) echo "private environment file path must be absolute" >&2; exit 2 ;;
  esac
fi
source_identity_arguments="$source_app_container$source_app_id$source_postgres_container$source_postgres_id"
if [ "$target" != "privacy" ] && [ -n "$source_identity_arguments" ]; then
  echo "source container arguments are supported only for the source privacy migration" >&2
  exit 2
fi
active_identity_arguments="$active_app_id$active_postgres_id"
if [ -n "$active_identity_arguments" ]; then
  if [ "$target" != "sync-role" ] || [ -n "$source_identity_arguments" ] \
    || [ -z "$active_app_id" ] || [ -z "$active_postgres_id" ]; then
    usage
  fi
  for container_id in "$active_app_id" "$active_postgres_id"; do
    case "$container_id" in
      *[!0-9a-f]*) usage ;;
    esac
    [ "${#container_id}" -eq 64 ] || usage
  done
fi

if [ "$mode" = "--apply" ]; then
  if [ -z "$env_file" ]; then
    echo "every database migration --apply requires --env-file" >&2
    exit 1
  fi
  if [ "$target" = "privacy" ] && { [ -z "$source_app_container" ] \
    || [ -z "$source_app_id" ] || [ -z "$source_postgres_container" ] \
    || [ -z "$source_postgres_id" ]; }; then
    echo "privacy --apply requires the private file and exact source container identities" >&2
    exit 1
  fi
  require_production_apply_context
fi

echo "database migration target: $target"
echo "mode: $mode"
for relative_path in $files; do
  "$SHA256SUM" "$repo_dir/$relative_path"
done

if [ "$mode" != "--apply" ]; then
  echo "check only; no database connection was opened"
  if [ "$target" = "privacy" ]; then
    echo "apply uses SUB2API_SOURCE_DATABASE_URL from the private environment file"
  elif [ -n "$active_identity_arguments" ]; then
    echo "apply uses the exact active production PostgreSQL container"
  else
    echo "apply uses SUB2API_TARGET_DATABASE_URL from the private environment file"
  fi
  echo "private environment file was not read"
  echo "rerun with --apply only after reviewing the listed files and the rollout order"
  exit 0
fi

if [ "$target" = "privacy" ]; then
  "$PYTHON3" -I "$repo_dir/deploy/verify-migration-totp.py" verify
  database_exec=(
    "$PYTHON3" -I "$source_pg_exec"
    --env-file "$env_file"
    --source-app-container "$source_app_container"
    --source-app-id "$source_app_id"
    --source-postgres-container "$source_postgres_container"
    --source-postgres-id "$source_postgres_id"
    --source-app-state running
  )
  privacy_started_at=$SECONDS
elif [ -n "$active_identity_arguments" ]; then
  database_exec=(
    "$PYTHON3" -I "$active_pg_exec"
    --env-file "$env_file"
    --app-id "$active_app_id"
    --postgres-id "$active_postgres_id"
  )
else
  database_exec=("$PYTHON3" -I "$pg_env_exec" --target-private-env-file "$env_file")
fi

privacy_guard_options='-c lock_timeout=5000 -c statement_timeout=30000 -c idle_in_transaction_session_timeout=30000'
privacy_read_options='-c default_transaction_read_only=on -c lock_timeout=5000 -c statement_timeout=30000 -c idle_in_transaction_session_timeout=30000'
privacy_scrub_options='-c lock_timeout=5000 -c statement_timeout=180000 -c idle_in_transaction_session_timeout=30000'

privacy_remaining_seconds() {
  local remaining=$((privacy_deadline_seconds - (SECONDS - privacy_started_at)))
  if [ "$remaining" -le 0 ]; then
    echo "privacy migration deadline exceeded" >&2
    return 1
  fi
  printf '%s\n' "$remaining"
}

run_privacy_bounded() {
  local remaining
  remaining="$(privacy_remaining_seconds)" || return 1
  "$TIMEOUT" --foreground -s TERM -k 5 "$remaining" "$@"
}

run_source_sql() {
  local pgoptions="$1"
  local sql_file="$2"
  SUB2API_PGOPTIONS="$pgoptions" \
    run_privacy_bounded "${database_exec[@]}" \
      psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
      < "$repo_dir/$sql_file" 2>/dev/null
}

if [ "$target" = "privacy" ]; then
  if ! run_privacy_bounded "${database_exec[@]}" identity >/dev/null 2>/dev/null; then
    echo "source PostgreSQL container binding gate failed" >&2
    exit 1
  fi
  if ! run_source_sql "$privacy_read_options" \
    deploy/verify-postgres-runtime-logging.sql >/dev/null; then
    echo "database migration PostgreSQL logging gate failed" >&2
    exit 1
  fi
else
  if ! SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c lock_timeout=5000 -c statement_timeout=10000 -c idle_in_transaction_session_timeout=30000' \
    "${database_exec[@]}" \
      psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
      < "$runtime_logging_gate" >/dev/null 2>/dev/null; then
    echo "database migration PostgreSQL logging gate failed" >&2
    exit 1
  fi
fi
run_sql() {
  "${database_exec[@]}" \
    psql --no-psqlrc -v ON_ERROR_STOP=1 < "$repo_dir/$1" 2>/dev/null
}

verify_sync_role() {
  local result
  result="$(
    SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c lock_timeout=5000 -c statement_timeout=10000 -c idle_in_transaction_session_timeout=30000' \
      "${database_exec[@]}" \
        psql --no-psqlrc --quiet --tuples-only --no-align -v ON_ERROR_STOP=1 \
        < "$repo_dir/migrations/verify_sync_role_least_privilege.sql" 2>/dev/null
  )" || {
    echo "sync runtime role verification gate failed" >&2
    exit 1
  }
  [ "$result" = "ok" ] || {
    echo "sync runtime role verification gate failed" >&2
    exit 1
  }
}

case "$target" in
  privacy)
    run_source_sql "$privacy_guard_options" migrations/002_remove_conversation_capture.sql
    run_source_sql "$privacy_read_options" migrations/verify_conversation_guards.sql
    run_source_sql "$privacy_scrub_options" migrations/002_scrub_conversation_history.sql
    run_source_sql "$privacy_read_options" migrations/verify_no_conversation_content.sql
    privacy_remaining_seconds >/dev/null
    ;;
  sync-role)
    run_sql migrations/003_sync_least_privilege.sql
    verify_sync_role
    ;;
  default-group)
    run_sql migrations/audit_default_group.sql
    run_sql migrations/001_default_to_openai_default.sql
    ;;
  usage-indexes)
    run_sql migrations/004_usage_cursor_indexes.sql
    ;;
  verify-content)
    run_sql migrations/verify_no_conversation_content.sql
    ;;
  audit-default-group)
    run_sql migrations/audit_default_group.sql
    ;;
esac

echo "database migration target completed: $target"
