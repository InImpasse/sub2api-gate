#!/usr/bin/env bash
set -euo pipefail
set +x

mode="${1:-check}"
env_file=""

usage() {
  echo "usage: $0 [check|--apply] [--env-file ABSOLUTE_PATH]" >&2
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
role_sql="$repo_dir/migrations/000_prepare_app_role.sql"
grant_sql="$repo_dir/migrations/005_app_least_privilege.sql"
schema_guard_sql="$repo_dir/migrations/006_allow_sub2api_schema_migrations.sql"
function_guard_sql="$repo_dir/migrations/007_allow_sub2api_function_trigger_migrations.sql"
alter_guard_sql="$repo_dir/migrations/008_allow_sub2api_additive_alter_migrations.sql"
deny_list_guard_sql="$repo_dir/migrations/009_allow_sub2api_deny_list_ddl_guard.sql"
guard_body_sql="$repo_dir/migrations/sub2api_gate_guard_app_ddl.sql"
pg_env_exec="$repo_dir/deploy/pg-env-exec.py"
private_env_parser="$repo_dir/deploy/private_env.py"

unset SUB2API_DATABASE_URL SUB2API_SOURCE_DATABASE_URL \
  SUB2API_TARGET_DATABASE_URL SUB2API_APP_DATABASE_PASSWORD \
  SUB2API_SYNC_DATABASE_PASSWORD

for command_name in python3 timeout base64 tr sha256sum; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "required app role preparation command is unavailable: $command_name" >&2
    exit 1
  fi
done

sha256sum "$role_sql" "$grant_sql" "$schema_guard_sql" "$function_guard_sql" \
  "$alter_guard_sql" "$deny_list_guard_sql" "$guard_body_sql" \
  "$pg_env_exec" "$private_env_parser"
if [ "$mode" != "--apply" ]; then
  echo "check only; no database connection was opened and no role was changed"
  echo "private environment file was not read"
  echo "rerun with --apply only after owner-run schema and privacy migrations"
  exit 0
fi

if [ -z "$env_file" ]; then
  echo "app role --apply requires --env-file" >&2
  exit 1
fi

"$repo_dir/deploy/require-clean-worktree.sh" check

target_database_url_seen=0
role_password=""
private_env_expect_key=1
private_env_key=""
private_env_field=""
coproc PRIVATE_ENV_READER {
  timeout --foreground -s TERM -k 1 5 \
    python3 "$private_env_parser" --emit-nul "$env_file" 2>/dev/null
}
private_env_pid="$PRIVATE_ENV_READER_PID"
private_env_fd="${PRIVATE_ENV_READER[0]}"
while IFS= read -r -d '' private_env_field <&"$private_env_fd"; do
  if [ "$private_env_expect_key" -eq 1 ]; then
    private_env_key="$private_env_field"
    private_env_expect_key=0
  else
    case "$private_env_key" in
      SUB2API_TARGET_DATABASE_URL)
        [ -n "$private_env_field" ] && target_database_url_seen=1
        ;;
      SUB2API_APP_DATABASE_PASSWORD)
        role_password="$private_env_field"
        ;;
    esac
    private_env_key=""
    private_env_field=""
    private_env_expect_key=1
  fi
done
exec {private_env_fd}<&-
private_env_status=0
wait "$private_env_pid" || private_env_status=$?
if [ "$private_env_status" -ne 0 ] || [ "$private_env_expect_key" -ne 1 ]; then
  echo "sub2api_private_environment_load_failed" >&2
  exit 1
fi
unset private_env_field private_env_key private_env_status
if [ "$target_database_url_seen" -ne 1 ] || [ -z "$role_password" ]; then
  echo "private environment is missing the target database or app role password" >&2
  exit 1
fi
if [ "${#role_password}" -lt 24 ]; then
  echo "SUB2API_APP_DATABASE_PASSWORD must contain at least 24 characters" >&2
  exit 1
fi
case "$role_password" in
  *replace-with-*|*YOUR_*)
    echo "SUB2API_APP_DATABASE_PASSWORD still uses a placeholder" >&2
    exit 1
    ;;
esac

password_b64="$(printf '%s' "$role_password" | base64 | tr -d '\n')"
unset role_password
if ! {
  printf "\\set app_password_b64 '%s'\n" "$password_b64"
  printf "\\i '%s'\n" "$role_sql"
  printf "\\i '%s'\n" "$grant_sql"
  printf "\\i '%s'\n" "$schema_guard_sql"
  printf "\\i '%s'\n" "$function_guard_sql"
  printf "\\i '%s'\n" "$alter_guard_sql"
  printf "\\i '%s'\n" "$deny_list_guard_sql"
} | timeout --foreground -s TERM -k 1 30 \
  python3 "$pg_env_exec" --target-private-env-file "$env_file" \
    psql --quiet --no-psqlrc -v ON_ERROR_STOP=1 >/dev/null 2>/dev/null; then
  echo "sub2api_app_role_prepare_failed" >&2
  exit 1
fi
unset password_b64

echo "sub2api_app runtime role prepared without logging its password"
