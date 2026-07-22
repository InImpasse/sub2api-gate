#!/usr/bin/env bash
set -eu

mode="${1:-check}"
case "$mode" in
  check|--apply) ;;
  *) echo "usage: $0 [check|--apply]" >&2; exit 2 ;;
esac

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
role_sql="$repo_dir/migrations/000_prepare_sync_role.sql"
pg_env_exec="$repo_dir/deploy/pg-env-exec.py"

sha256sum "$role_sql"
if [ "$mode" != "--apply" ]; then
  echo "check only; no database connection was opened and no role was changed"
  echo "rerun with --apply only during the approved sync-role rollout step"
  exit 0
fi

"$repo_dir/deploy/require-clean-worktree.sh" check

: "${SUB2API_DATABASE_URL:?SUB2API_DATABASE_URL is required with --apply}"
: "${SUB2API_SYNC_DATABASE_PASSWORD:?SUB2API_SYNC_DATABASE_PASSWORD is required with --apply}"
if [ "${#SUB2API_SYNC_DATABASE_PASSWORD}" -lt 24 ]; then
  echo "SUB2API_SYNC_DATABASE_PASSWORD must contain at least 24 characters" >&2
  exit 1
fi

password_b64="$(printf '%s' "$SUB2API_SYNC_DATABASE_PASSWORD" | base64 | tr -d '\n')"
{
  printf "\\set sync_password_b64 '%s'\n" "$password_b64"
  printf "\\i '%s'\n" "$role_sql"
} | python3 "$pg_env_exec" SUB2API_DATABASE_URL \
  psql --quiet --no-psqlrc -v ON_ERROR_STOP=1
unset password_b64

echo "sub2api_sync login role prepared without logging its password"
