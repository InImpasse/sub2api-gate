#!/usr/bin/env bash
set -eu

target="${1:-}"
mode="${2:-check}"
repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
pg_env_exec="$repo_dir/deploy/pg-env-exec.py"
runtime_logging_gate="$repo_dir/deploy/verify-postgres-runtime-logging.sql"

case "$mode" in
  check|--apply) ;;
  *)
    echo "usage: $0 <privacy|sync-role|default-group|usage-indexes|verify-content|audit-default-group> [check|--apply]" >&2
    exit 2
    ;;
esac

case "$target" in
  privacy)
    files="deploy/verify-migration-totp.py migrations/002_remove_conversation_capture.sql migrations/verify_conversation_guards.sql migrations/002_scrub_conversation_history.sql migrations/verify_no_conversation_content.sql"
    ;;
  sync-role)
    files="migrations/003_sync_least_privilege.sql"
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
  *)
    echo "usage: $0 <privacy|sync-role|default-group|usage-indexes|verify-content|audit-default-group> [check|--apply]" >&2
    exit 2
    ;;
esac

echo "database migration target: $target"
echo "mode: $mode"
for relative_path in $files; do
  sha256sum "$repo_dir/$relative_path"
done

if [ "$mode" != "--apply" ]; then
  echo "check only; no database connection was opened"
  echo "rerun with --apply only after reviewing the listed files and the rollout order"
  exit 0
fi

"$repo_dir/deploy/require-clean-worktree.sh" check

if [ "$target" = "privacy" ]; then
  python3 "$repo_dir/deploy/verify-migration-totp.py"
fi

: "${SUB2API_DATABASE_URL:?SUB2API_DATABASE_URL is required with --apply}"
if ! SUB2API_PGOPTIONS='-c default_transaction_read_only=on -c statement_timeout=10000' \
  python3 "$pg_env_exec" SUB2API_DATABASE_URL \
    psql --no-psqlrc --quiet -v ON_ERROR_STOP=1 \
    --file "$runtime_logging_gate" >/dev/null 2>/dev/null; then
  echo "database migration PostgreSQL logging gate failed" >&2
  exit 1
fi
run_sql() {
  python3 "$pg_env_exec" SUB2API_DATABASE_URL \
    psql --no-psqlrc -v ON_ERROR_STOP=1 --file "$repo_dir/$1" 2>/dev/null
}

case "$target" in
  privacy)
    run_sql migrations/002_remove_conversation_capture.sql
    run_sql migrations/verify_conversation_guards.sql
    run_sql migrations/002_scrub_conversation_history.sql
    run_sql migrations/verify_no_conversation_content.sql
    ;;
  sync-role)
    run_sql migrations/003_sync_least_privilege.sql
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
