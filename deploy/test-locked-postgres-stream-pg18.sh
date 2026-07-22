#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
image="${POSTGRES_TEST_IMAGE:-postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}"
source_container="sub2api-locked-source-pg18-$$"
target_container="sub2api-locked-target-pg18-$$"
fixture_root="$(mktemp -d /tmp/sub2api-locked-pg18.XXXXXX)"

cleanup() {
  docker rm -f "$source_container" "$target_container" >/dev/null 2>&1 || true
  case "$fixture_root" in
    /tmp/sub2api-locked-pg18.*) rm -rf -- "$fixture_root" ;;
  esac
}
trap cleanup EXIT INT TERM

mkdir -m 0700 "$fixture_root/deploy" "$fixture_root/migrations"
cp "$repo_dir/deploy/locked-postgres-stream.py" \
  "$fixture_root/deploy/locked-postgres-stream.py"
cp "$repo_dir/sub2api-sync/tests/postgres_container_exec_fixture.py" \
  "$fixture_root/deploy/source-postgres-exec.py"
cp "$repo_dir/sub2api-sync/tests/postgres_container_exec_fixture.py" \
  "$fixture_root/deploy/pg-env-exec.py"
cp "$repo_dir/deploy/verify-sanitized-target.sql" \
  "$fixture_root/deploy/verify-sanitized-target.sql"
chmod 0700 \
  "$fixture_root/deploy/locked-postgres-stream.py" \
  "$fixture_root/deploy/source-postgres-exec.py" \
  "$fixture_root/deploy/pg-env-exec.py"

cat > "$fixture_root/migrations/verify_no_conversation_content.sql" <<'SQL'
\set ON_ERROR_STOP on
DO $$
BEGIN
  IF current_setting('application_name') = 'sub2api_gate_snapshot_holder'
     AND (
       current_setting('transaction_read_only') <> 'on'
       OR current_setting('transaction_isolation') <> 'repeatable read'
     ) THEN
    RAISE EXCEPTION 'privacy gate did not run in a read-only repeatable snapshot';
  END IF;
END
$$;
SQL
cat > "$fixture_root/deploy/verify-postgres-portability.sql" <<'SQL'
\set ON_ERROR_STOP on
DO $$
BEGIN
  IF current_setting('application_name') = 'sub2api_gate_snapshot_holder'
     AND (
       current_setting('transaction_read_only') <> 'on'
       OR current_setting('transaction_isolation') <> 'repeatable read'
     ) THEN
    RAISE EXCEPTION 'portability gate did not share the read-only snapshot';
  END IF;
END
$$;
SQL
printf 'TEST_TARGET_CONTAINER=%s\n' "$target_container" \
  > "$fixture_root/private.env"
chmod 0600 "$fixture_root/private.env"

docker run --rm --detach --log-driver none \
  --name "$source_container" \
  --env POSTGRES_PASSWORD=test-only-locked-source \
  "$image" >/dev/null
docker run --rm --detach --log-driver none \
  --name "$target_container" \
  --env POSTGRES_PASSWORD=test-only-locked-target \
  "$image" >/dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$source_container" \
      psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1 \
    && docker exec "$target_container" \
      psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "PostgreSQL 18 locked stream fixtures did not become ready" >&2
  exit 1
fi
for container in "$source_container" "$target_container"; do
  if ! docker exec "$container" postgres --version 2>/dev/null \
    | grep -Eq 'PostgreSQL\) 18\.'; then
    echo "locked stream integration requires PostgreSQL 18" >&2
    exit 1
  fi
done

python3 "$repo_dir/sub2api-sync/tests/locked_postgres_stream_pg18_driver.py" \
  "$fixture_root" "$fixture_root/private.env" \
  "$source_container" "$target_container"
