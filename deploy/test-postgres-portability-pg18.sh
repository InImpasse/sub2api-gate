#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
gate="$repo_dir/deploy/verify-postgres-portability.sql"
postgres_image="${POSTGRES_TEST_IMAGE:-postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}"
container_name="sub2api-portability-pg18-$$"
volume_name="sub2api-portability-pg18-$$"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  docker volume rm "$volume_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$volume_name" >/dev/null
docker run -d --log-driver none \
  --name "$container_name" \
  --mount "type=volume,src=$volume_name,dst=/var/lib/postgresql" \
  -e POSTGRES_PASSWORD=test-only-portability-password \
  "$postgres_image" >/dev/null

ready=0
for _ in $(seq 1 60); do
  if docker exec "$container_name" \
    sh -c 'test "$(cat /proc/1/comm)" = postgres' >/dev/null 2>&1 \
    && docker exec "$container_name" \
    psql --no-psqlrc --quiet -U postgres -d postgres \
    -c 'SELECT 1' >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "PostgreSQL 18 portability test did not become ready" >&2
  exit 1
fi
if ! docker exec "$container_name" postgres --version 2>/dev/null \
  | grep -Eq 'PostgreSQL\) 18\.'; then
  echo "PostgreSQL portability test requires PostgreSQL 18" >&2
  exit 1
fi

run_gate() {
  docker exec -i \
    --env 'PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=10000' \
    "$container_name" \
    psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
    < "$gate" >/dev/null 2>&1
}

# PostgreSQL's default language plus the two explicitly reviewed Sub2API
# extensions are the complete allowlist.
docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'CREATE EXTENSION pgcrypto' >/dev/null
run_gate
docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'CREATE EXTENSION pg_trgm' >/dev/null
run_gate

docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'CREATE EXTENSION hstore' >/dev/null
if run_gate; then
  echo "portability gate accepted an extension outside the exact allowlist" >&2
  exit 1
fi
docker exec "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'DROP EXTENSION hstore' >/dev/null
run_gate

docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  >/dev/null <<'SQL'
CREATE TABLE usage_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  prompt text,
  categories jsonb NOT NULL DEFAULT '[]'::jsonb,
  CONSTRAINT usage_categories_shape
    CHECK (jsonb_typeof(categories) = 'array')
);
CREATE FUNCTION public.conversation_content_policy()
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
AS $$
  SELECT '{"usage_logs":{"prompt":null,"categories":[]}}'::jsonb
$$;
SQL
run_gate

docker exec "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c "ALTER TABLE usage_logs ALTER COLUMN prompt SET DEFAULT 'test-only-content-default'" \
  >/dev/null
if run_gate; then
  echo "portability gate accepted a non-empty content-column default" >&2
  exit 1
fi
docker exec "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs ALTER COLUMN prompt DROP DEFAULT' >/dev/null
run_gate

docker exec "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c "ALTER TABLE usage_logs ADD CONSTRAINT unsafe_content_literal CHECK (prompt <> 'test-only-content-constraint')" \
  >/dev/null
if run_gate; then
  echo "portability gate accepted a content-column literal constraint" >&2
  exit 1
fi
docker exec "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs DROP CONSTRAINT unsafe_content_literal' >/dev/null
run_gate

docker exec "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'CREATE EXTENSION postgres_fdw' >/dev/null
if run_gate; then
  echo "portability gate accepted an unreviewed extension" >&2
  exit 1
fi
docker exec "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'DROP EXTENSION postgres_fdw' >/dev/null

docker exec -i "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  >/dev/null <<'SQL'
CREATE FOREIGN DATA WRAPPER unsafe_test_fdw NO HANDLER;
CREATE SERVER unsafe_test_server
  FOREIGN DATA WRAPPER unsafe_test_fdw
  OPTIONS (host 'foreign.example.test');
CREATE USER MAPPING FOR CURRENT_USER
  SERVER unsafe_test_server
  OPTIONS (password 'test-only-foreign-password');
CREATE FOREIGN TABLE unsafe_test_table (id bigint)
  SERVER unsafe_test_server;
SQL
foreign_object_count="$(docker exec "$container_name" \
  psql --no-psqlrc --quiet --tuples-only --no-align -U postgres \
  -c "SELECT (SELECT count(*) FROM pg_foreign_data_wrapper WHERE fdwname='unsafe_test_fdw') + (SELECT count(*) FROM pg_foreign_server WHERE srvname='unsafe_test_server') + (SELECT count(*) FROM pg_user_mapping) + (SELECT count(*) FROM pg_foreign_table)")"
if [ "$foreign_object_count" != "4" ]; then
  echo "foreign data boundary test fixture was not created" >&2
  exit 1
fi
if run_gate; then
  echo "portability gate accepted a foreign data boundary" >&2
  exit 1
fi
docker exec "$container_name" \
  psql --no-psqlrc --quiet -U postgres -v ON_ERROR_STOP=1 \
  -c 'DROP FOREIGN DATA WRAPPER unsafe_test_fdw CASCADE' >/dev/null 2>&1
run_gate

echo "PostgreSQL 18 portability gate passed"
