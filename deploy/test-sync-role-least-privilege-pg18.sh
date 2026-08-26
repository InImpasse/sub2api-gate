#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
container_name="sub2api-gate-sync-role-pg18-$$"
image="${POSTGRES_TEST_IMAGE:-postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}"
test_password="local-sync-role-integration-only"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --rm --detach --log-driver none \
  --name "$container_name" \
  --env "POSTGRES_PASSWORD=$test_password" \
  "$image" >/dev/null

attempt=0
consecutive_ready=0
until [ "$consecutive_ready" -ge 2 ]; do
  attempt=$((attempt + 1))
  if docker exec "$container_name" sh -c 'test "$(cat /proc/1/comm)" = postgres' >/dev/null 2>&1 \
     && docker exec "$container_name" psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; then
    consecutive_ready=$((consecutive_ready + 1))
  else
    consecutive_ready=0
  fi
  if [ "$attempt" -ge 30 ]; then
    echo "PostgreSQL 18 did not become ready for sync-role integration" >&2
    exit 1
  fi
  sleep 1
done
if ! docker exec "$container_name" postgres --version | grep -Eq ' 18\.'; then
  echo "sync-role integration requires PostgreSQL 18" >&2
  exit 1
fi

docker exec "$container_name" createdb -U postgres sync_success
docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE inherited_sync_power;
CREATE ROLE sync_role_grantee;
CREATE ROLE sub2api_sync LOGIN SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS INHERIT
  PASSWORD 'local-sync-role-only';
GRANT inherited_sync_power TO sub2api_sync WITH ADMIN OPTION;
GRANT sub2api_sync TO sync_role_grantee;
ALTER ROLE sub2api_sync SET search_path = public, pg_catalog;
ALTER ROLE sub2api_sync SET work_mem = '64MB';
SQL

# Exercise the credential-safe role preparation input path before deliberately
# polluting the role again for the grants migration below.
{
  printf "\\set sync_password_b64 '%s'\n" "bG9jYWwtc3luYy1yb2xlLW9ubHk="
  sed -n '1,$p' "$repo_dir/migrations/000_prepare_sync_role.sql"
} | docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1

docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE
  role_state RECORD;
BEGIN
  SELECT * INTO STRICT role_state FROM pg_roles WHERE rolname = 'sub2api_sync';
  IF role_state.rolsuper OR role_state.rolcreatedb OR role_state.rolcreaterole
     OR role_state.rolreplication OR role_state.rolbypassrls
     OR role_state.rolinherit OR NOT role_state.rolcanlogin
     OR role_state.rolconfig IS NOT NULL THEN
    RAISE EXCEPTION 'prepare role pollution survived';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members
    WHERE roleid = role_state.oid OR member = role_state.oid
  ) THEN
    RAISE EXCEPTION 'prepare role membership pollution survived';
  END IF;
END
$$;

ALTER ROLE sub2api_sync SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS INHERIT;
GRANT inherited_sync_power TO sub2api_sync WITH ADMIN OPTION;
GRANT sub2api_sync TO sync_role_grantee;
ALTER ROLE sub2api_sync SET search_path = public, pg_catalog;
ALTER ROLE sub2api_sync SET work_mem = '64MB';

CREATE TABLE users (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, status text);
CREATE TABLE api_keys (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, status text);
CREATE TABLE groups (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text);
CREATE TABLE subscription_plans (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text);
CREATE TABLE user_allowed_groups (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id bigint,
  group_id bigint
);
CREATE TABLE user_subscriptions (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_id bigint,
  status text
);
CREATE TABLE auth_cache_invalidation_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cache_key char(64) NOT NULL
);
CREATE FUNCTION enqueue_group_auth_cache_invalidation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO auth_cache_invalidation_outbox (cache_key)
  VALUES (repeat('a', 64));
  RETURN NEW;
END
$$;
CREATE TRIGGER trg_groups_auth_cache_invalidation
AFTER UPDATE ON groups
FOR EACH ROW EXECUTE FUNCTION enqueue_group_auth_cache_invalidation();
-- requested_model is deliberately absent to prove optional-column compatibility.
CREATE TABLE usage_logs (
  id bigint PRIMARY KEY,
  request_id text,
  model text NOT NULL,
  input_tokens bigint NOT NULL,
  output_tokens bigint NOT NULL,
  cache_creation_tokens bigint,
  cache_read_tokens bigint,
  total_cost numeric,
  actual_cost numeric NOT NULL,
  duration_ms bigint,
  stream boolean,
  request_type smallint,
  inbound_endpoint text,
  created_at timestamptz NOT NULL,
  prompt text,
  response_body text
);
CREATE TABLE unrelated_secrets (id bigint PRIMARY KEY, secret text);
INSERT INTO usage_logs (
  id, request_id, model, input_tokens, output_tokens, total_cost, actual_cost,
  duration_ms, stream, request_type, inbound_endpoint, created_at, prompt,
  response_body
) VALUES (
  1, 'request-safe', 'model-safe', 3, 2, 0.03, 0.02, 40, false, 1,
  '/v1/responses', now(), 'PRIVATE_SENTINEL', 'PRIVATE_SENTINEL'
);
INSERT INTO unrelated_secrets VALUES (1, 'PRIVATE_SENTINEL');

GRANT ALL PRIVILEGES ON DATABASE sync_success TO sub2api_sync;
GRANT ALL PRIVILEGES ON SCHEMA public TO sub2api_sync;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO sub2api_sync;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO sub2api_sync;
GRANT SELECT (prompt, response_body) ON TABLE usage_logs TO sub2api_sync;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT ON TABLES TO sub2api_sync;
SQL

docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/003_sync_least_privilege.sql"

role_gate_result="$(docker exec -i "$container_name" sh -ec \
  'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=15000" exec psql --no-psqlrc --quiet --tuples-only --no-align -v ON_ERROR_STOP=1 -U postgres -d sync_success' \
  < "$repo_dir/migrations/verify_sync_role_least_privilege.sql" 2>/dev/null)"
if [ "$role_gate_result" != "ok" ]; then
  echo "sync runtime role verification gate failed" >&2
  exit 1
fi

docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE
  role_state RECORD;
BEGIN
  SELECT * INTO STRICT role_state FROM pg_roles WHERE rolname = 'sub2api_sync';
  IF role_state.rolsuper OR role_state.rolcreatedb OR role_state.rolcreaterole
     OR role_state.rolreplication OR role_state.rolbypassrls
     OR role_state.rolinherit OR NOT role_state.rolcanlogin THEN
    RAISE EXCEPTION 'role pollution survived';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members
    WHERE roleid = role_state.oid OR member = role_state.oid
  ) THEN
    RAISE EXCEPTION 'role membership pollution survived';
  END IF;
  IF role_state.rolconfig IS DISTINCT FROM ARRAY[
    'statement_timeout=10s',
    'lock_timeout=2s',
    'idle_in_transaction_session_timeout=15s'
  ] THEN
    RAISE EXCEPTION 'role setting pollution survived: %', role_state.rolconfig;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_default_acl AS defaults,
         LATERAL aclexplode(defaults.defaclacl) AS acl
    WHERE acl.grantee = role_state.oid
  ) THEN
    RAISE EXCEPTION 'default ACL pollution survived';
  END IF;
  IF has_table_privilege('sub2api_sync', 'public.unrelated_secrets', 'SELECT')
     OR has_table_privilege('sub2api_sync', 'public.usage_logs', 'SELECT')
     OR has_column_privilege('sub2api_sync', 'public.usage_logs', 'prompt', 'SELECT')
     OR has_column_privilege('sub2api_sync', 'public.usage_logs', 'response_body', 'SELECT')
     OR has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'TRUNCATE')
     OR has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'REFERENCES')
     OR has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'TRIGGER')
     OR has_table_privilege('public', 'public.sub2api_sync_invite_owners', 'SELECT') THEN
    RAISE EXCEPTION 'content or broad table access survived';
  END IF;
END
$$;

SET ROLE sub2api_sync;
SELECT id, request_id, model, input_tokens, output_tokens, total_cost,
       actual_cost, duration_ms, stream, request_type, inbound_endpoint, created_at
FROM usage_logs;
INSERT INTO groups (name) VALUES ('openai-default');
UPDATE groups SET name = name WHERE name = 'openai-default';
WITH new_user AS (
  INSERT INTO users (status) VALUES ('active') RETURNING id
)
INSERT INTO sub2api_sync_invite_owners (
  user_id, invite_fingerprint, created_at, updated_at
)
SELECT id, repeat('a', 64), now(), now() FROM new_user;
UPDATE sub2api_sync_invite_owners
SET updated_at = now()
WHERE invite_fingerprint = repeat('a', 64);
DELETE FROM sub2api_sync_invite_owners
WHERE invite_fingerprint = repeat('a', 64);
RESET ROLE;

DO $$
BEGIN
  IF (SELECT count(*) FROM auth_cache_invalidation_outbox) <> 1 THEN
    RAISE EXCEPTION 'sync-triggered auth cache invalidation was not queued';
  END IF;
  IF has_table_privilege(
    'sub2api_sync',
    'public.auth_cache_invalidation_outbox',
    'SELECT'
  ) OR has_table_privilege(
    'sub2api_sync',
    'public.auth_cache_invalidation_outbox',
    'UPDATE'
  ) OR has_table_privilege(
    'sub2api_sync',
    'public.auth_cache_invalidation_outbox',
    'DELETE'
  ) THEN
    RAISE EXCEPTION 'sync role can inspect or mutate queued cache references';
  END IF;
END
$$;
SQL

if docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_sync; SELECT cache_key FROM auth_cache_invalidation_outbox;' \
  >/dev/null 2>&1; then
  echo "sync role can read auth cache invalidation references" >&2
  exit 1
fi

if docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c "SET ROLE sub2api_sync; INSERT INTO sub2api_sync_invite_owners (user_id,invite_fingerprint) SELECT id,'7c484f74-6d93-43d1-9441-00c7d8d4ab11' FROM users LIMIT 1;" \
  >/dev/null 2>&1; then
  echo "ownership table accepted a raw UUID instead of an HMAC" >&2
  exit 1
fi

if ! docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_sync; SELECT id,model,input_tokens,output_tokens,actual_cost,created_at FROM usage_logs;' \
  >/dev/null; then
  echo "metadata query failed" >&2
  exit 1
fi
if docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_sync; SELECT prompt FROM usage_logs;' >/dev/null 2>&1; then
  echo "prompt column remained readable" >&2
  exit 1
fi
if docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_sync; SELECT * FROM usage_logs;' >/dev/null 2>&1; then
  echo "SELECT * FROM usage_logs unexpectedly succeeded" >&2
  exit 1
fi

docker exec "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs ADD COLUMN future_request_body text;'
if docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_sync; SELECT future_request_body FROM usage_logs;' >/dev/null 2>&1; then
  echo "future content column inherited read access" >&2
  exit 1
fi

# Replaying the migration must preserve the exact grants and continue to deny a
# content-capable column added after the first run.
docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/003_sync_least_privilege.sql"
role_gate_result="$(docker exec -i "$container_name" sh -ec \
  'PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=15000" exec psql --no-psqlrc --quiet --tuples-only --no-align -v ON_ERROR_STOP=1 -U postgres -d sync_success' \
  < "$repo_dir/migrations/verify_sync_role_least_privilege.sql" 2>/dev/null)"
if [ "$role_gate_result" != "ok" ]; then
  echo "sync runtime role verification gate failed after replay" >&2
  exit 1
fi
if ! docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_sync; SELECT id,model,input_tokens,output_tokens,actual_cost,created_at FROM usage_logs;' \
  >/dev/null; then
  echo "metadata query failed after replay" >&2
  exit 1
fi
if docker exec -i "$container_name" psql -U postgres -d sync_success -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_sync; SELECT future_request_body FROM usage_logs;' >/dev/null 2>&1; then
  echo "future content column became readable after replay" >&2
  exit 1
fi

docker exec "$container_name" createdb -U postgres sync_owner_rollback
docker exec -i "$container_name" psql -U postgres -d sync_owner_rollback -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE users (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE api_keys (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE groups (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE subscription_plans (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE user_allowed_groups (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE user_subscriptions (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE usage_logs (
  id bigint PRIMARY KEY,
  model text,
  input_tokens bigint,
  output_tokens bigint,
  actual_cost numeric,
  created_at timestamptz,
  prompt text
);
ALTER TABLE users OWNER TO sub2api_sync;
ALTER ROLE sub2api_sync SUPERUSER INHERIT;
ALTER ROLE sub2api_sync SET search_path = public;
SQL
if docker exec -i "$container_name" psql -U postgres -d sync_owner_rollback -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/003_sync_least_privilege.sql" >/dev/null 2>&1; then
  echo "sync role migration accepted an owned object" >&2
  exit 1
fi
docker exec -i "$container_name" psql -U postgres -d sync_owner_rollback -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT (SELECT rolsuper AND rolinherit FROM pg_roles WHERE rolname = 'sub2api_sync')
     OR array_position(
          (SELECT rolconfig FROM pg_roles WHERE rolname = 'sub2api_sync'),
          'search_path=public'
        ) IS NULL
     OR (SELECT relowner FROM pg_class WHERE oid = 'public.users'::regclass)
        <> (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync') THEN
    RAISE EXCEPTION 'owner rollback failed';
  END IF;
END
$$;
SQL

docker exec "$container_name" createdb -U postgres sync_missing_core
docker exec -i "$container_name" psql -U postgres -d sync_missing_core -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE users (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE api_keys (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE groups (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE subscription_plans (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE user_allowed_groups (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
CREATE TABLE user_subscriptions (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY);
-- actual_cost is a required metadata column and is deliberately absent.
CREATE TABLE usage_logs (
  id bigint PRIMARY KEY,
  model text,
  input_tokens bigint,
  output_tokens bigint,
  created_at timestamptz,
  prompt text
);
SQL
if docker exec -i "$container_name" psql -U postgres -d sync_missing_core -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/003_sync_least_privilege.sql" >/dev/null 2>&1; then
  echo "sync role migration accepted a missing core usage column" >&2
  exit 1
fi

echo "PostgreSQL 18 sync-role least-privilege integration test passed"
