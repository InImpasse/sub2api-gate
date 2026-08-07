#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
container_name="sub2api-gate-app-role-pg18-$$"
image="${POSTGRES_TEST_IMAGE:-postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}"
test_password="local-app-role-integration-only"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --rm --detach --log-driver none \
  --name "$container_name" --env "POSTGRES_PASSWORD=$test_password" "$image" >/dev/null

attempt=0
ready_streak=0
while [ "$ready_streak" -lt 2 ]; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "PostgreSQL 18 did not become ready for app-role integration" >&2
    exit 1
  fi
  if docker exec "$container_name" psql -U postgres -d postgres -c 'SELECT 1' \
    >/dev/null 2>&1; then
    ready_streak=$((ready_streak + 1))
  else
    ready_streak=0
  fi
  sleep 1
done
if ! docker exec "$container_name" postgres --version | grep -Eq ' 18\.'; then
  echo "app-role integration requires PostgreSQL 18" >&2
  exit 1
fi

docker exec "$container_name" createdb -U postgres app_role_test
{
  printf "\\set app_password_b64 '%s'\n" \
    "bG9jYWwtYXBwLXJvbGUtcGFzc3dvcmQ="
  sed -n '1,$p' "$repo_dir/migrations/000_prepare_app_role.sql"
} | docker exec -i "$container_name" \
  psql -U postgres -d app_role_test -v ON_ERROR_STOP=1

docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE usage_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  model text NOT NULL,
  input_tokens bigint NOT NULL DEFAULT 0,
  output_tokens bigint NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE audit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  action text NOT NULL,
  request_body text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE sub2api_sync_invite_owners (
  user_id bigint PRIMARY KEY,
  invite_fingerprint text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE schema_migrations (
  filename text PRIMARY KEY,
  checksum text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO schema_migrations (filename, checksum)
VALUES ('001_bootstrap.sql', repeat('a', 64));
CREATE TABLE atlas_schema_revisions (
  version text PRIMARY KEY,
  description text NOT NULL,
  type integer NOT NULL,
  applied integer NOT NULL DEFAULT 0,
  total integer NOT NULL DEFAULT 0,
  executed_at timestamptz NOT NULL DEFAULT now(),
  execution_time bigint NOT NULL DEFAULT 0,
  error text,
  error_stmt text,
  hash text NOT NULL DEFAULT '',
  partial_hashes text[],
  operator_version text
);
INSERT INTO atlas_schema_revisions (version, description, type, hash)
VALUES ('001_bootstrap', '001_bootstrap', 1, repeat('b', 64));
CREATE FUNCTION strip_test_content() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.request_body := NULL;
  RETURN NEW;
END
$$;
CREATE TRIGGER strip_conversation_content
  BEFORE INSERT OR UPDATE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION strip_test_content();
CREATE ROLE inherited_owner_power;
ALTER ROLE sub2api_app SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS INHERIT;
GRANT inherited_owner_power TO sub2api_app WITH ADMIN OPTION;
ALTER ROLE sub2api_app SET search_path = public, pg_catalog;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sub2api_app;
SQL

docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/005_app_least_privilege.sql"

docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE
  state RECORD;
BEGIN
  SELECT * INTO STRICT state FROM pg_roles WHERE rolname = 'sub2api_app';
  IF state.rolsuper OR state.rolcreatedb OR state.rolcreaterole
     OR state.rolreplication OR state.rolbypassrls OR state.rolinherit
     OR NOT state.rolcanlogin OR state.rolconfig IS NOT NULL THEN
    RAISE EXCEPTION 'unsafe app role attributes survived';
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_auth_members
    WHERE member = state.oid
  ) THEN
    RAISE EXCEPTION 'unsafe app role membership survived';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM pg_default_acl AS defaults,
         LATERAL aclexplode(defaults.defaclacl) AS acl
    WHERE acl.grantee = state.oid
  ) THEN
    RAISE EXCEPTION 'future-object default grants survived';
  END IF;
  IF NOT has_schema_privilege('sub2api_app', 'public', 'CREATE')
     OR has_database_privilege('sub2api_app', current_database(), 'TEMPORARY')
     OR has_table_privilege('sub2api_app', 'public.audit_logs', 'TRIGGER')
     OR has_table_privilege('sub2api_app', 'public.audit_logs', 'REFERENCES')
     OR has_table_privilege('sub2api_app', 'public.audit_logs', 'TRUNCATE')
     OR has_table_privilege('sub2api_app', 'public.usage_logs', 'TRUNCATE')
     OR has_any_column_privilege(
          'sub2api_app', 'public.sub2api_sync_invite_owners',
          'SELECT,INSERT,UPDATE,REFERENCES'
        )
     OR has_table_privilege(
          'sub2api_app', 'public.sub2api_sync_invite_owners',
          'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        ) THEN
    RAISE EXCEPTION 'app role retained DDL or trigger privileges';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM pg_event_trigger
    WHERE evtname = 'sub2api_gate_guard_app_ddl'
      AND evtevent = 'ddl_command_start'
      AND evtenabled = 'O'
  ) THEN
    RAISE EXCEPTION 'app DDL event trigger is missing or disabled';
  END IF;
END
$$;

SET ROLE sub2api_app;
INSERT INTO usage_logs (model, input_tokens, output_tokens) VALUES ('test-model', 2, 1);
UPDATE usage_logs SET output_tokens = 2 WHERE model = 'test-model';
SELECT model, input_tokens, output_tokens FROM usage_logs;
DELETE FROM usage_logs WHERE model = 'test-model';
INSERT INTO audit_logs (action, request_body) VALUES ('test', 'PRIVATE_SENTINEL');
RESET ROLE;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM audit_logs WHERE request_body IS NOT NULL) THEN
    RAISE EXCEPTION 'privacy trigger did not scrub app-role write';
  END IF;
END
$$;
SQL

# The only runtime DDL accepted is the exact fixed statement emitted by
# Sub2API 0.1.171 for an already-existing owner-created relation.
docker exec -i "$container_name" psql -U sub2api_app -d app_role_test -v ON_ERROR_STOP=1 \
  -c $'CREATE TABLE IF NOT EXISTS schema_migrations (\n\tfilename   TEXT PRIMARY KEY,\n\tchecksum   TEXT NOT NULL,\n\tapplied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);' \
  >/dev/null

if docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_app; ALTER TABLE audit_logs DISABLE TRIGGER strip_conversation_content;' \
  >/dev/null 2>&1; then
  echo "sub2api_app could disable a privacy trigger" >&2
  exit 1
fi
for forbidden_sql in \
  'CREATE TABLE bypass_content(value text);' \
  'create table if not exists schema_migrations (filename text primary key, checksum text not null, applied_at timestamptz not null default now());' \
  'CREATE TABLE IF NOT EXISTS schema_migrations ( filename TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW() ); /* variant */' \
  'CREATE FUNCTION bypass_content() RETURNS text LANGUAGE sql AS $$ SELECT current_user $$;' \
  'ALTER TABLE audit_logs DISABLE TRIGGER strip_conversation_content;' \
  'DROP TRIGGER strip_conversation_content ON audit_logs;' \
  'DROP TABLE audit_logs;'; do
  if docker exec -i "$container_name" psql -U sub2api_app -d app_role_test \
    -v ON_ERROR_STOP=1 -c "$forbidden_sql" >/dev/null 2>&1; then
    echo "sub2api_app executed unreviewed persistent DDL" >&2
    exit 1
  fi
done
docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 <<'SQL'
CREATE FUNCTION owner_ddl_bridge() RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  EXECUTE 'CREATE TABLE public.security_definer_bypass(value text)';
END
$$;
GRANT EXECUTE ON FUNCTION owner_ddl_bridge() TO sub2api_app;
SQL
if docker exec -i "$container_name" psql -U sub2api_app -d app_role_test -v ON_ERROR_STOP=1 \
  -c 'SELECT owner_ddl_bridge();' >/dev/null 2>&1; then
  echo "sub2api_app bypassed the DDL guard through SECURITY DEFINER" >&2
  exit 1
fi
docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 \
  -c 'DROP FUNCTION owner_ddl_bridge();' >/dev/null
if docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_app; TRUNCATE TABLE audit_logs;' >/dev/null 2>&1; then
  echo "sub2api_app retained TRUNCATE on a logging table" >&2
  exit 1
fi
if docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 \
  -c "SET ROLE sub2api_app; SELECT * FROM sub2api_sync_invite_owners;" \
  >/dev/null 2>&1; then
  echo "sub2api_app could read the sync-only ownership table" >&2
  exit 1
fi
if docker exec -i "$container_name" psql -U sub2api_app -d app_role_test -v ON_ERROR_STOP=1 \
  -c 'SET ROLE postgres;' >/dev/null 2>&1; then
  echo "sub2api_app could assume the database owner role" >&2
  exit 1
fi

# Replaying the grant migration must preserve the same non-owner boundary.
docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 \
  < "$repo_dir/migrations/005_app_least_privilege.sql"
if docker exec -i "$container_name" psql -U postgres -d app_role_test -v ON_ERROR_STOP=1 \
  -c 'SET ROLE sub2api_app; ALTER TABLE audit_logs DISABLE TRIGGER ALL;' \
  >/dev/null 2>&1; then
  echo "replayed app-role migration allowed trigger bypass" >&2
  exit 1
fi

echo "PostgreSQL 18 app-role trigger-bypass and least-privilege integration test passed"
