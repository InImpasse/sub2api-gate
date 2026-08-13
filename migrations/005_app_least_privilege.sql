\set ON_ERROR_STOP on

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sub2api_app') THEN
    RAISE EXCEPTION 'create role sub2api_app before applying this migration';
  END IF;
  IF to_regclass('public.sub2api_sync_invite_owners') IS NULL THEN
    RAISE EXCEPTION 'apply the sync ownership migration before app grants';
  END IF;
  IF to_regclass('public.schema_migrations') IS NULL
     OR to_regclass('public.atlas_schema_revisions') IS NULL
     OR NOT EXISTS (SELECT 1 FROM public.schema_migrations)
     OR NOT EXISTS (SELECT 1 FROM public.atlas_schema_revisions) THEN
    RAISE EXCEPTION 'owner bootstrap migrations and Atlas baseline must complete before app grants';
  END IF;
END
$$;

ALTER ROLE sub2api_app WITH
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  NOINHERIT;
ALTER ROLE sub2api_app RESET ALL;

DO $$
DECLARE
  membership RECORD;
BEGIN
  FOR membership IN
    SELECT granted.rolname
    FROM pg_auth_members AS memberships
    JOIN pg_roles AS granted ON granted.oid = memberships.roleid
    JOIN pg_roles AS member ON member.oid = memberships.member
    WHERE member.rolname = 'sub2api_app'
  LOOP
    EXECUTE format('REVOKE %I FROM sub2api_app CASCADE', membership.rolname);
  END LOOP;
END
$$;

DO $$
DECLARE
  target RECORD;
  object_kind text;
  schema_clause text;
BEGIN
  FOR target IN
    SELECT defaults.defaclobjtype,
           owner.rolname AS owner_name,
           namespace.nspname AS schema_name
    FROM pg_default_acl AS defaults
    JOIN pg_roles AS owner ON owner.oid = defaults.defaclrole
    LEFT JOIN pg_namespace AS namespace ON namespace.oid = defaults.defaclnamespace
    WHERE EXISTS (
      SELECT 1
      FROM aclexplode(defaults.defaclacl) AS acl
      WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_app')
    )
  LOOP
    object_kind := CASE target.defaclobjtype
      WHEN 'r' THEN 'TABLES'
      WHEN 'S' THEN 'SEQUENCES'
      WHEN 'f' THEN 'FUNCTIONS'
      WHEN 'T' THEN 'TYPES'
      WHEN 'n' THEN 'SCHEMAS'
      WHEN 'L' THEN 'LARGE OBJECTS'
      ELSE NULL
    END;
    IF object_kind IS NULL THEN
      RAISE EXCEPTION 'unsupported default ACL object type: %', target.defaclobjtype;
    END IF;
    schema_clause := CASE
      WHEN target.schema_name IS NULL THEN ''
      ELSE format(' IN SCHEMA %I', target.schema_name)
    END;
    EXECUTE format(
      'ALTER DEFAULT PRIVILEGES FOR ROLE %I%s REVOKE ALL PRIVILEGES ON %s FROM sub2api_app CASCADE',
      target.owner_name,
      schema_clause,
      object_kind
    );
  END LOOP;
END
$$;

DO $$
DECLARE
  target RECORD;
  privacy_tables text[] := ARRAY[
    'audit_logs',
    'usage_logs',
    'prompt_audit_events',
    'prompt_audit_jobs',
    'content_moderation_logs',
    'ops_error_logs',
    'ops_retry_attempts',
    'ops_job_heartbeats',
    'ops_system_logs',
    'ops_system_log_cleanup_audits',
    'idempotency_records',
    'deleted_api_key_audits',
    'usage_billing_dedup',
    'usage_billing_dedup_archive',
    'auth_cache_invalidation_outbox',
    'usage_cleanup_tasks',
    'scheduled_test_results',
    'channel_monitor_histories',
    'sora_generations',
    'batch_image_jobs',
    'batch_image_items',
    'batch_image_events',
    'scheduler_outbox',
    'sub2api_sync_invite_owners'
  ];
BEGIN
  -- Additive online migrations may create objects as sub2api_app. Replaying
  -- this grant migration first returns those objects to the owner, then hands
  -- non-privacy application tables back so ALTER TABLE ADD COLUMN can run.
  EXECUTE format('REASSIGN OWNED BY sub2api_app TO %I', current_user);

  FOR target IN
    SELECT relation.relname
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'public'
      AND relation.relkind IN ('r', 'p')
      AND relation.relname <> ALL (privacy_tables)
  LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO sub2api_app', target.relname);
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    JOIN pg_roles AS owner ON owner.oid = relation.relowner
    WHERE owner.rolname = 'sub2api_app'
      AND namespace.nspname = 'public'
      AND relation.relname = ANY (privacy_tables)
  ) OR EXISTS (
    SELECT 1
    FROM pg_proc AS procedure
    JOIN pg_roles AS owner ON owner.oid = procedure.proowner
    WHERE owner.rolname = 'sub2api_app'
  ) THEN
    RAISE EXCEPTION 'sub2api_app must not own privacy objects or functions';
  END IF;
END
$$;

GRANT USAGE, CREATE ON SCHEMA public TO sub2api_app;

-- Sub2API 0.1.176 still emits the exact schema_migrations CREATE TABLE IF
-- NOT EXISTS on every startup. It also applies additive goose migrations
-- (CREATE TABLE/INDEX, ALTER TABLE ADD COLUMN, COMMENT). Allow those tags
-- while still blocking trigger, function, grant, and privacy-table DDL.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper
  ) THEN
    RAISE EXCEPTION 'app DDL guard must be installed by a PostgreSQL superuser';
  END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.sub2api_gate_guard_app_ddl()
RETURNS event_trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  submitted_query text;
  normalized_query text;
  privacy_relation text :=
    '(audit_logs|usage_logs|prompt_audit_events|prompt_audit_jobs|'
    || 'content_moderation_logs|ops_error_logs|ops_retry_attempts|'
    || 'ops_job_heartbeats|ops_system_logs|ops_system_log_cleanup_audits|'
    || 'idempotency_records|deleted_api_key_audits|usage_billing_dedup|'
    || 'usage_billing_dedup_archive|auth_cache_invalidation_outbox|'
    || 'usage_cleanup_tasks|scheduled_test_results|channel_monitor_histories|'
    || 'sora_generations|batch_image_jobs|batch_image_items|batch_image_events|'
    || 'scheduler_outbox|sub2api_sync_invite_owners)';
BEGIN
  IF session_user <> 'sub2api_app' THEN
    RETURN;
  END IF;

  submitted_query := btrim(current_query(), E' \t\r\n');
  normalized_query := lower(regexp_replace(submitted_query, E'\\s+', ' ', 'g'));

  IF tg_tag = 'CREATE TABLE'
     AND submitted_query = E'CREATE TABLE IF NOT EXISTS schema_migrations (\n\tfilename   TEXT PRIMARY KEY,\n\tchecksum   TEXT NOT NULL,\n\tapplied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);' THEN
    RETURN;
  END IF;

  IF tg_tag IN (
    'CREATE TABLE',
    'CREATE INDEX',
    'DROP INDEX',
    'COMMENT',
    'CREATE SEQUENCE',
    'ALTER SEQUENCE',
    'CREATE TYPE',
    'ALTER TYPE'
  ) THEN
    IF (tg_tag = 'CREATE TABLE' AND normalized_query !~ 'create table')
       OR (tg_tag = 'CREATE INDEX' AND normalized_query !~ 'create( unique)? index')
       OR (tg_tag = 'DROP INDEX' AND normalized_query !~ 'drop index')
       OR (tg_tag = 'COMMENT' AND normalized_query !~ 'comment on')
       OR (tg_tag = 'CREATE SEQUENCE' AND normalized_query !~ 'create sequence')
       OR (tg_tag = 'ALTER SEQUENCE' AND normalized_query !~ 'alter sequence')
       OR (tg_tag = 'CREATE TYPE' AND normalized_query !~ 'create type')
       OR (tg_tag = 'ALTER TYPE' AND normalized_query !~ 'alter type') THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    IF tg_tag = 'CREATE TABLE'
       AND normalized_query ~ ('create table( if not exists)? (only )?(public\.)?' || privacy_relation) THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    RETURN;
  END IF;

  IF tg_tag = 'ALTER TABLE' THEN
    IF normalized_query !~ 'alter table'
       OR normalized_query ~ 'disable trigger'
       OR normalized_query ~ 'enable trigger'
       OR normalized_query ~ 'drop trigger'
       OR normalized_query ~ 'owner to'
       OR normalized_query ~ 'set schema' THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    IF normalized_query ~ ('alter table (only )?(public\.)?' || privacy_relation) THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    RETURN;
  END IF;

  RAISE EXCEPTION USING
    ERRCODE = '42501',
    MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160)),
    DETAIL = tg_tag || ': ' || left(submitted_query, 180);
END
$$;
REVOKE ALL ON FUNCTION public.sub2api_gate_guard_app_ddl() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sub2api_gate_guard_app_ddl() FROM sub2api_app;

DROP EVENT TRIGGER IF EXISTS sub2api_gate_guard_app_ddl;
CREATE EVENT TRIGGER sub2api_gate_guard_app_ddl
  ON ddl_command_start
  EXECUTE FUNCTION public.sub2api_gate_guard_app_ddl();

DO $$
BEGIN
  EXECUTE format(
    'REVOKE ALL PRIVILEGES ON DATABASE %I FROM sub2api_app',
    current_database()
  );
  EXECUTE format(
    'GRANT CONNECT ON DATABASE %I TO sub2api_app',
    current_database()
  );
  EXECUTE format(
    'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
    current_database()
  );
END
$$;

REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM sub2api_app;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM sub2api_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO sub2api_app;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO sub2api_app;

-- This binding is a sync-only security boundary. The gateway must never be
-- able to exchange invite fingerprints between users.
REVOKE ALL PRIVILEGES ON TABLE public.sub2api_sync_invite_owners FROM sub2api_app;
DO $$
DECLARE
  column_name text;
BEGIN
  FOR column_name IN
    SELECT attribute.attname
    FROM pg_attribute AS attribute
    WHERE attribute.attrelid = 'public.sub2api_sync_invite_owners'::regclass
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND attribute.attacl IS NOT NULL
      AND EXISTS (
        SELECT 1
        FROM aclexplode(attribute.attacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_app')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES (%I) ON TABLE public.sub2api_sync_invite_owners FROM sub2api_app',
      column_name
    );
  END LOOP;
END
$$;

-- Do not add default privileges. Owner-run schema migrations must be followed
-- by a replay of this explicit grant migration so new or sync-only tables fail
-- closed until reviewed.

COMMIT;
