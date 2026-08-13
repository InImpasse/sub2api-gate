\set ON_ERROR_STOP on

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper) THEN
    RAISE EXCEPTION 'app DDL guard must be installed by a PostgreSQL superuser';
  END IF;
  IF to_regprocedure('public.sub2api_gate_guard_app_ddl()') IS NULL THEN
    RAISE EXCEPTION 'apply migrations/005_app_least_privilege.sql before this guard update';
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
END
$$;

COMMIT;
