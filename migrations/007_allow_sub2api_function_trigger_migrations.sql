\set ON_ERROR_STOP on

-- Sub2API 0.1.176 admin online updates apply goose 222/223-style
-- CREATE FUNCTION/TRIGGER on usage_logs. Replay after 005/006.
-- 0.1.178 goose 226 also needs additive ALTER TABLE plus table ownership.

BEGIN;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND rolsuper) THEN
    RAISE EXCEPTION 'app DDL guard must be installed by a PostgreSQL superuser';
  END IF;
  IF to_regprocedure('public.sub2api_gate_guard_app_ddl()') IS NULL THEN
    RAISE EXCEPTION 'apply migrations/005_app_least_privilege.sql before this guard update';
  END IF;
  IF to_regclass('public.usage_logs') IS NULL THEN
    RAISE EXCEPTION 'usage_logs must exist before granting trigger privilege';
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
  privacy_routine text :=
    '(conversation_content_policy|is_reviewed_content_metadata_column|'
    || 'is_conversation_capable_type|is_safe_auth_cache_key|'
    || 'content_job_status_is_terminal|assert_no_active_conversation_jobs|'
    || 'sanitize_scheduler_outbox_payload|is_safe_system_operation_id|'
    || 'sanitize_idempotency_request_fingerprint|'
    || 'sanitize_idempotency_response_body|strip_conversation_content|'
    || 'enforce_privacy_safe_settings|sub2api_gate_guard_app_ddl)';
  content_column text :=
    '(request_body|response_body|request_headers|response_headers|'
    || 'prompt|full_prompt|prompt_preview|prompt_hash|debug_response_body)';
BEGIN
  IF session_user <> 'sub2api_app' THEN
    RETURN;
  END IF;

  submitted_query := btrim(current_query(), E' \t\r\n');
  normalized_query := lower(regexp_replace(submitted_query, E'\\s+', ' ', 'g'));

  -- Deny-list: privilege, remote access, trigger-skipping rules, and
  -- cluster-level changes. Unknown additive goose tags fail open.
  IF tg_tag IN (
    'GRANT',
    'REVOKE',
    'TRUNCATE',
    'DROP TABLE',
    'DROP SCHEMA',
    'DROP DATABASE',
    'ALTER DATABASE',
    'ALTER SYSTEM',
    'CREATE EXTENSION',
    'ALTER EXTENSION',
    'DROP EXTENSION',
    'CREATE EVENT TRIGGER',
    'ALTER EVENT TRIGGER',
    'DROP EVENT TRIGGER',
    'CREATE FOREIGN TABLE',
    'ALTER FOREIGN TABLE',
    'DROP FOREIGN TABLE',
    'CREATE SERVER',
    'ALTER SERVER',
    'DROP SERVER',
    'CREATE USER MAPPING',
    'ALTER USER MAPPING',
    'DROP USER MAPPING',
    'CREATE FOREIGN DATA WRAPPER',
    'ALTER FOREIGN DATA WRAPPER',
    'DROP FOREIGN DATA WRAPPER',
    'CREATE ROLE',
    'ALTER ROLE',
    'DROP ROLE',
    'CREATE TABLESPACE',
    'ALTER TABLESPACE',
    'DROP TABLESPACE',
    'CREATE PUBLICATION',
    'ALTER PUBLICATION',
    'DROP PUBLICATION',
    'CREATE SUBSCRIPTION',
    'ALTER SUBSCRIPTION',
    'DROP SUBSCRIPTION',
    'CREATE POLICY',
    'ALTER POLICY',
    'DROP POLICY',
    'CREATE RULE',
    'ALTER RULE',
    'DROP RULE',
    'CREATE LANGUAGE',
    'CREATE ACCESS METHOD',
    'SECURITY LABEL'
  ) THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
  END IF;

  IF tg_tag = 'CREATE TABLE'
     AND submitted_query = E'CREATE TABLE IF NOT EXISTS schema_migrations (\n\tfilename   TEXT PRIMARY KEY,\n\tchecksum   TEXT NOT NULL,\n\tapplied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\n);' THEN
    RETURN;
  END IF;

  IF tg_tag = 'CREATE TABLE'
     AND normalized_query ~ ('create table( if not exists)? (only )?(public\.)?' || privacy_relation) THEN
    RAISE EXCEPTION USING
      ERRCODE = '42501',
      MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
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
    IF normalized_query ~ ('alter table (only )?(public\.)?' || privacy_relation)
       AND (
         normalized_query ~ ' drop column'
         OR normalized_query ~ ' rename column'
         OR normalized_query ~ ' rename to'
         OR normalized_query ~ (
              ' (add column( if not exists)?|alter column) '
              || content_column
              || '([^_a-z0-9]|$)'
            )
         OR normalized_query !~ (
              ' add column| add constraint| drop constraint| alter column|'
              || ' replica identity| attach partition| detach partition|'
              || ' validate constraint| cluster on| set default| drop default|'
              || ' set not null| drop not null'
            )
       ) THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    RETURN;
  END IF;

  IF tg_tag = 'CREATE FUNCTION' THEN
    IF normalized_query !~ 'create( or replace)? function'
       OR normalized_query ~ 'security definer'
       OR normalized_query ~ (
            'create( or replace)? function (if not exists )?(public\.)?'
            || privacy_routine
            || '([^_a-z0-9]|$)'
          ) THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    RETURN;
  END IF;

  IF tg_tag IN ('DROP FUNCTION', 'ALTER FUNCTION') THEN
    IF (tg_tag = 'DROP FUNCTION' AND normalized_query !~ 'drop function')
       OR (tg_tag = 'ALTER FUNCTION' AND normalized_query !~ 'alter function')
       OR normalized_query ~ (
         '(drop|alter) function (if exists )?(public\.)?'
         || privacy_routine
         || '([^_a-z0-9]|$)'
       )
       OR (tg_tag = 'ALTER FUNCTION' AND normalized_query ~ 'security definer') THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    RETURN;
  END IF;

  IF tg_tag = 'CREATE TRIGGER' THEN
    IF normalized_query !~ 'create( or replace)? constraint trigger'
       AND normalized_query !~ 'create( or replace)? trigger' THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    IF normalized_query ~ (
         'create( or replace)? (constraint )?trigger (if not exists )?'
         || privacy_routine
         || '([^_a-z0-9]|$)'
       )
       OR (
         normalized_query ~ (
           ' on (only )?(public\.)?' || privacy_relation || '([^_a-z0-9]|$)'
         )
         AND normalized_query !~ ' on (only )?(public\.)?usage_logs([^_a-z0-9]|$)'
       ) THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    RETURN;
  END IF;

  IF tg_tag = 'DROP TRIGGER' THEN
    IF normalized_query !~ 'drop trigger'
       OR normalized_query ~ (
         'drop trigger (if exists )?'
         || privacy_routine
         || '([^_a-z0-9]|$)'
       )
       OR (
         normalized_query ~ (
           ' on (only )?(public\.)?' || privacy_relation || '([^_a-z0-9]|$)'
         )
         AND normalized_query !~ ' on (only )?(public\.)?usage_logs([^_a-z0-9]|$)'
       ) THEN
      RAISE EXCEPTION USING
        ERRCODE = '42501',
        MESSAGE = format('sub2api_app persistent DDL is blocked [%s] %s', tg_tag, left(submitted_query, 160));
    END IF;
    RETURN;
  END IF;

  RETURN;
END
$$;
REVOKE ALL ON FUNCTION public.sub2api_gate_guard_app_ddl() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sub2api_gate_guard_app_ddl() FROM sub2api_app;

DROP EVENT TRIGGER IF EXISTS sub2api_gate_guard_app_ddl;
CREATE EVENT TRIGGER sub2api_gate_guard_app_ddl
  ON ddl_command_start
  EXECUTE FUNCTION public.sub2api_gate_guard_app_ddl();

GRANT TRIGGER ON TABLE public.usage_logs TO sub2api_app;

COMMIT;
