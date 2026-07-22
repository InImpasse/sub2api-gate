\set ON_ERROR_STOP on

-- Read-only gate run after the guard transaction commits and before any
-- historical scrub starts.
DO $$
DECLARE
    policy jsonb;
    target RECORD;
    relation regclass;
    converted jsonb;
BEGIN
    IF to_regprocedure('public.conversation_content_policy()') IS NULL
       OR to_regprocedure('public.strip_conversation_content()') IS NULL
       OR to_regprocedure(
            'public.content_job_status_is_terminal(text,text)'
          ) IS NULL
       OR to_regprocedure(
            'public.assert_no_active_conversation_jobs()'
          ) IS NULL
       OR to_regprocedure(
            'public.sanitize_scheduler_outbox_payload(text,jsonb)'
          ) IS NULL
       OR to_regprocedure(
            'public.is_safe_system_operation_id(text)'
          ) IS NULL
       OR to_regprocedure(
            'public.sanitize_idempotency_request_fingerprint(text,text)'
          ) IS NULL
       OR to_regprocedure(
            'public.sanitize_idempotency_response_body(text,text,text)'
          ) IS NULL
       OR to_regprocedure(
            'public.is_reviewed_content_metadata_column(text,text)'
          ) IS NULL
       OR to_regprocedure(
            'public.is_safe_auth_cache_key(text)'
          ) IS NULL
       OR to_regprocedure(
            'public.enforce_privacy_safe_settings()'
          ) IS NULL THEN
        RAISE EXCEPTION 'conversation content write guards are not installed';
    END IF;
    policy := public.conversation_content_policy();
    PERFORM public.assert_no_active_conversation_jobs();

    IF to_regclass('public.settings') IS NOT NULL THEN
        PERFORM 1
        FROM public.settings
        WHERE key = 'risk_control_enabled'
          AND lower(btrim(value::text)) = 'false';
        IF NOT FOUND THEN
            RAISE EXCEPTION 'risk control must remain disabled';
        END IF;

        PERFORM 1
        FROM public.settings
        WHERE key = 'image_storage_config'
          AND value::jsonb = '{"enabled":false}'::jsonb;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'async image storage must remain disabled and credential-free';
        END IF;

        IF NOT EXISTS (
            SELECT 1
            FROM pg_trigger
            WHERE tgrelid = to_regclass('public.settings')
              AND tgname = 'enforce_privacy_safe_settings'
              AND tgfoid = to_regprocedure(
                    'public.enforce_privacy_safe_settings()'
                  )
              AND (tgtype & 31) = 31
              AND tgenabled IN ('O', 'A')
              AND NOT tgisinternal
        ) THEN
            RAISE EXCEPTION 'privacy-safe settings write guard missing';
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'request_logs'
          AND column_name IN (
              'request_headers', 'body_text', 'body_preview',
              'body_truncated', 'response_preview', 'response_truncated',
              'response_captured_at', 'debug_response_body',
              'debug_response_content_type', 'debug_response_truncated',
              'debug_response_enabled', 'debug_response_captured_at'
          )
    ) THEN
        RAISE EXCEPTION 'request content capture columns remain';
    END IF;

    FOR target IN
        SELECT key AS table_name, value AS replacements
        FROM jsonb_each(policy)
    LOOP
        relation := to_regclass(format('public.%I', target.table_name));
        IF relation IS NULL THEN
            CONTINUE;
        END IF;
        IF NOT EXISTS (
            SELECT 1
            FROM pg_trigger
            WHERE tgrelid = relation
              AND tgname = 'strip_conversation_content'
              AND tgfoid = to_regprocedure('public.strip_conversation_content()')
              AND (tgtype & 23) = 23
              AND tgenabled IN ('O', 'A')
              AND NOT tgisinternal
        ) THEN
            RAISE EXCEPTION 'conversation content write guard missing: %',
                target.table_name;
        END IF;

        EXECUTE format(
            'SELECT to_jsonb(jsonb_populate_record(NULL::%s, $1))',
            relation
        ) INTO converted USING target.replacements;
    END LOOP;

    FOR target IN
        SELECT columns.table_name, columns.column_name
        FROM information_schema.columns AS columns
        WHERE columns.table_schema = 'public'
          AND (
            policy ? columns.table_name
            OR columns.table_name LIKE '%log%'
            OR columns.table_name LIKE '%audit%'
            OR columns.table_name LIKE '%moderation%'
            OR columns.table_name = 'request_logs'
            OR columns.table_name = 'idempotency_records'
            OR columns.table_name = 'ops_retry_attempts'
          )
          AND (
            columns.data_type IN (
              'text', 'character varying', 'json', 'jsonb', 'bytea', 'xml',
              'ARRAY'
            )
          )
    LOOP
        IF target.column_name IN (
            'request_id', 'client_request_id',
            'result_request_id', 'result_usage_request_id'
        ) THEN
            CONTINUE;
        END IF;
        IF public.is_reviewed_content_metadata_column(
            target.table_name,
            target.column_name
        ) THEN
            CONTINUE;
        END IF;
        IF (target.table_name, target.column_name) IN (
            ('payment_audit_logs', 'detail'),
            ('idempotency_records', 'idempotency_key_hash'),
            ('ops_error_logs', 'error_phase'),
            ('prompt_audit_jobs', 'last_error_code'),
            ('batch_image_jobs', 'last_error_code'),
            ('batch_image_items', 'error_code'),
            ('ops_error_logs', 'request_path'),
            ('usage_cleanup_tasks', 'filters')
        ) THEN
            CONTINUE;
        END IF;
        IF NOT (
            policy ? target.table_name
            AND policy -> target.table_name ? target.column_name
        ) THEN
            RAISE EXCEPTION 'unreviewed content-capable schema field: %.%',
                target.table_name, target.column_name;
        END IF;
    END LOOP;
END
$$;
