\set ON_ERROR_STOP on

-- Read-only post-scrub gate. Missing optional tables/columns are accepted;
-- any surviving capture field, content residue, disabled guard, or unreviewed
-- content-capable schema field aborts the check.
DO $$
DECLARE
    policy jsonb;
    target RECORD;
    field RECORD;
    relation regclass;
    has_residue boolean;
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
            'public.is_conversation_capable_type(oid)'
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

    FOR target IN
        SELECT column_name
        FROM (VALUES
            ('request_headers'),
            ('body_text'),
            ('body_preview'),
            ('body_truncated'),
            ('response_preview'),
            ('response_truncated'),
            ('response_captured_at'),
            ('debug_response_body'),
            ('debug_response_content_type'),
            ('debug_response_truncated'),
            ('debug_response_enabled'),
            ('debug_response_captured_at')
        ) AS capture_columns(column_name)
    LOOP
        IF EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'request_logs'
              AND column_name = target.column_name
        ) THEN
            RAISE EXCEPTION 'content capture column remains: request_logs.%',
                target.column_name;
        END IF;
    END LOOP;

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

        FOR field IN
            SELECT key AS column_name, value AS replacement
            FROM jsonb_each(target.replacements)
        LOOP
            IF NOT EXISTS (
                SELECT 1
                FROM pg_attribute
                WHERE attrelid = relation
                  AND attname = field.column_name
                  AND attnum > 0
                  AND NOT attisdropped
            ) THEN
                CONTINUE;
            END IF;

            IF target.table_name = 'scheduler_outbox'
               AND field.column_name = 'payload' THEN
                EXECUTE format(
                    'SELECT EXISTS (SELECT 1 FROM %s '
                    || 'WHERE payload IS DISTINCT FROM '
                    || 'public.sanitize_scheduler_outbox_payload('
                    || 'event_type::text, payload))',
                    relation
                ) INTO has_residue;
            ELSIF target.table_name = 'idempotency_records'
               AND field.column_name = 'request_fingerprint' THEN
                EXECUTE format(
                    'SELECT EXISTS (SELECT 1 FROM %s '
                    || 'WHERE request_fingerprint IS DISTINCT FROM '
                    || 'public.sanitize_idempotency_request_fingerprint('
                    || 'scope::text, request_fingerprint::text))',
                    relation
                ) INTO has_residue;
            ELSIF target.table_name = 'idempotency_records'
               AND field.column_name = 'response_body' THEN
                EXECUTE format(
                    'SELECT EXISTS (SELECT 1 FROM %s '
                    || 'WHERE response_body IS DISTINCT FROM '
                    || 'public.sanitize_idempotency_response_body('
                    || 'scope::text, status::text, response_body::text))',
                    relation
                ) INTO has_residue;
            ELSIF field.replacement = 'null'::jsonb THEN
                EXECUTE format(
                    'SELECT EXISTS (SELECT 1 FROM %s WHERE %I IS NOT NULL)',
                    relation,
                    field.column_name
                ) INTO has_residue;
            ELSE
                EXECUTE format(
                    'SELECT EXISTS (SELECT 1 FROM %s '
                    || 'WHERE to_jsonb(%I) IS DISTINCT FROM $1)',
                    relation,
                    field.column_name
                ) INTO has_residue USING field.replacement;
            END IF;

            IF has_residue THEN
                RAISE EXCEPTION 'conversation-capable content remains: %.%',
                    target.table_name, field.column_name;
            END IF;
        END LOOP;
    END LOOP;

    IF to_regclass('public.ops_error_logs') IS NOT NULL AND EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = to_regclass('public.ops_error_logs')
          AND attname = 'error_phase'
          AND attnum > 0
          AND NOT attisdropped
    ) THEN
        EXECUTE $sql$
            SELECT EXISTS (
                SELECT 1
                FROM public.ops_error_logs
                WHERE error_phase IS NULL
                   OR lower(btrim(error_phase::text)) NOT IN (
                       'request', 'auth', 'routing',
                       'upstream', 'network', 'internal'
                   )
            )
        $sql$ INTO has_residue;
        IF has_residue THEN
            RAISE EXCEPTION 'conversation-capable content remains: ops_error_logs.error_phase';
        END IF;
    END IF;

    IF to_regclass('public.auth_cache_invalidation_outbox') IS NOT NULL
       AND EXISTS (
            SELECT 1
            FROM pg_attribute
            WHERE attrelid = to_regclass(
                    'public.auth_cache_invalidation_outbox'
                  )
              AND attname = 'cache_key'
              AND attnum > 0
              AND NOT attisdropped
       ) THEN
        EXECUTE $sql$
            SELECT EXISTS (
                SELECT 1
                FROM public.auth_cache_invalidation_outbox
                WHERE NOT public.is_safe_auth_cache_key(cache_key::text)
            )
        $sql$ INTO has_residue;
        IF has_residue THEN
            RAISE EXCEPTION
                'credential-derived auth cache reference is invalid';
        END IF;
    END IF;

    -- Fail closed on upstream schema drift. All content-capable fields must be
    -- scrubbed by the shared policy or be an explicitly reviewed exception.
    FOR target IN
        SELECT namespace.nspname AS schema_name,
               relation.relname AS table_name,
               attribute.attname AS column_name
        FROM pg_catalog.pg_attribute AS attribute
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname <> 'information_schema'
          AND namespace.nspname NOT LIKE 'pg\_%' ESCAPE '\'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND public.is_conversation_capable_type(attribute.atttypid)
          AND (
            namespace.nspname <> 'public'
            OR policy ? relation.relname
            OR lower(relation.relname) LIKE '%log%'
            OR lower(relation.relname) LIKE '%audit%'
            OR lower(relation.relname) LIKE '%moderation%'
            OR relation.relname = 'request_logs'
            OR relation.relname = 'idempotency_records'
            OR relation.relname = 'ops_retry_attempts'
          )
    LOOP
        IF target.schema_name <> 'public' THEN
            RAISE EXCEPTION
                'unreviewed content-capable field outside public schema';
        END IF;
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
            -- Financial reconciliation detail is unrelated to conversations.
            ('payment_audit_logs', 'detail'),
            -- HMAC/SHA digest of an admin idempotency key, never a request body.
            ('idempotency_records', 'idempotency_key_hash'),
            -- These are bounded classification/stable-code metadata.
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
