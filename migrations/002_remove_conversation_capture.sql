BEGIN;

-- This phase must remain short: it removes custom capture columns, installs
-- write guards, and commits before any historical rows are scrubbed.
DO $$
BEGIN
    IF to_regclass('public.request_logs') IS NOT NULL THEN
        EXECUTE 'ALTER TABLE public.request_logs '
            || 'DROP COLUMN IF EXISTS request_headers, '
            || 'DROP COLUMN IF EXISTS body_text, '
            || 'DROP COLUMN IF EXISTS body_preview, '
            || 'DROP COLUMN IF EXISTS body_truncated, '
            || 'DROP COLUMN IF EXISTS response_preview, '
            || 'DROP COLUMN IF EXISTS response_truncated, '
            || 'DROP COLUMN IF EXISTS response_captured_at, '
            || 'DROP COLUMN IF EXISTS debug_response_body, '
            || 'DROP COLUMN IF EXISTS debug_response_content_type, '
            || 'DROP COLUMN IF EXISTS debug_response_truncated, '
            || 'DROP COLUMN IF EXISTS debug_response_enabled, '
            || 'DROP COLUMN IF EXISTS debug_response_captured_at';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION public.conversation_content_policy()
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $function$
    SELECT jsonb_build_object(
        'usage_logs', jsonb_build_object(
            'prompt', NULL,
            'content', NULL,
            'messages', NULL,
            'input', NULL,
            'output', NULL,
            'payload', NULL,
            'request_body', NULL,
            'response_body', NULL,
            'request_headers', NULL,
            'response_headers', NULL,
            'body', NULL,
            'request', NULL,
            'response', NULL,
            'completion', NULL,
            'image_size_breakdown', NULL,
            'user_agent', NULL,
            'ip_address', NULL
        ),
        'audit_logs', jsonb_build_object(
            'actor_email', '',
            'credential_masked', '',
            'client_ip', '',
            'user_agent', '',
            'request_body', '',
            'extra', '{}'::jsonb
        ),
        'prompt_audit_events', jsonb_build_object(
            'username_snapshot', '',
            'user_email_snapshot', '',
            'api_key_name_snapshot', '',
            'group_name', '',
            'prompt_hash', '',
            'full_prompt', '',
            'redacted_preview', '',
            'categories', '[]'::jsonb,
            'matched_scanners', '[]'::jsonb,
            'scanner_scores', '{}'::jsonb,
            'scanner_evidence', '{}'::jsonb
        ),
        'prompt_audit_jobs', jsonb_build_object(
            'username_snapshot', '',
            'user_email_snapshot', '',
            'api_key_name_snapshot', '',
            'group_name', '',
            'prompt_hash', '',
            'redacted_preview', '',
            'last_error_message', ''
        ),
        'content_moderation_logs', jsonb_build_object(
            'user_email', '',
            'api_key_name', '',
            'group_name', '',
            'input_excerpt', '',
            'error', '',
            'matched_keyword', '',
            'category_scores', '{}'::jsonb,
            'threshold_snapshot', '{}'::jsonb
        ),
        'ops_error_logs', jsonb_build_object(
            'request_headers', NULL,
            'request_body', NULL,
            'response_headers', NULL,
            'response_body', NULL,
            'error_message', NULL,
            'error_body', NULL,
            'upstream_error_message', NULL,
            'upstream_error_detail', NULL,
            'upstream_errors', '[]'::jsonb,
            'error_type', '',
            'error_source', '',
            'error_owner', '',
            'provider_error_code', '',
            'provider_error_type', '',
            'network_error_type', '',
            'user_agent', NULL,
            'attempted_key_prefix', NULL,
            'deleted_key_name', NULL,
            'api_key_prefix', NULL
        ),
        'ops_retry_attempts', jsonb_build_object(
            'response_preview', '',
            'error_message', ''
        ),
        'ops_job_heartbeats', jsonb_build_object(
            'last_error', NULL,
            'last_result', NULL
        ),
        'ops_system_logs', jsonb_build_object(
            'message', '',
            'extra', '{}'::jsonb
        ),
        'ops_system_log_cleanup_audits', jsonb_build_object(
            'conditions', '{}'::jsonb
        ),
        'idempotency_records', jsonb_build_object(
            'request_fingerprint', '',
            'response_body', NULL,
            'error_reason', ''
        ),
        'deleted_api_key_audits', jsonb_build_object(
            'key', '',
            'key_name', ''
        ),
        'usage_billing_dedup', jsonb_build_object(
            'request_fingerprint', ''
        ),
        'usage_billing_dedup_archive', jsonb_build_object(
            'request_fingerprint', ''
        ),
        'auth_cache_invalidation_outbox', jsonb_build_object(
            'last_error', NULL
        ),
        'usage_cleanup_tasks', jsonb_build_object(
            'error_message', NULL
        ),
        'scheduled_test_results', jsonb_build_object(
            'response_text', '',
            'error_message', ''
        ),
        'channel_monitor_histories', jsonb_build_object(
            'message', ''
        ),
        'sora_generations', jsonb_build_object(
            'prompt', '',
            'media_url', '',
            'media_urls', NULL,
            's3_object_keys', NULL,
            'error_message', ''
        ),
        'batch_image_jobs', jsonb_build_object(
            'task_name', '',
            'provider_input_ref', NULL,
            'provider_output_ref', NULL,
            'gcs_input_uri', NULL,
            'gcs_output_uri', NULL,
            'request_hash', NULL,
            'manifest_hash', NULL,
            'idempotency_key', NULL,
            'last_error_message', NULL
        ),
        'batch_image_items', jsonb_build_object(
            'request_hash', NULL,
            'prompt_preview', NULL,
            'provider_source_object', NULL,
            'error_message', NULL
        ),
        'batch_image_events', jsonb_build_object(
            'payload', NULL,
            'event_hash', NULL
        ),
        -- The generic replacement is a schema-policy marker. Scheduler payloads
        -- are normalized separately so current ID/time-only invalidations keep
        -- working while unknown keys and values are discarded.
        'scheduler_outbox', jsonb_build_object(
            'payload', NULL
        )
    )
$function$;

CREATE OR REPLACE FUNCTION public.is_reviewed_content_metadata_column(
    target_table text,
    target_column text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $function$
    SELECT COALESCE(CASE target_table
        WHEN 'audit_logs' THEN target_column = ANY (ARRAY[
            'actor_role', 'auth_method', 'action', 'method', 'path',
            'request_id'
        ])
        WHEN 'auth_cache_invalidation_outbox' THEN target_column = ANY (ARRAY[
            'cache_key', 'claimed_by'
        ])
        WHEN 'batch_image_events' THEN target_column = ANY (ARRAY[
            'job_id', 'event_type'
        ])
        WHEN 'batch_image_items' THEN target_column = ANY (ARRAY[
            'job_id', 'custom_id', 'status', 'mime_type', 'file_extension',
            'error_code'
        ])
        WHEN 'batch_image_jobs' THEN target_column = ANY (ARRAY[
            'batch_id', 'provider', 'model', 'status', 'provider_job_name',
            'currency', 'hold_id', 'last_error_code', 'parent_batch_id'
        ])
        WHEN 'channel_monitor_histories' THEN target_column = ANY (ARRAY[
            'model', 'status'
        ])
        WHEN 'content_moderation_logs' THEN target_column = ANY (ARRAY[
            'request_id', 'endpoint', 'provider', 'model', 'mode', 'action',
            'highest_category'
        ])
        WHEN 'idempotency_records' THEN target_column = ANY (ARRAY[
            'scope', 'idempotency_key_hash', 'status'
        ])
        WHEN 'ops_error_logs' THEN target_column = ANY (ARRAY[
            'request_id', 'client_request_id', 'platform', 'model',
            'request_path', 'error_phase', 'severity', 'account_status',
            'inbound_endpoint', 'upstream_endpoint', 'requested_model',
            'upstream_model'
        ])
        WHEN 'ops_job_heartbeats' THEN target_column = 'job_name'
        WHEN 'ops_system_logs' THEN target_column = ANY (ARRAY[
            'level', 'component', 'request_id', 'client_request_id',
            'platform', 'model', 'host'
        ])
        WHEN 'payment_audit_logs' THEN target_column = ANY (ARRAY[
            'order_id', 'action', 'detail', 'operator'
        ])
        WHEN 'prompt_audit_events' THEN target_column = ANY (ARRAY[
            'request_id', 'provider', 'endpoint', 'protocol', 'model', 'stage',
            'decision', 'risk_level', 'action', 'scanner_backend',
            'scanner_version', 'guard_endpoint_id', 'policy_id'
        ])
        WHEN 'prompt_audit_jobs' THEN target_column = ANY (ARRAY[
            'request_id', 'provider', 'endpoint', 'protocol', 'model', 'stage',
            'execution_mode', 'status', 'last_error_code'
        ])
        WHEN 'request_logs' THEN target_column = 'request_id'
        WHEN 'scheduled_test_results' THEN target_column = 'status'
        WHEN 'scheduler_outbox' THEN target_column = ANY (ARRAY[
            'event_type', 'dedup_key'
        ])
        WHEN 'sora_generations' THEN target_column = ANY (ARRAY[
            'status', 'model', 'upstream_task_id'
        ])
        WHEN 'usage_billing_dedup' THEN target_column = 'request_id'
        WHEN 'usage_billing_dedup_archive' THEN target_column = 'request_id'
        WHEN 'usage_cleanup_tasks' THEN target_column = 'status'
        WHEN 'usage_logs' THEN target_column = ANY (ARRAY[
            'request_id', 'model', 'image_size', 'reasoning_effort',
            'service_tier', 'inbound_endpoint', 'upstream_endpoint',
            'upstream_model', 'requested_model', 'model_mapping_chain',
            'billing_tier', 'billing_mode', 'image_input_size',
            'image_output_size', 'image_size_source', 'video_resolution'
        ])
        ELSE false
    END, false)
$function$;

CREATE OR REPLACE FUNCTION public.is_conversation_capable_type(
    target_type oid
)
RETURNS boolean
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $function$
    WITH RECURSIVE type_chain AS (
        SELECT type.oid, type.typtype, type.typbasetype, type.typelem
        FROM pg_catalog.pg_type AS type
        WHERE type.oid = target_type

        UNION ALL

        SELECT base.oid, base.typtype, base.typbasetype, base.typelem
        FROM type_chain AS current_type
        JOIN pg_catalog.pg_type AS base
          ON base.oid = current_type.typbasetype
        WHERE current_type.typtype = 'd'
          AND current_type.typbasetype <> 0
    )
    SELECT COALESCE(bool_or(
        type_chain.oid = ANY (ARRAY[
            'pg_catalog.text'::regtype::oid,
            'pg_catalog.varchar'::regtype::oid,
            'pg_catalog.bpchar'::regtype::oid,
            'pg_catalog.json'::regtype::oid,
            'pg_catalog.jsonb'::regtype::oid,
            'pg_catalog.bytea'::regtype::oid,
            'pg_catalog.xml'::regtype::oid
        ])
        OR type_chain.typelem <> 0
    ), false)
    FROM type_chain
$function$;

CREATE OR REPLACE FUNCTION public.is_safe_auth_cache_key(
    cache_key text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $function$
    SELECT COALESCE(
        length(cache_key) = 64
        AND cache_key ~ '^[0-9a-f]{64}$',
        false
    )
$function$;

CREATE OR REPLACE FUNCTION public.content_job_status_is_terminal(
    target_table text,
    raw_status text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $function$
    SELECT COALESCE(CASE target_table
        WHEN 'batch_image_jobs' THEN lower(btrim(raw_status)) IN (
            'completed', 'failed', 'cancelled', 'output_deleted'
        )
        WHEN 'sora_generations' THEN lower(btrim(raw_status)) IN (
            'completed', 'failed', 'cancelled'
        )
        ELSE false
    END, false)
$function$;

CREATE OR REPLACE FUNCTION public.assert_no_active_conversation_jobs()
RETURNS void
LANGUAGE plpgsql
AS $function$
DECLARE
    target_table text;
    relation regclass;
    has_active_rows boolean;
BEGIN
    FOREACH target_table IN ARRAY ARRAY[
        'batch_image_jobs',
        'sora_generations'
    ]
    LOOP
        relation := to_regclass(format('public.%I', target_table));
        IF relation IS NULL THEN
            CONTINUE;
        END IF;
        IF NOT EXISTS (
            SELECT 1
            FROM pg_attribute
            WHERE attrelid = relation
              AND attname = 'status'
              AND attnum > 0
              AND NOT attisdropped
        ) THEN
            RAISE EXCEPTION 'content job table has no reviewable status: %',
                target_table;
        END IF;
        EXECUTE format(
            'SELECT EXISTS (SELECT 1 FROM %s '
            || 'WHERE NOT public.content_job_status_is_terminal($1, status::text))',
            relation
        ) INTO has_active_rows USING target_table;
        IF has_active_rows THEN
            RAISE EXCEPTION
                'active content jobs must be drained or cancelled before privacy migration: %',
                target_table;
        END IF;
    END LOOP;
END
$function$;

CREATE OR REPLACE FUNCTION public.sanitize_scheduler_outbox_payload(
    event_type text,
    raw_payload jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $function$
DECLARE
    safe_account_ids jsonb;
    safe_group_ids jsonb;
    safe_last_used jsonb;
BEGIN
    IF raw_payload IS NULL OR jsonb_typeof(raw_payload) <> 'object' THEN
        RETURN NULL;
    END IF;

    IF event_type IN ('account_changed', 'account_groups_changed') THEN
        SELECT COALESCE(jsonb_agg(entry.value ORDER BY entry.ordinality), '[]'::jsonb)
        INTO safe_group_ids
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(raw_payload -> 'group_ids') = 'array'
                THEN raw_payload -> 'group_ids'
                ELSE '[]'::jsonb
            END
        ) WITH ORDINALITY AS entry(value, ordinality)
        WHERE jsonb_typeof(entry.value) = 'number'
          AND entry.value::text ~ '^[1-9][0-9]{0,18}$';
        RETURN jsonb_build_object('group_ids', safe_group_ids);
    END IF;

    IF event_type = 'account_bulk_changed' THEN
        SELECT COALESCE(jsonb_agg(entry.value ORDER BY entry.ordinality), '[]'::jsonb)
        INTO safe_account_ids
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(raw_payload -> 'account_ids') = 'array'
                THEN raw_payload -> 'account_ids'
                ELSE '[]'::jsonb
            END
        ) WITH ORDINALITY AS entry(value, ordinality)
        WHERE jsonb_typeof(entry.value) = 'number'
          AND entry.value::text ~ '^[1-9][0-9]{0,18}$';

        SELECT COALESCE(jsonb_agg(entry.value ORDER BY entry.ordinality), '[]'::jsonb)
        INTO safe_group_ids
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(raw_payload -> 'group_ids') = 'array'
                THEN raw_payload -> 'group_ids'
                ELSE '[]'::jsonb
            END
        ) WITH ORDINALITY AS entry(value, ordinality)
        WHERE jsonb_typeof(entry.value) = 'number'
          AND entry.value::text ~ '^[1-9][0-9]{0,18}$';

        RETURN jsonb_build_object(
            'account_ids', safe_account_ids,
            'group_ids', safe_group_ids
        );
    END IF;

    IF event_type = 'account_last_used' THEN
        SELECT COALESCE(jsonb_object_agg(entry.key, entry.value), '{}'::jsonb)
        INTO safe_last_used
        FROM jsonb_each(
            CASE WHEN jsonb_typeof(raw_payload -> 'last_used') = 'object'
                THEN raw_payload -> 'last_used'
                ELSE '{}'::jsonb
            END
        ) AS entry(key, value)
        WHERE entry.key ~ '^[1-9][0-9]{0,18}$'
          AND jsonb_typeof(entry.value) = 'number'
          AND entry.value::text ~ '^[1-9][0-9]{0,18}$';
        RETURN jsonb_build_object('last_used', safe_last_used);
    END IF;

    RETURN NULL;
END
$function$;

CREATE OR REPLACE FUNCTION public.is_safe_system_operation_id(
    operation_id text
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $function$
    SELECT COALESCE(
        length(operation_id) BETWEEN 7 AND 64
        AND operation_id ~ '^sysop-[A-Za-z0-9._:-]+$',
        false
    )
$function$;

CREATE OR REPLACE FUNCTION public.sanitize_idempotency_request_fingerprint(
    scope_name text,
    raw_fingerprint text
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $function$
    SELECT CASE
        WHEN scope_name = 'admin.system.operations.global_lock'
         AND public.is_safe_system_operation_id(raw_fingerprint)
        THEN raw_fingerprint
        ELSE ''
    END
$function$;

CREATE OR REPLACE FUNCTION public.sanitize_idempotency_response_body(
    scope_name text,
    status_name text,
    raw_body text
)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
AS $function$
DECLARE
    parsed jsonb;
    operation_id text;
BEGIN
    IF scope_name IS DISTINCT FROM 'admin.system.operations.global_lock'
       OR status_name IS DISTINCT FROM 'succeeded'
       OR raw_body IS NULL THEN
        RETURN NULL;
    END IF;

    BEGIN
        parsed := raw_body::jsonb;
    EXCEPTION WHEN OTHERS THEN
        RETURN NULL;
    END;
    IF jsonb_typeof(parsed) <> 'object'
       OR parsed -> 'released' IS DISTINCT FROM 'true'::jsonb THEN
        RETURN NULL;
    END IF;
    operation_id := parsed ->> 'operation_id';
    IF NOT public.is_safe_system_operation_id(operation_id) THEN
        RETURN NULL;
    END IF;

    RETURN jsonb_build_object(
        'operation_id', operation_id,
        'released', true
    )::text;
END
$function$;

SELECT public.assert_no_active_conversation_jobs();

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.pg_attribute AS attribute
        JOIN pg_catalog.pg_class AS relation
          ON relation.oid = attribute.attrelid
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname <> 'public'
          AND namespace.nspname <> 'information_schema'
          AND namespace.nspname NOT LIKE 'pg\_%' ESCAPE '\'
          AND relation.relkind IN ('r', 'p', 'v', 'm', 'f')
          AND attribute.attnum > 0
          AND NOT attribute.attisdropped
          AND public.is_conversation_capable_type(attribute.atttypid)
    ) THEN
        RAISE EXCEPTION
            'content-capable relation exists outside the reviewed public schema';
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.strip_conversation_content()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
    policy jsonb;
    replacements jsonb;
    normalized_phase text;
    original_payload jsonb;
    normalized_payload jsonb;
    status_value text;
    original_fingerprint text;
    original_response_body text;
    normalized_fingerprint text;
    normalized_response_body text;
BEGIN
    policy := public.conversation_content_policy();
    replacements := policy -> TG_TABLE_NAME;
    IF replacements IS NULL THEN
        RAISE EXCEPTION 'conversation content policy missing for table %',
            TG_TABLE_NAME;
    END IF;

    IF TG_TABLE_NAME IN ('batch_image_jobs', 'sora_generations') THEN
        status_value := to_jsonb(NEW) ->> 'status';
        IF NOT public.content_job_status_is_terminal(
            TG_TABLE_NAME,
            status_value
        ) THEN
            RAISE EXCEPTION
                'active content jobs are disabled by the conversation privacy guard: %',
                TG_TABLE_NAME;
        END IF;
    END IF;

    IF TG_TABLE_NAME = 'scheduler_outbox' THEN
        original_payload := to_jsonb(NEW) -> 'payload';
        normalized_payload := public.sanitize_scheduler_outbox_payload(
            to_jsonb(NEW) ->> 'event_type',
            original_payload
        );
        NEW := jsonb_populate_record(NEW, replacements - 'payload');
        NEW := jsonb_populate_record(
            NEW,
            jsonb_build_object('payload', normalized_payload)
        );
    ELSIF TG_TABLE_NAME = 'idempotency_records' THEN
        original_fingerprint := to_jsonb(NEW) ->> 'request_fingerprint';
        original_response_body := to_jsonb(NEW) ->> 'response_body';
        normalized_fingerprint :=
            public.sanitize_idempotency_request_fingerprint(
                to_jsonb(NEW) ->> 'scope',
                original_fingerprint
            );
        normalized_response_body :=
            public.sanitize_idempotency_response_body(
                to_jsonb(NEW) ->> 'scope',
                to_jsonb(NEW) ->> 'status',
                original_response_body
            );
        NEW := jsonb_populate_record(
            NEW,
            replacements - 'request_fingerprint' - 'response_body'
        );
        NEW := jsonb_populate_record(
            NEW,
            jsonb_build_object(
                'request_fingerprint', normalized_fingerprint,
                'response_body', normalized_response_body
            )
        );
    ELSIF TG_TABLE_NAME = 'auth_cache_invalidation_outbox' THEN
        IF NOT public.is_safe_auth_cache_key(
            to_jsonb(NEW) ->> 'cache_key'
        ) THEN
            RAISE EXCEPTION 'auth cache key must remain a SHA-256 reference'
                USING ERRCODE = '23514';
        END IF;
        NEW := jsonb_populate_record(NEW, replacements);
    ELSE
        NEW := jsonb_populate_record(NEW, replacements);
    END IF;
    IF TG_TABLE_NAME = 'ops_error_logs' AND to_jsonb(NEW) ? 'error_phase' THEN
        normalized_phase := lower(btrim(to_jsonb(NEW)->>'error_phase'));
        IF normalized_phase IS NULL OR normalized_phase NOT IN (
            'request', 'auth', 'routing', 'upstream', 'network', 'internal'
        ) THEN
            normalized_phase := 'internal';
        END IF;
        NEW := jsonb_populate_record(
            NEW,
            jsonb_build_object('error_phase', normalized_phase)
        );
    END IF;
    RETURN NEW;
END
$function$;

CREATE OR REPLACE FUNCTION public.enforce_privacy_safe_settings()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.key IN ('risk_control_enabled', 'image_storage_config') THEN
            RAISE EXCEPTION 'privacy-safe setting cannot be deleted: %', OLD.key
                USING ERRCODE = '23514';
        END IF;
        RETURN OLD;
    END IF;

    IF TG_OP = 'UPDATE'
       AND OLD.key IN ('risk_control_enabled', 'image_storage_config')
       AND NEW.key IS DISTINCT FROM OLD.key THEN
        RAISE EXCEPTION 'privacy-safe setting cannot be renamed: %', OLD.key
            USING ERRCODE = '23514';
    END IF;

    IF NEW.key = 'risk_control_enabled' THEN
        NEW.value := 'false';
    ELSIF NEW.key = 'image_storage_config' THEN
        -- Drop credentials and every other fallback-capable option, rather
        -- than merely flipping the enabled member in the supplied document.
        NEW.value := '{"enabled":false}';
    END IF;
    RETURN NEW;
END
$function$;

DO $$
DECLARE
    target_table text;
    relation regclass;
BEGIN
    FOR target_table IN
        SELECT jsonb_object_keys(public.conversation_content_policy())
    LOOP
        relation := to_regclass(format('public.%I', target_table));
        IF relation IS NULL THEN
            CONTINUE;
        END IF;
        EXECUTE format(
            'DROP TRIGGER IF EXISTS strip_conversation_content ON %s',
            relation
        );
        EXECUTE format(
            'CREATE TRIGGER strip_conversation_content '
            || 'BEFORE INSERT OR UPDATE ON %s '
            || 'FOR EACH ROW EXECUTE FUNCTION public.strip_conversation_content()',
            relation
        );
    END LOOP;
END $$;

DO $$
BEGIN
    IF to_regclass('public.settings') IS NOT NULL THEN
        DROP TRIGGER IF EXISTS enforce_privacy_safe_settings
            ON public.settings;
        CREATE TRIGGER enforce_privacy_safe_settings
            BEFORE INSERT OR UPDATE OR DELETE ON public.settings
            FOR EACH ROW
            EXECUTE FUNCTION public.enforce_privacy_safe_settings();

        INSERT INTO public.settings (key, value, updated_at)
        VALUES
            ('risk_control_enabled', 'false', NOW()),
            ('image_storage_config', '{"enabled":false}', NOW())
        ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
        WHERE settings.value IS DISTINCT FROM EXCLUDED.value;
    END IF;
END $$;

COMMIT;
