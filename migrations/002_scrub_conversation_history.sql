\set ON_ERROR_STOP on

-- Guards from 002_remove_conversation_capture.sql are already committed.
-- Each procedure commits batches independently so a large history table does
-- not retain locks for the whole scrub. The script is safe to resume.
CREATE OR REPLACE PROCEDURE pg_temp.scrub_optional_content_columns(
    target_table regclass,
    replacements jsonb,
    batch_size integer
)
LANGUAGE plpgsql
AS $procedure$
DECLARE
    assignments text;
    where_clause text;
    last_id bigint;
    batch_last_id bigint;
    updated_rows bigint;
    has_id boolean;
BEGIN
    IF target_table IS NULL THEN
        RETURN;
    END IF;
    IF batch_size < 1 OR batch_size > 10000 THEN
        RAISE EXCEPTION 'privacy scrub batch size is out of range';
    END IF;

    SELECT string_agg(
        format(
            '%1$I = (jsonb_populate_record(NULL::%2$s, $1)).%1$I',
            attribute.attname,
            target_table
        ),
        ', '
    ), string_agg(
        format(
            'to_jsonb(%1$I) IS DISTINCT FROM '
            || 'to_jsonb((jsonb_populate_record(NULL::%2$s, $1)).%1$I)',
            attribute.attname,
            target_table
        ),
        ' OR '
    )
    INTO assignments, where_clause
    FROM pg_attribute attribute
    WHERE attribute.attrelid = target_table
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND replacements ? attribute.attname;

    IF assignments IS NULL OR where_clause IS NULL THEN
        RETURN;
    END IF;
    SELECT EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = target_table
          AND attname = 'id'
          AND attnum > 0
          AND NOT attisdropped
    ) INTO has_id;

    IF NOT has_id THEN
        LOOP
            EXECUTE format(
                'WITH candidates AS MATERIALIZED ('
                || 'SELECT ctid AS row_tid FROM %s WHERE (%s) '
                || 'LIMIT $2 FOR UPDATE'
                || '), scrubbed AS ('
                || 'UPDATE %s AS target SET %s '
                || 'FROM candidates WHERE target.ctid = candidates.row_tid '
                || 'RETURNING 1'
                || ') SELECT count(*) FROM scrubbed',
                target_table,
                where_clause,
                target_table,
                assignments
            )
            INTO updated_rows
            USING replacements, batch_size;

            COMMIT;
            EXIT WHEN updated_rows = 0;
        END LOOP;
        RETURN;
    END IF;

    LOOP
        EXECUTE format(
            'WITH candidates AS MATERIALIZED ('
            || 'SELECT id FROM %s '
            || 'WHERE ($2 IS NULL OR id > $2) AND (%s) '
            || 'ORDER BY id LIMIT $3 FOR UPDATE'
            || '), scrubbed AS ('
            || 'UPDATE %s AS target SET %s '
            || 'FROM candidates WHERE target.id = candidates.id '
            || 'RETURNING target.id'
            || ') SELECT count(*), max(id)::bigint FROM scrubbed',
            target_table,
            where_clause,
            target_table,
            assignments
        )
        INTO updated_rows, batch_last_id
        USING replacements, last_id, batch_size;

        COMMIT;
        EXIT WHEN updated_rows = 0;
        last_id := batch_last_id;
    END LOOP;
END
$procedure$;

CREATE OR REPLACE PROCEDURE pg_temp.normalize_idempotency_records(
    target_table regclass,
    batch_size integer
)
LANGUAGE plpgsql
AS $procedure$
DECLARE
    last_id bigint;
    batch_last_id bigint;
    updated_rows bigint;
BEGIN
    IF target_table IS NULL THEN
        RETURN;
    END IF;
    IF batch_size < 1 OR batch_size > 10000 THEN
        RAISE EXCEPTION 'privacy scrub batch size is out of range';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = target_table
          AND attname IN (
              'id', 'scope', 'status',
              'request_fingerprint', 'response_body'
          )
          AND attnum > 0
          AND NOT attisdropped
        GROUP BY attrelid
        HAVING count(*) = 5
    ) THEN
        RAISE EXCEPTION
            'idempotency privacy scrub requires id, scope, status, fingerprint, and response columns';
    END IF;

    LOOP
        EXECUTE format(
            'WITH candidates AS MATERIALIZED ('
            || 'SELECT id FROM %s WHERE ($1 IS NULL OR id > $1) AND ('
            || 'request_fingerprint IS DISTINCT FROM '
            || 'public.sanitize_idempotency_request_fingerprint('
            || 'scope::text, request_fingerprint::text) OR '
            || 'response_body IS DISTINCT FROM '
            || 'public.sanitize_idempotency_response_body('
            || 'scope::text, status::text, response_body::text)) '
            || 'ORDER BY id LIMIT $2 FOR UPDATE'
            || '), normalized AS ('
            || 'UPDATE %s AS target SET '
            || 'request_fingerprint = '
            || 'public.sanitize_idempotency_request_fingerprint('
            || 'target.scope::text, target.request_fingerprint::text), '
            || 'response_body = public.sanitize_idempotency_response_body('
            || 'target.scope::text, target.status::text, target.response_body::text) '
            || 'FROM candidates WHERE target.id = candidates.id '
            || 'RETURNING target.id'
            || ') SELECT count(*), max(id)::bigint FROM normalized',
            target_table,
            target_table
        )
        INTO updated_rows, batch_last_id
        USING last_id, batch_size;

        COMMIT;
        EXIT WHEN updated_rows = 0;
        last_id := batch_last_id;
    END LOOP;
END
$procedure$;

CREATE OR REPLACE PROCEDURE pg_temp.normalize_ops_error_phases(
    target_table regclass,
    batch_size integer
)
LANGUAGE plpgsql
AS $procedure$
DECLARE
    last_id bigint;
    batch_last_id bigint;
    updated_rows bigint;
BEGIN
    IF target_table IS NULL THEN
        RETURN;
    END IF;
    IF batch_size < 1 OR batch_size > 10000 THEN
        RAISE EXCEPTION 'privacy scrub batch size is out of range';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = target_table
          AND attname = 'error_phase'
          AND attnum > 0
          AND NOT attisdropped
    ) THEN
        RETURN;
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = target_table
          AND attname = 'id'
          AND attnum > 0
          AND NOT attisdropped
    ) THEN
        RAISE EXCEPTION 'privacy scrub requires an id column on %', target_table;
    END IF;

    LOOP
        EXECUTE format(
            'WITH candidates AS MATERIALIZED ('
            || 'SELECT id FROM %s WHERE ($1 IS NULL OR id > $1) '
            || 'AND error_phase::text IS DISTINCT FROM CASE '
            || 'WHEN lower(btrim(error_phase::text)) IN ('
            || '''request'', ''auth'', ''routing'', ''upstream'', '
            || '''network'', ''internal'') '
            || 'THEN lower(btrim(error_phase::text)) ELSE ''internal'' END '
            || 'ORDER BY id LIMIT $2 FOR UPDATE'
            || '), normalized AS ('
            || 'UPDATE %s AS target SET error_phase = CASE '
            || 'WHEN lower(btrim(target.error_phase::text)) IN ('
            || '''request'', ''auth'', ''routing'', ''upstream'', '
            || '''network'', ''internal'') '
            || 'THEN lower(btrim(target.error_phase::text)) ELSE ''internal'' END '
            || 'FROM candidates WHERE target.id = candidates.id '
            || 'RETURNING target.id'
            || ') SELECT count(*), max(id)::bigint FROM normalized',
            target_table,
            target_table
        )
        INTO updated_rows, batch_last_id
        USING last_id, batch_size;

        COMMIT;
        EXIT WHEN updated_rows = 0;
        last_id := batch_last_id;
    END LOOP;
END
$procedure$;

CREATE OR REPLACE PROCEDURE pg_temp.normalize_scheduler_outbox_payloads(
    target_table regclass,
    batch_size integer
)
LANGUAGE plpgsql
AS $procedure$
DECLARE
    last_id bigint;
    batch_last_id bigint;
    updated_rows bigint;
BEGIN
    IF target_table IS NULL THEN
        RETURN;
    END IF;
    IF batch_size < 1 OR batch_size > 10000 THEN
        RAISE EXCEPTION 'privacy scrub batch size is out of range';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = target_table
          AND attname = 'id'
          AND attnum > 0
          AND NOT attisdropped
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = target_table
          AND attname = 'event_type'
          AND attnum > 0
          AND NOT attisdropped
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_attribute
        WHERE attrelid = target_table
          AND attname = 'payload'
          AND attnum > 0
          AND NOT attisdropped
    ) THEN
        RAISE EXCEPTION
            'scheduler outbox privacy scrub requires id, event_type, and payload columns';
    END IF;

    LOOP
        EXECUTE format(
            'WITH candidates AS MATERIALIZED ('
            || 'SELECT id FROM %s WHERE ($1 IS NULL OR id > $1) '
            || 'AND payload IS DISTINCT FROM '
            || 'public.sanitize_scheduler_outbox_payload(event_type::text, payload) '
            || 'ORDER BY id LIMIT $2 FOR UPDATE'
            || '), normalized AS ('
            || 'UPDATE %s AS target SET payload = '
            || 'public.sanitize_scheduler_outbox_payload('
            || 'target.event_type::text, target.payload) '
            || 'FROM candidates WHERE target.id = candidates.id '
            || 'RETURNING target.id'
            || ') SELECT count(*), max(id)::bigint FROM normalized',
            target_table,
            target_table
        )
        INTO updated_rows, batch_last_id
        USING last_id, batch_size;

        COMMIT;
        EXIT WHEN updated_rows = 0;
        last_id := batch_last_id;
    END LOOP;
END
$procedure$;

SELECT public.assert_no_active_conversation_jobs();

CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.usage_logs'),
    public.conversation_content_policy() -> 'usage_logs',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.audit_logs'),
    public.conversation_content_policy() -> 'audit_logs',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.prompt_audit_events'),
    public.conversation_content_policy() -> 'prompt_audit_events',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.prompt_audit_jobs'),
    public.conversation_content_policy() -> 'prompt_audit_jobs',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.content_moderation_logs'),
    public.conversation_content_policy() -> 'content_moderation_logs',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.ops_error_logs'),
    public.conversation_content_policy() -> 'ops_error_logs',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.ops_retry_attempts'),
    public.conversation_content_policy() -> 'ops_retry_attempts',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.ops_job_heartbeats'),
    public.conversation_content_policy() -> 'ops_job_heartbeats',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.ops_system_logs'),
    public.conversation_content_policy() -> 'ops_system_logs',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.ops_system_log_cleanup_audits'),
    public.conversation_content_policy() -> 'ops_system_log_cleanup_audits',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.idempotency_records'),
    (public.conversation_content_policy() -> 'idempotency_records')
        - 'request_fingerprint' - 'response_body',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.deleted_api_key_audits'),
    public.conversation_content_policy() -> 'deleted_api_key_audits',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.usage_billing_dedup'),
    public.conversation_content_policy() -> 'usage_billing_dedup',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.usage_billing_dedup_archive'),
    public.conversation_content_policy() -> 'usage_billing_dedup_archive',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.auth_cache_invalidation_outbox'),
    public.conversation_content_policy() -> 'auth_cache_invalidation_outbox',
    1000
);
DO $privacy$
BEGIN
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
        EXECUTE 'DELETE FROM public.auth_cache_invalidation_outbox '
            || 'WHERE NOT public.is_safe_auth_cache_key(cache_key::text)';
    END IF;
END
$privacy$;
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.usage_cleanup_tasks'),
    public.conversation_content_policy() -> 'usage_cleanup_tasks',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.scheduled_test_results'),
    public.conversation_content_policy() -> 'scheduled_test_results',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.channel_monitor_histories'),
    public.conversation_content_policy() -> 'channel_monitor_histories',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.sora_generations'),
    public.conversation_content_policy() -> 'sora_generations',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.batch_image_jobs'),
    public.conversation_content_policy() -> 'batch_image_jobs',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.batch_image_items'),
    public.conversation_content_policy() -> 'batch_image_items',
    1000
);
CALL pg_temp.scrub_optional_content_columns(
    to_regclass('public.batch_image_events'),
    public.conversation_content_policy() -> 'batch_image_events',
    1000
);

CALL pg_temp.normalize_ops_error_phases(
    to_regclass('public.ops_error_logs'),
    1000
);
CALL pg_temp.normalize_scheduler_outbox_payloads(
    to_regclass('public.scheduler_outbox'),
    1000
);
CALL pg_temp.normalize_idempotency_records(
    to_regclass('public.idempotency_records'),
    1000
);

DO $$
BEGIN
    IF to_regclass('public.settings') IS NOT NULL THEN
        INSERT INTO public.settings (key, value, updated_at)
        VALUES
            ('risk_control_enabled', 'false', NOW()),
            ('image_storage_config', '{"enabled":false}', NOW())
        ON CONFLICT (key) DO UPDATE
        SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at
        WHERE settings.value IS DISTINCT FROM EXCLUDED.value;
    END IF;
END $$;

DROP PROCEDURE pg_temp.scrub_optional_content_columns(regclass, jsonb, integer);
DROP PROCEDURE pg_temp.normalize_ops_error_phases(regclass, integer);
DROP PROCEDURE pg_temp.normalize_scheduler_outbox_payloads(regclass, integer);
DROP PROCEDURE pg_temp.normalize_idempotency_records(regclass, integer);
