\set ON_ERROR_STOP on

-- This gate is appended to the same psql --single-transaction stream as the
-- logical restore. Any mismatch aborts and rolls back the complete target.
DO $$
DECLARE
    expected_counts jsonb;
    expected_usage jsonb;
    expected_keys text[] := ARRAY[
        'users',
        'api_keys',
        'groups',
        'user_allowed_groups',
        'user_subscriptions',
        'usage_logs'
    ];
    target RECORD;
    relationship RECORD;
    relation regclass;
    parent_relation regclass;
    expected_count bigint;
    actual_count bigint;
    has_orphan boolean;
    actual_usage jsonb;
BEGIN
    expected_counts := current_setting(
        'sub2api_gate.expected_row_counts',
        false
    )::jsonb;
    expected_usage := current_setting(
        'sub2api_gate.expected_usage_aggregate',
        false
    )::jsonb;

    IF jsonb_typeof(expected_counts) <> 'object'
       OR ARRAY(SELECT jsonb_object_keys(expected_counts) ORDER BY 1)
          IS DISTINCT FROM ARRAY(SELECT unnest(expected_keys) ORDER BY 1) THEN
        RAISE EXCEPTION 'sanitized migration row-count manifest is invalid';
    END IF;

    FOR target IN
        SELECT key AS table_name, value AS expected
        FROM jsonb_each(expected_counts)
    LOOP
        relation := to_regclass(format('public.%I', target.table_name));
        IF jsonb_typeof(target.expected) = 'null' THEN
            IF relation IS NOT NULL THEN
                RAISE EXCEPTION 'target unexpectedly contains relation %',
                    target.table_name;
            END IF;
            CONTINUE;
        END IF;
        IF jsonb_typeof(target.expected) <> 'number' OR relation IS NULL THEN
            RAISE EXCEPTION 'target relation/count mismatch for %',
                target.table_name;
        END IF;
        expected_count := (target.expected #>> '{}')::bigint;
        IF expected_count < 0 THEN
            RAISE EXCEPTION 'negative expected row count for %', target.table_name;
        END IF;
        EXECUTE format('SELECT count(*) FROM %s', relation) INTO actual_count;
        IF actual_count IS DISTINCT FROM expected_count THEN
            RAISE EXCEPTION 'target row count mismatch for %: expected %, got %',
                target.table_name, expected_count, actual_count;
        END IF;
    END LOOP;

    FOR relationship IN
        SELECT *
        FROM (VALUES
            ('api_keys', 'user_id', 'users', 'id'),
            ('api_keys', 'group_id', 'groups', 'id'),
            ('user_allowed_groups', 'user_id', 'users', 'id'),
            ('user_allowed_groups', 'group_id', 'groups', 'id'),
            ('user_subscriptions', 'user_id', 'users', 'id'),
            ('user_subscriptions', 'group_id', 'groups', 'id')
        ) AS relationships(child_table, child_column, parent_table, parent_column)
    LOOP
        relation := to_regclass(format('public.%I', relationship.child_table));
        parent_relation := to_regclass(format('public.%I', relationship.parent_table));
        IF relation IS NULL THEN
            CONTINUE;
        END IF;
        IF parent_relation IS NULL
           OR NOT EXISTS (
               SELECT 1
               FROM pg_attribute
               WHERE attrelid = relation
                 AND attname = relationship.child_column
                 AND attnum > 0
                 AND NOT attisdropped
           )
           OR NOT EXISTS (
               SELECT 1
               FROM pg_attribute
               WHERE attrelid = parent_relation
                 AND attname = relationship.parent_column
                 AND attnum > 0
                 AND NOT attisdropped
           ) THEN
            RAISE EXCEPTION 'target relationship schema is incomplete: %.% -> %.%',
                relationship.child_table,
                relationship.child_column,
                relationship.parent_table,
                relationship.parent_column;
        END IF;
        EXECUTE format(
            'SELECT EXISTS ('
            || 'SELECT 1 FROM %s AS child '
            || 'LEFT JOIN %s AS parent ON child.%I = parent.%I '
            || 'WHERE child.%I IS NOT NULL AND parent.%I IS NULL'
            || ')',
            relation,
            parent_relation,
            relationship.child_column,
            relationship.parent_column,
            relationship.child_column,
            relationship.parent_column
        ) INTO has_orphan;
        IF has_orphan THEN
            RAISE EXCEPTION 'target contains an orphan relationship: %.% -> %.%',
                relationship.child_table,
                relationship.child_column,
                relationship.parent_table,
                relationship.parent_column;
        END IF;
    END LOOP;

    relation := to_regclass('public.usage_logs');
    IF jsonb_typeof(expected_usage) = 'null' THEN
        IF relation IS NOT NULL THEN
            RAISE EXCEPTION 'target unexpectedly contains usage_logs';
        END IF;
    ELSIF jsonb_typeof(expected_usage) = 'object' AND relation IS NOT NULL THEN
        EXECUTE $query$
            SELECT jsonb_build_object(
                'rows', count(*)::text,
                'request_ids', count(request_id)::text,
                'input_tokens', COALESCE(sum(input_tokens), 0)::text,
                'output_tokens', COALESCE(sum(output_tokens), 0)::text,
                'total_cost', COALESCE(sum(total_cost), 0)::text,
                'actual_cost', COALESCE(sum(actual_cost), 0)::text
            )
            FROM public.usage_logs
        $query$ INTO actual_usage;
        IF actual_usage IS DISTINCT FROM expected_usage THEN
            RAISE EXCEPTION 'target usage metadata aggregate mismatch';
        END IF;
    ELSE
        RAISE EXCEPTION 'target usage metadata manifest/schema mismatch';
    END IF;
END
$$;
