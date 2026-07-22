BEGIN;

SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '5min';

CREATE TEMP TABLE group_migration_ids (
    source_id BIGINT PRIMARY KEY,
    target_id BIGINT NOT NULL
) ON COMMIT DROP;

INSERT INTO group_migration_ids (source_id, target_id)
SELECT source.id, target.id
FROM groups source
JOIN groups target ON target.name = 'openai-default' AND target.deleted_at IS NULL
WHERE source.name = 'default' AND source.deleted_at IS NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM group_migration_ids) THEN
        IF EXISTS (SELECT 1 FROM groups WHERE name = 'default' AND deleted_at IS NULL) THEN
            RAISE EXCEPTION 'openai-default group is missing';
        END IF;
        RAISE NOTICE 'default group is already absent; migration is a no-op';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM user_subscriptions source
        JOIN group_migration_ids ids ON source.group_id = ids.source_id
        JOIN user_subscriptions target
          ON target.user_id = source.user_id
         AND target.group_id = ids.target_id
        WHERE source.deleted_at IS NULL
          AND target.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'dual active user subscriptions require manual resolution';
    END IF;
END $$;

UPDATE api_keys
SET group_id = ids.target_id, updated_at = now()
FROM group_migration_ids ids
WHERE api_keys.group_id = ids.source_id;

INSERT INTO account_groups (account_id, group_id, priority, created_at)
SELECT source.account_id, ids.target_id, source.priority, source.created_at
FROM account_groups source
JOIN group_migration_ids ids ON source.group_id = ids.source_id
ON CONFLICT (account_id, group_id) DO UPDATE
SET priority = LEAST(account_groups.priority, EXCLUDED.priority);
DELETE FROM account_groups USING group_migration_ids ids
WHERE account_groups.group_id = ids.source_id;

INSERT INTO user_allowed_groups (user_id, group_id, created_at)
SELECT source.user_id, ids.target_id, source.created_at
FROM user_allowed_groups source
JOIN group_migration_ids ids ON source.group_id = ids.source_id
ON CONFLICT (user_id, group_id) DO NOTHING;
DELETE FROM user_allowed_groups USING group_migration_ids ids
WHERE user_allowed_groups.group_id = ids.source_id;

INSERT INTO user_group_rate_multipliers (user_id, group_id, rate_multiplier, created_at, updated_at)
SELECT source.user_id, ids.target_id, source.rate_multiplier, source.created_at, now()
FROM user_group_rate_multipliers source
JOIN group_migration_ids ids ON source.group_id = ids.source_id
ON CONFLICT (user_id, group_id) DO NOTHING;
DELETE FROM user_group_rate_multipliers USING group_migration_ids ids
WHERE user_group_rate_multipliers.group_id = ids.source_id;

UPDATE user_subscriptions
SET group_id = ids.target_id, updated_at = now()
FROM group_migration_ids ids
WHERE user_subscriptions.group_id = ids.source_id;

UPDATE usage_logs SET group_id = ids.target_id
FROM group_migration_ids ids WHERE usage_logs.group_id = ids.source_id;
UPDATE redeem_codes SET group_id = ids.target_id
FROM group_migration_ids ids WHERE redeem_codes.group_id = ids.source_id;
UPDATE content_moderation_logs SET group_id = ids.target_id
FROM group_migration_ids ids WHERE content_moderation_logs.group_id = ids.source_id;

UPDATE channel_groups SET group_id = ids.target_id
FROM group_migration_ids ids WHERE channel_groups.group_id = ids.source_id;

UPDATE groups SET fallback_group_id = ids.target_id
FROM group_migration_ids ids WHERE groups.fallback_group_id = ids.source_id;
UPDATE groups SET fallback_group_id_on_invalid_request = ids.target_id
FROM group_migration_ids ids WHERE groups.fallback_group_id_on_invalid_request = ids.source_id;

UPDATE subscription_plans SET group_id = ids.target_id
FROM group_migration_ids ids WHERE subscription_plans.group_id = ids.source_id;

DO $$
DECLARE
    reference RECORD;
    remaining BOOLEAN;
BEGIN
    FOR reference IN
        SELECT n.nspname AS schema_name, c.relname AS table_name, a.attname AS column_name
        FROM pg_constraint fk
        JOIN pg_class c ON c.oid = fk.conrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN LATERAL generate_subscripts(fk.confkey, 1) key_position(position) ON TRUE
        JOIN pg_attribute referenced_attribute
          ON referenced_attribute.attrelid = fk.confrelid
         AND referenced_attribute.attnum = fk.confkey[key_position.position]
         AND referenced_attribute.attname = 'id'
        JOIN pg_attribute a
          ON a.attrelid = c.oid
         AND a.attnum = fk.conkey[key_position.position]
        WHERE fk.contype = 'f'
          AND fk.confrelid = 'groups'::regclass
    LOOP
        EXECUTE format(
            'SELECT EXISTS ('
            'SELECT 1 FROM %I.%I AS referencing '
            'JOIN group_migration_ids AS ids '
            'ON referencing.%I = ids.source_id'
            ')',
            reference.schema_name,
            reference.table_name,
            reference.column_name
        ) INTO remaining;
        IF remaining THEN
            RAISE EXCEPTION 'unmigrated group reference: %.%.%',
                reference.schema_name, reference.table_name, reference.column_name;
        END IF;
    END LOOP;
END $$;

UPDATE groups
SET status = 'inactive', deleted_at = now(), updated_at = now()
FROM group_migration_ids ids
WHERE groups.id = ids.source_id;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM groups WHERE name = 'default' AND deleted_at IS NULL) THEN
        RAISE EXCEPTION 'default group remains active';
    END IF;
    IF EXISTS (
        SELECT 1 FROM api_keys key
        JOIN groups group_row ON group_row.id = key.group_id
        WHERE group_row.name = 'default' AND key.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION 'active API keys still reference default';
    END IF;
END $$;

COMMIT;
