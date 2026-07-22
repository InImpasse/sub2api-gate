SELECT json_build_object(
    'default_group_id', (SELECT id FROM groups WHERE name = 'default' AND deleted_at IS NULL LIMIT 1),
    'target_group_id', (SELECT id FROM groups WHERE name = 'openai-default' AND deleted_at IS NULL LIMIT 1),
    'active_default_api_keys', (
        SELECT count(*) FROM api_keys key
        JOIN groups group_row ON group_row.id = key.group_id
        WHERE group_row.name = 'default' AND key.status = 'active' AND key.deleted_at IS NULL
    ),
    'active_target_api_keys', (
        SELECT count(*) FROM api_keys key
        JOIN groups group_row ON group_row.id = key.group_id
        WHERE group_row.name = 'openai-default' AND key.status = 'active' AND key.deleted_at IS NULL
    )
)::text;
