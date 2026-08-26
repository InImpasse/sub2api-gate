\set ON_ERROR_STOP on

-- Read-only release gate for the sync runtime role. Functional status probes
-- run separately through the role itself; this query rejects privilege drift.
WITH sync_role AS (
  SELECT * FROM pg_roles WHERE rolname = 'sub2api_sync'
),
core_allowed_table_privileges(schema_name, table_name, privilege_type) AS (
  VALUES
    ('public', 'users', 'SELECT'),
    ('public', 'users', 'INSERT'),
    ('public', 'users', 'UPDATE'),
    ('public', 'users', 'DELETE'),
    ('public', 'api_keys', 'SELECT'),
    ('public', 'api_keys', 'INSERT'),
    ('public', 'api_keys', 'UPDATE'),
    ('public', 'api_keys', 'DELETE'),
    ('public', 'groups', 'SELECT'),
    ('public', 'groups', 'INSERT'),
    ('public', 'groups', 'UPDATE'),
    ('public', 'subscription_plans', 'SELECT'),
    ('public', 'subscription_plans', 'INSERT'),
    ('public', 'subscription_plans', 'UPDATE'),
    ('public', 'user_allowed_groups', 'SELECT'),
    ('public', 'user_allowed_groups', 'INSERT'),
    ('public', 'user_allowed_groups', 'DELETE'),
    ('public', 'user_subscriptions', 'SELECT'),
    ('public', 'user_subscriptions', 'INSERT'),
    ('public', 'user_subscriptions', 'UPDATE'),
    ('public', 'user_subscriptions', 'DELETE'),
    ('public', 'sub2api_sync_invite_owners', 'SELECT'),
    ('public', 'sub2api_sync_invite_owners', 'INSERT'),
    ('public', 'sub2api_sync_invite_owners', 'UPDATE'),
    ('public', 'sub2api_sync_invite_owners', 'DELETE')
),
allowed_table_privileges(schema_name, table_name, privilege_type) AS (
  SELECT * FROM core_allowed_table_privileges
  UNION ALL
  SELECT 'public', 'auth_cache_invalidation_outbox', 'INSERT'
  WHERE to_regclass('public.auth_cache_invalidation_outbox') IS NOT NULL
),
unexpected_table_privileges AS (
  SELECT privilege.table_schema, privilege.table_name, privilege.privilege_type
  FROM information_schema.role_table_grants AS privilege
  WHERE privilege.grantee = 'sub2api_sync'
  EXCEPT
  SELECT * FROM allowed_table_privileges
),
missing_table_privileges AS (
  SELECT * FROM allowed_table_privileges
  EXCEPT
  SELECT privilege.table_schema, privilege.table_name, privilege.privilege_type
  FROM information_schema.role_table_grants AS privilege
  WHERE privilege.grantee = 'sub2api_sync'
),
unexpected_usage_columns AS (
  SELECT attribute.attname
  FROM pg_attribute AS attribute
  WHERE attribute.attrelid = 'public.usage_logs'::regclass
    AND attribute.attnum > 0
    AND NOT attribute.attisdropped
    AND attribute.attname <> ALL (ARRAY[
      'id', 'request_id', 'model', 'requested_model', 'input_tokens',
      'output_tokens', 'cache_creation_tokens', 'cache_read_tokens',
      'total_cost', 'actual_cost', 'duration_ms', 'stream', 'request_type',
      'inbound_endpoint', 'created_at'
    ])
    AND has_column_privilege(
      'sub2api_sync', 'public.usage_logs', attribute.attname, 'SELECT'
    )
),
invalid_auth_cache_outbox_sequence AS (
  SELECT sequence_name
  FROM (
    SELECT pg_get_serial_sequence(
      'public.auth_cache_invalidation_outbox',
      'id'
    ) AS sequence_name
    WHERE to_regclass('public.auth_cache_invalidation_outbox') IS NOT NULL
  ) AS outbox
  WHERE sequence_name IS NULL
    OR NOT has_sequence_privilege('sub2api_sync', sequence_name, 'USAGE')
    OR NOT has_sequence_privilege('sub2api_sync', sequence_name, 'SELECT')
    OR has_sequence_privilege('sub2api_sync', sequence_name, 'UPDATE')
)
SELECT CASE WHEN
  (SELECT count(*) FROM sync_role) = 1
  AND (SELECT rolcanlogin AND NOT rolsuper AND NOT rolcreatedb
       AND NOT rolcreaterole AND NOT rolreplication AND NOT rolbypassrls
       AND NOT rolinherit FROM sync_role)
  AND (SELECT COALESCE(rolconfig, ARRAY[]::text[]) <@ ARRAY[
         'idle_in_transaction_session_timeout=15s',
         'lock_timeout=2s',
         'statement_timeout=10s'
       ] FROM sync_role)
  AND (SELECT COALESCE(rolconfig, ARRAY[]::text[]) @> ARRAY[
         'idle_in_transaction_session_timeout=15s',
         'lock_timeout=2s',
         'statement_timeout=10s'
       ] FROM sync_role)
  AND NOT EXISTS (
    SELECT 1 FROM pg_auth_members AS membership, sync_role
    WHERE membership.roleid = sync_role.oid OR membership.member = sync_role.oid
  )
  AND NOT EXISTS (SELECT 1 FROM unexpected_table_privileges)
  AND NOT EXISTS (SELECT 1 FROM missing_table_privileges)
  AND NOT EXISTS (SELECT 1 FROM unexpected_usage_columns)
  AND NOT EXISTS (SELECT 1 FROM invalid_auth_cache_outbox_sequence)
  AND NOT has_table_privilege('sub2api_sync', 'public.usage_logs', 'SELECT')
  AND NOT has_database_privilege('sub2api_sync', current_database(), 'CREATE')
  AND NOT has_database_privilege('sub2api_sync', current_database(), 'TEMPORARY')
  AND NOT EXISTS (
    SELECT 1 FROM pg_default_acl AS defaults, sync_role,
      LATERAL aclexplode(defaults.defaclacl) AS acl
    WHERE acl.grantee = sync_role.oid
  )
THEN 'ok' ELSE 'unsafe' END;
