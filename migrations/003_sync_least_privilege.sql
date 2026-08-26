\set ON_ERROR_STOP on

BEGIN;

-- Apply as a database owner with enough role administration rights to revoke
-- any historical grants. The sync runtime never performs DDL.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sub2api_sync') THEN
    RAISE EXCEPTION 'create role sub2api_sync before applying this migration';
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS public.sub2api_sync_invite_owners (
  user_id bigint PRIMARY KEY REFERENCES public.users(id) ON DELETE CASCADE,
  invite_fingerprint char(64) NOT NULL UNIQUE
    CHECK (invite_fingerprint ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER ROLE sub2api_sync WITH
  LOGIN
  NOSUPERUSER
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION
  NOBYPASSRLS
  NOINHERIT;
ALTER ROLE sub2api_sync RESET ALL;

DO $$
DECLARE
  membership RECORD;
BEGIN
  FOR membership IN
    SELECT granted_role.rolname AS role_name
    FROM pg_auth_members
    JOIN pg_roles AS granted_role ON granted_role.oid = pg_auth_members.roleid
    JOIN pg_roles AS member_role ON member_role.oid = pg_auth_members.member
    WHERE member_role.rolname = 'sub2api_sync'
  LOOP
    EXECUTE format(
      'REVOKE %I FROM sub2api_sync CASCADE',
      membership.role_name
    );
  END LOOP;

  FOR membership IN
    SELECT member_role.rolname AS role_name
    FROM pg_auth_members
    JOIN pg_roles AS granted_role ON granted_role.oid = pg_auth_members.roleid
    JOIN pg_roles AS member_role ON member_role.oid = pg_auth_members.member
    WHERE granted_role.rolname = 'sub2api_sync'
  LOOP
    EXECUTE format(
      'REVOKE sub2api_sync FROM %I CASCADE',
      membership.role_name
    );
  END LOOP;
END
$$;

-- Remove every direct database grant before restoring CONNECT only on this DB.
DO $$
DECLARE
  target RECORD;
BEGIN
  FOR target IN
    SELECT database.oid, database.datname
    FROM pg_database AS database
    WHERE database.datacl IS NOT NULL
      AND EXISTS (
        SELECT 1
        FROM aclexplode(database.datacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON DATABASE %I FROM sub2api_sync CASCADE',
      target.datname
    );
  END LOOP;
END
$$;

-- Default privileges are owned by the role that created them. A migration
-- executor unable to revoke one of these grants must fail rather than leave a
-- hidden future-object grant in place.
DO $$
DECLARE
  target RECORD;
  object_kind text;
  schema_clause text;
BEGIN
  FOR target IN
    SELECT defaults.defaclobjtype,
           owner.rolname AS owner_name,
           namespace.nspname AS schema_name
    FROM pg_default_acl AS defaults
    JOIN pg_roles AS owner ON owner.oid = defaults.defaclrole
    LEFT JOIN pg_namespace AS namespace ON namespace.oid = defaults.defaclnamespace
    WHERE EXISTS (
      SELECT 1
      FROM aclexplode(defaults.defaclacl) AS acl
      WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
    )
  LOOP
    object_kind := CASE target.defaclobjtype
      WHEN 'r' THEN 'TABLES'
      WHEN 'S' THEN 'SEQUENCES'
      WHEN 'f' THEN 'FUNCTIONS'
      WHEN 'T' THEN 'TYPES'
      WHEN 'n' THEN 'SCHEMAS'
      WHEN 'L' THEN 'LARGE OBJECTS'
      ELSE NULL
    END;
    IF object_kind IS NULL THEN
      RAISE EXCEPTION 'unsupported default ACL object type: %', target.defaclobjtype;
    END IF;
    schema_clause := CASE
      WHEN target.schema_name IS NULL THEN ''
      ELSE format(' IN SCHEMA %I', target.schema_name)
    END;
    EXECUTE format(
      'ALTER DEFAULT PRIVILEGES FOR ROLE %I%s REVOKE ALL PRIVILEGES ON %s FROM sub2api_sync CASCADE',
      target.owner_name,
      schema_clause,
      object_kind
    );
  END LOOP;
END
$$;

-- Remove direct schema, relation, sequence and column grants throughout the
-- current database. Table-level REVOKE does not remove column ACLs, so those
-- are intentionally handled in a separate loop.
DO $$
DECLARE
  target RECORD;
BEGIN
  FOR target IN
    SELECT namespace.nspname
    FROM pg_namespace AS namespace
    WHERE namespace.nspacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(namespace.nspacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON SCHEMA %I FROM sub2api_sync CASCADE',
      target.nspname
    );
  END LOOP;

  FOR target IN
    SELECT namespace.nspname, relation.relname, relation.relkind
    FROM pg_class AS relation
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE relation.relacl IS NOT NULL
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
      AND EXISTS (
        SELECT 1 FROM aclexplode(relation.relacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    IF target.relkind = 'S' THEN
      EXECUTE format(
        'REVOKE ALL PRIVILEGES ON SEQUENCE %I.%I FROM sub2api_sync CASCADE',
        target.nspname,
        target.relname
      );
    ELSE
      EXECUTE format(
        'REVOKE ALL PRIVILEGES ON TABLE %I.%I FROM sub2api_sync CASCADE',
        target.nspname,
        target.relname
      );
    END IF;
  END LOOP;

  FOR target IN
    SELECT namespace.nspname, relation.relname, attribute.attname
    FROM pg_attribute AS attribute
    JOIN pg_class AS relation ON relation.oid = attribute.attrelid
    JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE attribute.attnum > 0
      AND NOT attribute.attisdropped
      AND attribute.attacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(attribute.attacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES (%I) ON TABLE %I.%I FROM sub2api_sync CASCADE',
      target.attname,
      target.nspname,
      target.relname
    );
  END LOOP;
END
$$;

-- Remove direct grants on executable and auxiliary objects as well. This
-- prevents a previously broader role from retaining a side channel after the
-- table ACLs have been narrowed.
DO $$
DECLARE
  target RECORD;
BEGIN
  FOR target IN
    SELECT namespace.nspname,
           procedure.proname,
           procedure.prokind,
           pg_get_function_identity_arguments(procedure.oid) AS arguments
    FROM pg_proc AS procedure
    JOIN pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    WHERE procedure.proacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(procedure.proacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON %s %I.%I(%s) FROM sub2api_sync CASCADE',
      CASE WHEN target.prokind = 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
      target.nspname,
      target.proname,
      target.arguments
    );
  END LOOP;

  FOR target IN
    SELECT namespace.nspname, type.typname
    FROM pg_type AS type
    JOIN pg_namespace AS namespace ON namespace.oid = type.typnamespace
    WHERE type.typacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(type.typacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON TYPE %I.%I FROM sub2api_sync CASCADE',
      target.nspname,
      target.typname
    );
  END LOOP;

  FOR target IN
    SELECT large_object.oid
    FROM pg_largeobject_metadata AS large_object
    WHERE large_object.lomacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(large_object.lomacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON LARGE OBJECT %s FROM sub2api_sync CASCADE',
      target.oid
    );
  END LOOP;

  FOR target IN
    SELECT language.lanname
    FROM pg_language AS language
    WHERE language.lanacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(language.lanacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON LANGUAGE %I FROM sub2api_sync CASCADE',
      target.lanname
    );
  END LOOP;

  FOR target IN
    SELECT wrapper.fdwname
    FROM pg_foreign_data_wrapper AS wrapper
    WHERE wrapper.fdwacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(wrapper.fdwacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON FOREIGN DATA WRAPPER %I FROM sub2api_sync CASCADE',
      target.fdwname
    );
  END LOOP;

  FOR target IN
    SELECT server.srvname
    FROM pg_foreign_server AS server
    WHERE server.srvacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(server.srvacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON FOREIGN SERVER %I FROM sub2api_sync CASCADE',
      target.srvname
    );
  END LOOP;

  FOR target IN
    SELECT tablespace.spcname
    FROM pg_tablespace AS tablespace
    WHERE tablespace.spcacl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(tablespace.spcacl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON TABLESPACE %I FROM sub2api_sync CASCADE',
      target.spcname
    );
  END LOOP;

  FOR target IN
    SELECT parameter.parname
    FROM pg_parameter_acl AS parameter
    WHERE parameter.paracl IS NOT NULL
      AND EXISTS (
        SELECT 1 FROM aclexplode(parameter.paracl) AS acl
        WHERE acl.grantee = (SELECT oid FROM pg_roles WHERE rolname = 'sub2api_sync')
      )
  LOOP
    EXECUTE format(
      'REVOKE ALL PRIVILEGES ON PARAMETER %I FROM sub2api_sync CASCADE',
      target.parname
    );
  END LOOP;
END
$$;

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'users',
    'api_keys',
    'groups',
    'subscription_plans',
    'user_allowed_groups',
    'user_subscriptions',
    'sub2api_sync_invite_owners',
    'usage_logs'
  ]
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'public'
        AND relation.relname = table_name
        AND relation.relkind IN ('r', 'p')
    ) THEN
      RAISE EXCEPTION 'required sync table missing: public.%', table_name;
    END IF;
  END LOOP;
END
$$;

DO $$
BEGIN
  EXECUTE format(
    'GRANT CONNECT ON DATABASE %I TO sub2api_sync',
    current_database()
  );
  -- TEMPORARY inherited from PUBLIC defeats per-role least privilege and can
  -- create disk-backed data outside the reviewed schema. The application role
  -- migration enforces the same database-wide baseline.
  EXECUTE format(
    'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC',
    current_database()
  );
END
$$;

GRANT USAGE ON SCHEMA public TO sub2api_sync;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.users,
  public.api_keys,
  public.user_subscriptions,
  public.sub2api_sync_invite_owners
TO sub2api_sync;

GRANT SELECT, INSERT, UPDATE ON TABLE
  public.groups,
  public.subscription_plans
TO sub2api_sync;

GRANT SELECT, INSERT, DELETE ON TABLE
  public.user_allowed_groups
TO sub2api_sync;

-- Current Sub2API releases invalidate cached API-key authorization through
-- invoker-rights triggers on users, groups, API keys, and allowed groups. The
-- sync role may enqueue the privacy-guarded SHA-256 cache reference, but it
-- must never read, update, delete, or claim queued work.
DO $$
BEGIN
  IF to_regclass('public.auth_cache_invalidation_outbox') IS NOT NULL THEN
    GRANT INSERT ON TABLE public.auth_cache_invalidation_outbox TO sub2api_sync;
  END IF;
END
$$;

-- A small core is required for stable ordering and accounting. Version-specific
-- metadata columns are granted only when present and are never replaced with a
-- table-level SELECT grant.
DO $$
DECLARE
  required_usage_columns CONSTANT text[] := ARRAY[
    'id',
    'model',
    'input_tokens',
    'output_tokens',
    'actual_cost',
    'created_at'
  ];
  allowed_usage_columns CONSTANT text[] := ARRAY[
    'id',
    'request_id',
    'model',
    'requested_model',
    'input_tokens',
    'output_tokens',
    'cache_creation_tokens',
    'cache_read_tokens',
    'total_cost',
    'actual_cost',
    'duration_ms',
    'stream',
    'request_type',
    'inbound_endpoint',
    'created_at'
  ];
  present_usage_columns text[];
  missing_usage_columns text[];
BEGIN
  SELECT array_agg(column_name ORDER BY array_position(required_usage_columns, column_name))
  INTO missing_usage_columns
  FROM unnest(required_usage_columns) AS column_name
  WHERE NOT EXISTS (
    SELECT 1
    FROM pg_attribute AS attribute
    WHERE attribute.attrelid = 'public.usage_logs'::regclass
      AND attribute.attname = column_name
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
  );

  IF cardinality(missing_usage_columns) > 0 THEN
    RAISE EXCEPTION 'required usage metadata columns missing: %', missing_usage_columns;
  END IF;

  SELECT array_agg(column_name ORDER BY array_position(allowed_usage_columns, column_name))
  INTO present_usage_columns
  FROM unnest(allowed_usage_columns) AS column_name
  WHERE EXISTS (
    SELECT 1
    FROM pg_attribute AS attribute
    WHERE attribute.attrelid = 'public.usage_logs'::regclass
      AND attribute.attname = column_name
      AND attribute.attnum > 0
      AND NOT attribute.attisdropped
  );

  EXECUTE format(
    'GRANT SELECT (%s) ON TABLE public.usage_logs TO sub2api_sync',
    (SELECT string_agg(format('%I', column_name), ',')
     FROM unnest(present_usage_columns) AS column_name)
  );
END
$$;

GRANT EXECUTE ON FUNCTION public.crypt(text, text) TO sub2api_sync;
GRANT EXECUTE ON FUNCTION public.gen_salt(text) TO sub2api_sync;

DO $$
DECLARE
  owned_sequence RECORD;
BEGIN
  FOR owned_sequence IN
    SELECT DISTINCT sequence_namespace.nspname AS schema_name,
           sequence_class.relname AS sequence_name
    FROM pg_class AS sequence_class
    JOIN pg_namespace AS sequence_namespace
      ON sequence_namespace.oid = sequence_class.relnamespace
    JOIN pg_depend AS dependency
      ON dependency.classid = 'pg_class'::regclass
     AND dependency.objid = sequence_class.oid
     AND dependency.deptype IN ('a', 'i')
    JOIN pg_class AS owner_table ON owner_table.oid = dependency.refobjid
    JOIN pg_namespace AS owner_namespace ON owner_namespace.oid = owner_table.relnamespace
    WHERE sequence_class.relkind = 'S'
      AND owner_namespace.nspname = 'public'
      AND owner_table.relname IN (
        'users',
        'api_keys',
        'groups',
        'subscription_plans',
        'user_allowed_groups',
        'user_subscriptions',
        'auth_cache_invalidation_outbox'
      )
  LOOP
    EXECUTE format(
      'GRANT USAGE, SELECT ON SEQUENCE %I.%I TO sub2api_sync',
      owned_sequence.schema_name,
      owned_sequence.sequence_name
    );
  END LOOP;
END
$$;

ALTER ROLE sub2api_sync SET statement_timeout = '10s';
ALTER ROLE sub2api_sync SET lock_timeout = '2s';
ALTER ROLE sub2api_sync SET idle_in_transaction_session_timeout = '15s';

DO $$
DECLARE
  sync_role RECORD;
  unexpected_column text;
  auth_cache_outbox_sequence text;
  expected_settings CONSTANT text[] := ARRAY[
    'idle_in_transaction_session_timeout=15s',
    'lock_timeout=2s',
    'statement_timeout=10s'
  ];
  actual_settings text[];
  allowed_usage_columns CONSTANT text[] := ARRAY[
    'id', 'request_id', 'model', 'requested_model', 'input_tokens',
    'output_tokens', 'cache_creation_tokens', 'cache_read_tokens',
    'total_cost', 'actual_cost', 'duration_ms', 'stream', 'request_type',
    'inbound_endpoint', 'created_at'
  ];
BEGIN
  SELECT * INTO STRICT sync_role
  FROM pg_roles
  WHERE rolname = 'sub2api_sync';

  IF sync_role.rolsuper
     OR sync_role.rolcreatedb
     OR sync_role.rolcreaterole
     OR sync_role.rolreplication
     OR sync_role.rolbypassrls
     OR sync_role.rolinherit
     OR NOT sync_role.rolcanlogin THEN
    RAISE EXCEPTION 'sub2api_sync retains dangerous role attributes';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_auth_members
    WHERE roleid = sync_role.oid OR member = sync_role.oid
  ) THEN
    RAISE EXCEPTION 'sub2api_sync retains role membership';
  END IF;

  SELECT array_agg(setting ORDER BY setting)
  INTO actual_settings
  FROM unnest(COALESCE(sync_role.rolconfig, ARRAY[]::text[])) AS setting;
  IF COALESCE(actual_settings, ARRAY[]::text[]) <> expected_settings THEN
    RAISE EXCEPTION 'sub2api_sync retains unexpected role settings: %', actual_settings;
  END IF;

  IF EXISTS (
    SELECT 1
    FROM pg_default_acl AS defaults,
         LATERAL aclexplode(defaults.defaclacl) AS acl
    WHERE acl.grantee = sync_role.oid
  ) THEN
    RAISE EXCEPTION 'sub2api_sync retains a default ACL grant';
  END IF;

  -- pg_shdepend covers ownership across object catalogs. ACL dependencies use
  -- a different dependency type and are intentionally not matched here.
  IF EXISTS (
    SELECT 1
    FROM pg_shdepend AS dependency
    WHERE dependency.refclassid = 'pg_authid'::regclass
      AND dependency.refobjid = sync_role.oid
      AND dependency.deptype = 'o'
      AND (
        dependency.dbid = 0
        OR dependency.dbid = (SELECT oid FROM pg_database WHERE datname = current_database())
      )
  ) THEN
    RAISE EXCEPTION 'sub2api_sync owns database objects; reassign ownership before applying grants';
  END IF;

  IF has_table_privilege('sub2api_sync', 'public.usage_logs', 'SELECT') THEN
    RAISE EXCEPTION 'sub2api_sync retains table-level SELECT on usage_logs';
  END IF;

  IF NOT has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'SELECT')
    OR NOT has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'INSERT')
    OR NOT has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'UPDATE')
    OR NOT has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'DELETE')
    OR has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'TRUNCATE')
    OR has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'REFERENCES')
    OR has_table_privilege('sub2api_sync', 'public.sub2api_sync_invite_owners', 'TRIGGER') THEN
    RAISE EXCEPTION 'sub2api_sync invite ownership privileges are unsafe';
  END IF;

  IF to_regclass('public.auth_cache_invalidation_outbox') IS NOT NULL
    AND (
      NOT has_table_privilege(
        'sub2api_sync', 'public.auth_cache_invalidation_outbox', 'INSERT'
      )
      OR has_table_privilege(
        'sub2api_sync', 'public.auth_cache_invalidation_outbox', 'SELECT'
      )
      OR has_table_privilege(
        'sub2api_sync', 'public.auth_cache_invalidation_outbox', 'UPDATE'
      )
      OR has_table_privilege(
        'sub2api_sync', 'public.auth_cache_invalidation_outbox', 'DELETE'
      )
      OR has_table_privilege(
        'sub2api_sync', 'public.auth_cache_invalidation_outbox', 'TRUNCATE'
      )
      OR has_table_privilege(
        'sub2api_sync', 'public.auth_cache_invalidation_outbox', 'REFERENCES'
      )
      OR has_table_privilege(
        'sub2api_sync', 'public.auth_cache_invalidation_outbox', 'TRIGGER'
      )
    ) THEN
    RAISE EXCEPTION 'sub2api_sync auth cache outbox privileges are unsafe';
  END IF;

  IF to_regclass('public.auth_cache_invalidation_outbox') IS NOT NULL THEN
    SELECT pg_get_serial_sequence(
      'public.auth_cache_invalidation_outbox',
      'id'
    ) INTO auth_cache_outbox_sequence;
    IF auth_cache_outbox_sequence IS NULL
      OR NOT has_sequence_privilege(
        'sub2api_sync', auth_cache_outbox_sequence, 'USAGE'
      )
      OR NOT has_sequence_privilege(
        'sub2api_sync', auth_cache_outbox_sequence, 'SELECT'
      )
      OR has_sequence_privilege(
        'sub2api_sync', auth_cache_outbox_sequence, 'UPDATE'
      ) THEN
      RAISE EXCEPTION 'sub2api_sync auth cache outbox sequence privileges are unsafe';
    END IF;
  END IF;

  SELECT attribute.attname
  INTO unexpected_column
  FROM pg_attribute AS attribute
  WHERE attribute.attrelid = 'public.usage_logs'::regclass
    AND attribute.attnum > 0
    AND NOT attribute.attisdropped
    AND NOT (attribute.attname = ANY (allowed_usage_columns))
    AND has_column_privilege(
      'sub2api_sync',
      'public.usage_logs',
      attribute.attname,
      'SELECT'
    )
  ORDER BY attribute.attnum
  LIMIT 1;
  IF unexpected_column IS NOT NULL THEN
    RAISE EXCEPTION 'unexpected readable usage_logs column: %', unexpected_column;
  END IF;
END
$$;

COMMIT;
