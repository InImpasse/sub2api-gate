\set ON_ERROR_STOP on

-- pg_dump can serialize foreign-server and user-mapping options, including
-- remote credentials, even for a schema-only export. Keep the portable schema
-- boundary intentionally small and fail without printing object names/options.
DO $sub2api_gate$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_extension
    WHERE extname NOT IN ('plpgsql', 'pgcrypto', 'pg_trgm')
  ) THEN
    RAISE EXCEPTION 'postgres_portability_gate_failed: unreviewed extension';
  END IF;

  IF EXISTS (SELECT 1 FROM pg_catalog.pg_foreign_data_wrapper) THEN
    RAISE EXCEPTION 'postgres_portability_gate_failed: foreign data wrapper';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_foreign_server) THEN
    RAISE EXCEPTION 'postgres_portability_gate_failed: foreign server';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_user_mapping) THEN
    RAISE EXCEPTION 'postgres_portability_gate_failed: user mapping';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_foreign_table) THEN
    RAISE EXCEPTION 'postgres_portability_gate_failed: foreign table';
  END IF;
END
$sub2api_gate$;

-- A schema-only dump still serializes column defaults. Content-bearing fields
-- are allowed to default only to canonical empty values; any other expression
-- could turn runtime content into a persistent schema literal.
DO $sub2api_schema_defaults$
DECLARE
  policy jsonb;
  target record;
  default_expression text;
BEGIN
  IF to_regprocedure('public.conversation_content_policy()') IS NULL THEN
    RETURN;
  END IF;
  policy := public.conversation_content_policy();

  FOR target IN
    SELECT definition.oid AS definition_oid,
           definition.adrelid AS relation_oid
    FROM jsonb_each(policy) AS table_policy(table_name, replacements)
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.nspname = 'public'
    JOIN pg_catalog.pg_class AS relation
      ON relation.relnamespace = namespace.oid
     AND relation.relname = table_policy.table_name
     AND relation.relkind IN ('r', 'p')
    CROSS JOIN LATERAL jsonb_each(table_policy.replacements)
      AS field_policy(column_name, replacement)
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = relation.oid
     AND attribute.attname = field_policy.column_name
     AND attribute.attnum > 0
     AND NOT attribute.attisdropped
    JOIN pg_catalog.pg_attrdef AS definition
      ON definition.adrelid = attribute.attrelid
     AND definition.adnum = attribute.attnum
  LOOP
    default_expression := pg_get_expr(
      (SELECT adbin FROM pg_catalog.pg_attrdef
       WHERE oid = target.definition_oid),
      target.relation_oid,
      true
    );
    IF default_expression IS NULL
       OR default_expression <> ALL (ARRAY[
      '''''::text',
      '''''::character varying',
      '''''::bpchar',
      '''{}''::json',
      '''[]''::json',
      '''{}''::jsonb',
      '''[]''::jsonb'
    ]) THEN
      RAISE EXCEPTION
        'postgres_portability_gate_failed: unsafe content-column default';
    END IF;
  END LOOP;
END
$sub2api_schema_defaults$;

-- CHECK constraints are also part of a schema-only dump. Only the reviewed
-- JSON container-shape checks used by prompt-audit metadata may reference a
-- content-policy column; every other such constraint is rejected.
DO $sub2api_schema_constraints$
DECLARE
  policy jsonb;
  target record;
  constrained_column text;
  constrained_type oid;
  replacement jsonb;
  expected_kind text;
  expected_definition text;
  actual_definition text;
BEGIN
  IF to_regprocedure('public.conversation_content_policy()') IS NULL THEN
    RETURN;
  END IF;
  policy := public.conversation_content_policy();

  FOR target IN
    SELECT DISTINCT constraint_record.oid AS constraint_oid,
           constraint_record.conrelid AS relation_oid,
           constraint_record.conkey AS column_numbers,
           table_policy.replacements
    FROM jsonb_each(policy) AS table_policy(table_name, replacements)
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.nspname = 'public'
    JOIN pg_catalog.pg_class AS relation
      ON relation.relnamespace = namespace.oid
     AND relation.relname = table_policy.table_name
     AND relation.relkind IN ('r', 'p')
    JOIN pg_catalog.pg_constraint AS constraint_record
      ON constraint_record.conrelid = relation.oid
     AND constraint_record.contype = 'c'
    CROSS JOIN LATERAL unnest(constraint_record.conkey)
      AS constrained_attribute(attribute_number)
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = relation.oid
     AND attribute.attnum = constrained_attribute.attribute_number
     AND NOT attribute.attisdropped
    WHERE table_policy.replacements ? attribute.attname
  LOOP
    expected_definition := NULL;
    IF cardinality(target.column_numbers) = 1 THEN
      SELECT attribute.attname, attribute.atttypid,
             target.replacements -> attribute.attname
      INTO constrained_column, constrained_type, replacement
      FROM pg_catalog.pg_attribute AS attribute
      WHERE attribute.attrelid = target.relation_oid
        AND attribute.attnum = target.column_numbers[1]
        AND NOT attribute.attisdropped;

      expected_kind := CASE replacement
        WHEN '[]'::jsonb THEN 'array'
        WHEN '{}'::jsonb THEN 'object'
        ELSE NULL
      END;
      IF expected_kind IS NOT NULL
         AND constrained_type IN (
           'pg_catalog.json'::regtype::oid,
           'pg_catalog.jsonb'::regtype::oid
         ) THEN
        expected_definition := format(
          'CHECK (%s(%I) = %L::text)',
          CASE constrained_type
            WHEN 'pg_catalog.json'::regtype::oid THEN 'json_typeof'
            ELSE 'jsonb_typeof'
          END,
          constrained_column,
          expected_kind
        );
      END IF;
    END IF;

    actual_definition := pg_get_constraintdef(target.constraint_oid, true);
    IF expected_definition IS NULL
       OR actual_definition IS DISTINCT FROM expected_definition THEN
      RAISE EXCEPTION
        'postgres_portability_gate_failed: unsafe content-column constraint';
    END IF;
  END LOOP;
END
$sub2api_schema_constraints$;
