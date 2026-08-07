-- Intentionally not transactional: CONCURRENTLY must run outside a transaction.
-- Apply separately after inspecting pg_stat_activity and disk headroom.
\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- CREATE INDEX CONCURRENTLY can leave an invalid relation after interruption.
-- IF NOT EXISTS would otherwise accept that unusable relation forever.
SELECT format(
  'DROP INDEX CONCURRENTLY %I.%I;',
  index_namespace.nspname,
  index_relation.relname
)
FROM pg_catalog.pg_index AS index_state
JOIN pg_catalog.pg_class AS index_relation
  ON index_relation.oid = index_state.indexrelid
JOIN pg_catalog.pg_namespace AS index_namespace
  ON index_namespace.oid = index_relation.relnamespace
WHERE index_namespace.nspname = 'public'
  AND index_relation.relname IN (
    'idx_usage_logs_created_id_desc',
    'idx_usage_logs_model_created_desc',
    'idx_usage_logs_metadata_search_trgm'
  )
  AND (
    NOT index_state.indisvalid
    OR NOT index_state.indisready
  )
\gexec

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_usage_logs_created_id_desc
  ON public.usage_logs (created_at DESC, id DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_usage_logs_model_created_desc
  ON public.usage_logs (model, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_usage_logs_metadata_search_trgm
  ON public.usage_logs USING gin ((
    COALESCE(request_id, '') || ' ' ||
    COALESCE(model, '') || ' ' ||
    COALESCE(requested_model, '') || ' ' ||
    COALESCE(inbound_endpoint, '')
  ) gin_trgm_ops);

DO $verify_usage_indexes$
DECLARE
  created_definition text;
  model_definition text;
  search_definition text;
BEGIN
  IF (
    SELECT count(*)
    FROM pg_catalog.pg_index AS index_state
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid = index_state.indexrelid
    JOIN pg_catalog.pg_namespace AS index_namespace
      ON index_namespace.oid = index_relation.relnamespace
    WHERE index_namespace.nspname = 'public'
      AND index_relation.relname IN (
        'idx_usage_logs_created_id_desc',
        'idx_usage_logs_model_created_desc',
        'idx_usage_logs_metadata_search_trgm'
      )
      AND index_state.indisvalid
      AND index_state.indisready
  ) <> 3 THEN
    RAISE EXCEPTION 'usage index validation failed';
  END IF;

  SELECT pg_catalog.pg_get_indexdef(to_regclass('public.idx_usage_logs_created_id_desc'))
    INTO created_definition;
  SELECT pg_catalog.pg_get_indexdef(to_regclass('public.idx_usage_logs_model_created_desc'))
    INTO model_definition;
  SELECT pg_catalog.pg_get_indexdef(to_regclass('public.idx_usage_logs_metadata_search_trgm'))
    INTO search_definition;

  IF created_definition NOT LIKE '%USING btree (created_at DESC, id DESC)%'
    OR model_definition NOT LIKE '%USING btree (model, created_at DESC)%'
    OR search_definition NOT LIKE '%USING gin%gin_trgm_ops%'
    OR search_definition NOT LIKE '%request_id%'
    OR search_definition NOT LIKE '%model%'
    OR search_definition NOT LIKE '%requested_model%'
    OR search_definition NOT LIKE '%inbound_endpoint%'
    OR search_definition ~ '(prompt|content|body|message|response)'
  THEN
    RAISE EXCEPTION 'usage index definition validation failed';
  END IF;
END
$verify_usage_indexes$;
