-- Intentionally not transactional: CONCURRENTLY must run outside a transaction.
-- Apply separately after inspecting pg_stat_activity and disk headroom.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_usage_logs_created_id_desc
  ON usage_logs (created_at DESC, id DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_usage_logs_model_created_desc
  ON usage_logs (model, created_at DESC);
