\set ON_ERROR_STOP on

-- Owner-applied copy of Sub2API 0.1.176 backend/migrations/221_group_model_pricing.sql.
-- Additive and idempotent. The app role may apply the same statements after
-- migrations/006_allow_sub2api_schema_migrations.sql.

BEGIN;

ALTER TABLE groups
  ADD COLUMN IF NOT EXISTS long_context_pricing_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS model_pricing JSONB;

UPDATE groups
SET long_context_pricing_enabled = TRUE
WHERE long_context_pricing_enabled IS DISTINCT FROM TRUE;

COMMENT ON COLUMN groups.long_context_pricing_enabled IS
  'Whether token pricing selects official/preset long-context tiers; default true preserves existing long-context billing';
COMMENT ON COLUMN groups.model_pricing IS
  'Per-model group pricing overrides channel and built-in model pricing';

COMMIT;
