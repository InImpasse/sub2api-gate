#!/usr/bin/env bash
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
container_name="sub2api-gate-pg18-$$"
image="${POSTGRES_TEST_IMAGE:-postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15}"
test_password="local-integration-only"

cleanup() {
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker run --rm --detach \
  --name "$container_name" \
  --env "POSTGRES_PASSWORD=$test_password" \
  "$image" >/dev/null

attempt=0
until docker exec "$container_name" sh -c 'test "$(cat /proc/1/comm)" = postgres' >/dev/null 2>&1 \
  && docker exec "$container_name" psql -U postgres -d postgres -c 'SELECT 1' >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 30 ]; then
    echo "PostgreSQL 18 did not become ready" >&2
    exit 1
  fi
  sleep 1
done
if ! docker exec "$container_name" postgres --version | grep -Eq ' 18\.'; then
  echo "privacy integration requires PostgreSQL 18" >&2
  exit 1
fi

run_file() {
  database="$1"
  relative_path="$2"
  docker exec -i "$container_name" \
    psql -U postgres -d "$database" -v ON_ERROR_STOP=1 \
    < "$repo_dir/$relative_path"
}

# A failure inside the short guard transaction must roll back both DDL and
# trigger functions. A view deliberately makes trigger installation fail.
docker exec "$container_name" createdb -U postgres privacy_guard_rollback
docker exec -i "$container_name" psql -U postgres -d privacy_guard_rollback -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE request_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  body_text text
);
CREATE TABLE usage_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  input_tokens bigint NOT NULL,
  prompt text,
  messages jsonb
);
CREATE VIEW audit_logs AS
SELECT ''::text AS request_body, '{}'::jsonb AS extra;
INSERT INTO request_logs (body_text) VALUES ('rollback prompt');
INSERT INTO usage_logs (input_tokens, prompt, messages)
VALUES (9, 'rollback prompt', '{"role":"user"}');
SQL
if run_file privacy_guard_rollback migrations/002_remove_conversation_capture.sql \
  >/dev/null 2>&1; then
  echo "guard transaction unexpectedly succeeded in rollback scenario" >&2
  exit 1
fi
docker exec -i "$container_name" psql -U postgres -d privacy_guard_rollback -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'request_logs'
      AND column_name = 'body_text'
  ) OR NOT EXISTS (
    SELECT 1 FROM request_logs WHERE body_text = 'rollback prompt'
  ) OR NOT EXISTS (
    SELECT 1 FROM usage_logs
    WHERE input_tokens = 9
      AND prompt = 'rollback prompt'
      AND messages = '{"role":"user"}'::jsonb
  ) OR to_regprocedure('public.conversation_content_policy()') IS NOT NULL
    OR to_regprocedure('public.strip_conversation_content()') IS NOT NULL THEN
    RAISE EXCEPTION 'guard transaction rollback failed';
  END IF;
END
$$;
SQL

# Once guards commit, a later scrub failure must not remove them. The check
# constraint rejects the scrubbed value and models an unexpected schema rule.
docker exec "$container_name" createdb -U postgres privacy_scrub_failure
docker exec -i "$container_name" psql -U postgres -d privacy_scrub_failure -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE audit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_body text NOT NULL CHECK (request_body <> ''),
  extra jsonb NOT NULL DEFAULT '{}'::jsonb
);
INSERT INTO audit_logs (request_body, extra)
VALUES ('historical prompt', '{"payload":"historical prompt"}');
SQL
run_file privacy_scrub_failure migrations/002_remove_conversation_capture.sql >/dev/null
run_file privacy_scrub_failure migrations/verify_conversation_guards.sql >/dev/null
if run_file privacy_scrub_failure migrations/002_scrub_conversation_history.sql \
  >/dev/null 2>&1; then
  echo "historical scrub unexpectedly ignored a conflicting schema constraint" >&2
  exit 1
fi
docker exec -i "$container_name" psql -U postgres -d privacy_scrub_failure -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_trigger
    WHERE tgrelid = 'public.audit_logs'::regclass
      AND tgname = 'strip_conversation_content'
      AND tgenabled IN ('O', 'A')
      AND NOT tgisinternal
  ) THEN
    RAISE EXCEPTION 'guard disappeared after scrub failure';
  END IF;
  IF to_regprocedure(
    'public.scrub_optional_content_columns(regclass,jsonb)'
  ) IS NOT NULL THEN
    RAISE EXCEPTION 'scrub helper escaped its temporary session scope';
  END IF;
END
$$;
SQL
if docker exec -i "$container_name" psql -U postgres -d privacy_scrub_failure \
  -v ON_ERROR_STOP=1 -c \
  "INSERT INTO audit_logs (request_body, extra) VALUES ('new prompt', '{\"payload\":\"new prompt\"}')" \
  >/dev/null 2>&1; then
  echo "write guard allowed content after scrub failure" >&2
  exit 1
fi

# Privacy guards cannot safely strip the fields used by an in-flight image
# batch. The apply must fail before changing schema until every content job is
# terminal, rather than corrupting or silently abandoning active work.
docker exec "$container_name" createdb -U postgres privacy_active_content_job
docker exec -i "$container_name" psql -U postgres -d privacy_active_content_job -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE batch_image_jobs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  status varchar(32) NOT NULL,
  request_hash varchar(128)
);
INSERT INTO batch_image_jobs (status, request_hash)
VALUES ('running', 'derived-from-private-prompt');
SQL
if run_file privacy_active_content_job migrations/002_remove_conversation_capture.sql \
  >/dev/null 2>&1; then
  echo "privacy guard accepted an active content job" >&2
  exit 1
fi
docker exec -i "$container_name" psql -U postgres -d privacy_active_content_job -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF to_regprocedure('public.conversation_content_policy()') IS NOT NULL
    OR to_regprocedure('public.strip_conversation_content()') IS NOT NULL
    OR NOT EXISTS (
      SELECT 1 FROM batch_image_jobs
      WHERE status = 'running'
        AND request_hash = 'derived-from-private-prompt'
    ) THEN
    RAISE EXCEPTION 'active content job precheck did not roll back cleanly';
  END IF;
END
$$;
SQL

docker exec "$container_name" createdb -U postgres privacy_nonpublic_guard
docker exec -i "$container_name" psql -U postgres -d privacy_nonpublic_guard -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE request_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  body_text text
);
INSERT INTO request_logs (body_text) VALUES ('must survive rejected guard install');
CREATE SCHEMA archived_logging;
CREATE TABLE archived_logging.events (payload text);
SQL
if run_file privacy_nonpublic_guard migrations/002_remove_conversation_capture.sql \
  >/dev/null 2>&1; then
  echo "privacy guard accepted a content-capable non-public schema" >&2
  exit 1
fi
docker exec -i "$container_name" psql -U postgres -d privacy_nonpublic_guard -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF to_regprocedure('public.conversation_content_policy()') IS NOT NULL
     OR NOT EXISTS (
       SELECT 1 FROM request_logs
       WHERE body_text = 'must survive rejected guard install'
     ) THEN
    RAISE EXCEPTION 'non-public schema preflight did not roll back guard DDL';
  END IF;
END
$$;
SQL

# A locked low-ID history row must be revisited. Advancing an ID cursor past a
# SKIP LOCKED row can otherwise let the scrub return success with content left
# behind, requiring an operator rerun after the final residue gate fails.
docker exec "$container_name" createdb -U postgres privacy_locked_history
docker exec -i "$container_name" psql -U postgres -d privacy_locked_history -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE usage_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  input_tokens bigint NOT NULL,
  prompt text
);
INSERT INTO usage_logs (input_tokens, prompt)
VALUES (1, 'locked historical prompt');
SQL
run_file privacy_locked_history migrations/002_remove_conversation_capture.sql >/dev/null
run_file privacy_locked_history migrations/verify_conversation_guards.sql >/dev/null
docker exec -i "$container_name" \
  env PGAPPNAME=privacy_locked_history_holder \
  psql -U postgres -d privacy_locked_history -v ON_ERROR_STOP=1 \
  >/dev/null <<'SQL' &
BEGIN;
SELECT id FROM usage_logs WHERE id = 1 FOR UPDATE;
SELECT pg_sleep(1);
COMMIT;
SQL
locked_history_pid=$!
lock_seen=false
attempt=0
while [ "$attempt" -lt 100 ]; do
  lock_state="$(docker exec "$container_name" psql -U postgres -d privacy_locked_history -Atc \
    "SELECT state || ':' || COALESCE(wait_event, '') FROM pg_stat_activity WHERE application_name = 'privacy_locked_history_holder' LIMIT 1")"
  case "$lock_state" in
    active:PgSleep) lock_seen=true; break ;;
  esac
  attempt=$((attempt + 1))
  sleep 0.01
done
if [ "$lock_seen" != "true" ]; then
  echo "locked history fixture did not acquire its row lock" >&2
  wait "$locked_history_pid" || true
  exit 1
fi
run_file privacy_locked_history migrations/002_scrub_conversation_history.sql >/dev/null
wait "$locked_history_pid"
if ! run_file privacy_locked_history migrations/verify_no_conversation_content.sql >/dev/null; then
  echo "privacy scrub skipped a locked historical content row" >&2
  exit 1
fi

# Main fixture mirrors the conversation-capable fields in Sub2API 0.1.173,
# while retaining legacy optional capture fields for upgrade compatibility.
docker exec -i "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE TABLE request_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id text NOT NULL,
  input_tokens bigint NOT NULL,
  actual_cost numeric NOT NULL,
  request_headers jsonb,
  body_text text,
  body_preview text,
  response_preview text,
  debug_response_body text
);
CREATE TABLE audit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  actor_email varchar NOT NULL DEFAULT '',
  credential_masked varchar NOT NULL DEFAULT '',
  client_ip varchar NOT NULL DEFAULT '',
  user_agent varchar NOT NULL DEFAULT '',
  request_body text NOT NULL DEFAULT '',
  extra jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE content_moderation_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  user_email varchar NOT NULL DEFAULT '',
  api_key_name varchar NOT NULL DEFAULT '',
  group_name varchar NOT NULL DEFAULT '',
  input_excerpt text NOT NULL DEFAULT '',
  error text NOT NULL DEFAULT '',
  matched_keyword varchar NOT NULL DEFAULT '',
  category_scores jsonb NOT NULL DEFAULT '{}'::jsonb,
  threshold_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE prompt_audit_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username_snapshot varchar NOT NULL DEFAULT '',
  user_email_snapshot varchar NOT NULL DEFAULT '',
  api_key_name_snapshot varchar NOT NULL DEFAULT '',
  group_name varchar NOT NULL DEFAULT '',
  prompt_hash varchar NOT NULL DEFAULT '',
  full_prompt text NOT NULL DEFAULT '',
  redacted_preview text NOT NULL DEFAULT '',
  categories jsonb NOT NULL DEFAULT '[]'::jsonb,
  matched_scanners jsonb NOT NULL DEFAULT '[]'::jsonb,
  scanner_scores jsonb NOT NULL DEFAULT '{}'::jsonb,
  scanner_evidence jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE prompt_audit_jobs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username_snapshot varchar NOT NULL DEFAULT '',
  user_email_snapshot varchar NOT NULL DEFAULT '',
  api_key_name_snapshot varchar NOT NULL DEFAULT '',
  group_name varchar NOT NULL DEFAULT '',
  prompt_hash varchar NOT NULL DEFAULT '',
  redacted_preview text NOT NULL DEFAULT '',
  last_error_code varchar NOT NULL DEFAULT '',
  last_error_message varchar NOT NULL DEFAULT ''
);
CREATE TABLE ops_error_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  error_phase varchar(32) NOT NULL,
  error_type varchar(128) NOT NULL,
  error_source varchar(128),
  error_owner varchar(128),
  provider_error_code varchar(128),
  provider_error_type varchar(128),
  network_error_type varchar(128),
  error_message text,
  error_body text,
  upstream_error_message text,
  upstream_error_detail text,
  upstream_errors jsonb,
  user_agent text,
  attempted_key_prefix varchar,
  deleted_key_name varchar,
  api_key_prefix varchar
);
CREATE TABLE ops_retry_attempts (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  attempt integer NOT NULL,
  response_preview text NOT NULL DEFAULT '',
  error_message text NOT NULL DEFAULT ''
);
CREATE TABLE ops_job_heartbeats (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  job_name varchar NOT NULL,
  last_error text,
  last_result text
);
-- PostgreSQL json (not jsonb) ensures the scrub does not rely on json equality.
CREATE TABLE ops_system_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  message text NOT NULL,
  extra json NOT NULL DEFAULT '{}'::json
);
CREATE TABLE ops_system_log_cleanup_audits (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  conditions jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE idempotency_records (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scope varchar(128) NOT NULL,
  idempotency_key_hash varchar(64) NOT NULL,
  request_fingerprint varchar(64) NOT NULL,
  status varchar(32) NOT NULL,
  response_body text,
  error_reason varchar(128),
  locked_until timestamptz,
  expires_at timestamptz NOT NULL DEFAULT now() + interval '1 hour',
  UNIQUE (scope, idempotency_key_hash)
);
CREATE TABLE deleted_api_key_audits (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  key varchar(128) NOT NULL,
  key_name varchar(100) NOT NULL DEFAULT '',
  api_key_id bigint NOT NULL,
  user_id bigint NOT NULL
);
CREATE TABLE usage_billing_dedup (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  request_id varchar(255) NOT NULL,
  api_key_id bigint NOT NULL,
  request_fingerprint varchar(64) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (request_id, api_key_id)
);
-- The real archive has no synthetic id; this exercises bounded ctid batches.
CREATE TABLE usage_billing_dedup_archive (
  request_id varchar(255) NOT NULL,
  api_key_id bigint NOT NULL,
  request_fingerprint varchar(64) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  archived_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (request_id, api_key_id)
);
CREATE TABLE auth_cache_invalidation_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  cache_key char(64) NOT NULL CHECK (cache_key ~ '^[0-9a-f]{64}$'),
  last_error text
);
CREATE TABLE usage_cleanup_tasks (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  filters jsonb NOT NULL DEFAULT '{}'::jsonb,
  error_message text
);
CREATE TABLE scheduled_test_results (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  status varchar NOT NULL,
  response_text text NOT NULL DEFAULT '',
  error_message text NOT NULL DEFAULT '',
  latency_ms bigint NOT NULL DEFAULT 0
);
CREATE TABLE channel_monitor_histories (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  status varchar NOT NULL,
  latency_ms integer,
  message varchar(500) NOT NULL DEFAULT ''
);
CREATE TABLE sora_generations (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  status varchar(16) NOT NULL,
  model varchar(64) NOT NULL,
  prompt text NOT NULL DEFAULT '',
  media_url text NOT NULL DEFAULT '',
  media_urls jsonb,
  s3_object_keys jsonb,
  upstream_task_id varchar(128) NOT NULL DEFAULT '',
  error_message text NOT NULL DEFAULT ''
);
CREATE TABLE batch_image_jobs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  status varchar(32) NOT NULL,
  provider varchar(32) NOT NULL,
  provider_job_name varchar(512),
  task_name varchar(255) NOT NULL DEFAULT '',
  provider_input_ref varchar(1024),
  provider_output_ref varchar(1024),
  gcs_input_uri varchar(1024),
  gcs_output_uri varchar(1024),
  request_hash varchar(128),
  manifest_hash varchar(128),
  idempotency_key varchar(255),
  last_error_code varchar(128),
  last_error_message text,
  session_id varchar(255)
);
CREATE TABLE batch_image_items (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  custom_id varchar(255) NOT NULL,
  request_hash varchar(128),
  prompt_preview text,
  provider_source_object varchar(1024),
  error_code varchar(128),
  error_message text
);
CREATE TABLE batch_image_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_type varchar(64) NOT NULL,
  payload jsonb,
  event_hash varchar(128)
);
CREATE TABLE scheduler_outbox (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_type text NOT NULL,
  account_id bigint,
  group_id bigint,
  payload jsonb,
  dedup_key text
);
CREATE TABLE payment_audit_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  detail text NOT NULL DEFAULT ''
);
CREATE TABLE settings (
  key text PRIMARY KEY,
  value text NOT NULL,
  updated_at timestamptz NOT NULL
);
CREATE TABLE usage_logs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  input_tokens bigint NOT NULL,
  prompt_tokens bigint NOT NULL,
  output_tokens bigint NOT NULL,
  actual_cost numeric NOT NULL,
  model text NOT NULL,
  duration_ms bigint NOT NULL,
  prompt text,
  messages jsonb,
  image_size_breakdown jsonb,
  user_agent varchar,
  ip_address varchar,
  session_id varchar(255)
);

INSERT INTO request_logs (
  request_id, input_tokens, actual_cost, request_headers, body_text,
  body_preview, response_preview, debug_response_body
) VALUES ('req-test', 9, 0.1, '{"authorization":"test"}', 'prompt', 'prompt', 'answer', 'answer');
INSERT INTO audit_logs (
  actor_email, credential_masked, client_ip, user_agent, request_body, extra
) VALUES (
  'private@example.test', 'sk-pri***vate', '192.0.2.10',
  'conversation in user agent', 'prompt', '{"payload":"prompt"}'
);
INSERT INTO content_moderation_logs (
  user_email, api_key_name, group_name, input_excerpt, error, matched_keyword,
  category_scores, threshold_snapshot
) VALUES (
  'private@example.test', 'private key label', 'private group label',
  'prompt', 'detail', 'private phrase', '{"violence":0.8}', '{"violence":0.5}'
);
INSERT INTO prompt_audit_events (
  username_snapshot, user_email_snapshot, api_key_name_snapshot, group_name,
  prompt_hash, full_prompt, redacted_preview, categories,
  matched_scanners, scanner_scores, scanner_evidence
) VALUES (
  'private username', 'private@example.test', 'private key label',
  'private group label',
  'derived-prompt-hash', 'prompt', 'preview', '["private-category"]',
  '["scanner"]', '{"private":0.9}', '{"evidence":"prompt"}'
);
INSERT INTO prompt_audit_jobs (
  username_snapshot, user_email_snapshot, api_key_name_snapshot, group_name,
  prompt_hash, redacted_preview, last_error_code, last_error_message
) VALUES (
  'private username', 'private@example.test', 'private key label',
  'private group label', 'derived-job-hash', 'preview', 'stable_code', 'detail'
);
INSERT INTO ops_error_logs (
  error_phase, error_type, error_source, error_owner, provider_error_code,
  provider_error_type, network_error_type, error_message, error_body,
  upstream_error_message, upstream_error_detail, upstream_errors,
  user_agent, attempted_key_prefix, deleted_key_name, api_key_prefix
) VALUES (
  'free-form user fragment', 'prompt fragment', 'request body fragment',
  'response fragment', 'provider body fragment', 'upstream detail fragment',
  'network detail fragment', 'detail', 'answer', 'detail', 'detail',
  '[{"body":"answer"}]', 'conversation in user agent', 'sk-private',
  'private key label', 'sk-secret-prefix'
);
INSERT INTO ops_retry_attempts (attempt, response_preview, error_message)
VALUES (1, 'answer preview', 'private error detail');
INSERT INTO ops_job_heartbeats (job_name, last_error, last_result)
VALUES ('cleanup', 'private error detail', 'response preview detail');
INSERT INTO ops_system_logs (message, extra)
VALUES ('detail', '{"payload":"prompt"}');
INSERT INTO ops_system_log_cleanup_audits (conditions)
VALUES ('{"query":"prompt fragment"}');
INSERT INTO idempotency_records (
  scope, idempotency_key_hash, request_fingerprint,
  status, response_body, error_reason
) VALUES
  ('admin.accounts.create', 'key-hash-1', 'private-request-body-hash',
   'succeeded', '{"credential":"private"}', 'prompt fragment'),
  ('admin.system.operations.global_lock', 'key-hash-2', 'sysop-a1b2c3',
   'processing', NULL,
   'private error'),
  ('admin.system.operations.global_lock', 'key-hash-3', 'private prompt',
   'succeeded', '{"operation_id":"private prompt","released":true}',
   'private error');
INSERT INTO deleted_api_key_audits (key, key_name, api_key_id, user_id)
VALUES ('sk-plaintext-deleted-secret', 'private key label', 42, 7);
INSERT INTO usage_billing_dedup (
  request_id, api_key_id, request_fingerprint
) VALUES
  ('usage-request-1', 10, 'chat-body-derived-hash'),
  ('usage-request-2', 10, 'responses-body-derived-hash');
INSERT INTO usage_billing_dedup_archive (
  request_id, api_key_id, request_fingerprint
) VALUES ('usage-request-old', 10, 'image-body-derived-hash');
INSERT INTO auth_cache_invalidation_outbox (cache_key, last_error)
VALUES (repeat('a', 64), 'private Redis error detail');
INSERT INTO usage_cleanup_tasks (filters, error_message)
VALUES ('{"model":"safe-model-metadata"}', 'private cleanup error detail');
INSERT INTO scheduled_test_results (status, response_text, error_message, latency_ms)
VALUES ('failed', 'synthetic response body', 'synthetic private error', 125);
INSERT INTO channel_monitor_histories (status, latency_ms, message)
VALUES ('failed', 140, 'upstream response detail');
INSERT INTO sora_generations (
  status, model, prompt, media_url, media_urls, s3_object_keys,
  upstream_task_id, error_message
) VALUES (
  'completed', 'sora-model', 'private video prompt',
  'https://content.example/private-video',
  '["https://content.example/private-image"]', '["private/object/key"]',
  'provider-task-safe-id', 'private provider error'
);
INSERT INTO batch_image_jobs (
  status, provider, provider_job_name, task_name,
  provider_input_ref, provider_output_ref, gcs_input_uri, gcs_output_uri,
  request_hash, manifest_hash, idempotency_key,
  last_error_code, last_error_message, session_id
) VALUES (
  'completed', 'vertex', 'provider-task-safe-id', 'private task label',
  'private/input/object', 'private/output/object',
  'gs://private/input', 'gs://private/output',
  'private-request-hash', 'private-manifest-hash', 'private-idempotency-key',
  'STABLE_CODE', 'private batch error', 'private-session-reference'
);
INSERT INTO batch_image_items (
  custom_id, request_hash, prompt_preview, provider_source_object,
  error_code, error_message
) VALUES (
  'request-item-safe-id', 'private-item-request-hash', 'private prompt preview',
  'private/source/object', 'STABLE_ITEM_CODE', 'private item error'
);
INSERT INTO batch_image_events (event_type, payload, event_hash)
VALUES ('provider_completed', '{"response":"private image output"}', 'private-event-hash');
INSERT INTO scheduler_outbox (event_type, account_id, payload, dedup_key)
VALUES
  ('account_changed', 1,
   '{"group_ids":[1,2,"private"],"prompt":"private prompt"}',
   'safe-dedup-1'),
  ('account_bulk_changed', NULL,
   '{"account_ids":[3,"private"],"group_ids":[4],"body":"private body"}',
   'safe-dedup-2'),
  ('account_last_used', 5,
   '{"last_used":{"5":1700000000,"bad":"private","6":"private"},"response":"private"}',
   'safe-dedup-3'),
  ('future_unknown_event', NULL, '{"payload":"private"}', 'safe-dedup-4');
INSERT INTO payment_audit_logs (detail)
VALUES ('financial reconciliation metadata');
INSERT INTO settings (key, value, updated_at)
VALUES
  ('risk_control_enabled', 'true', now()),
  ('image_storage_config',
   '{"enabled":true,"bucket":"private-bucket","access_key_id":"private-access","secret_access_key":"private-secret"}',
   now());
INSERT INTO usage_logs (
  input_tokens, prompt_tokens, output_tokens, actual_cost, model, duration_ms,
  prompt, messages, image_size_breakdown, user_agent, ip_address, session_id
) VALUES (
  9, 9, 4, 0.1, 'model-test', 120, 'prompt', '[{"role":"user"}]',
  '{"private-size-detail":"1024x1024"}', 'conversation in user agent',
  '192.0.2.20', 'private-usage-session-reference'
);
INSERT INTO usage_logs (
  input_tokens, prompt_tokens, output_tokens, actual_cost, model, duration_ms,
  prompt, messages, image_size_breakdown
)
SELECT
  7, 7, 3, 0.07, 'bulk-' || sequence, 100,
  'bulk prompt', '[{"role":"user"}]'::jsonb, '{"private":"size"}'::jsonb
FROM generate_series(1, 2505) AS sequence;
SQL

run_file postgres migrations/002_remove_conversation_capture.sql >/dev/null
run_file postgres migrations/verify_conversation_guards.sql >/dev/null

# A request that lands after the guard commit but before historical scrubbing
# must be stripped immediately. Existing history should still be present here.
docker exec -i "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO usage_logs (
  input_tokens, prompt_tokens, output_tokens, actual_cost, model, duration_ms,
  prompt, messages, image_size_breakdown, session_id
) VALUES (
  3, 3, 2, 0.03, 'guard-gap', 80, 'new prompt',
  '[{"role":"user"}]', '{"private":"size"}', 'new-usage-session-reference'
);
INSERT INTO prompt_audit_events (
  prompt_hash, full_prompt, redacted_preview, categories,
  matched_scanners, scanner_scores, scanner_evidence
) VALUES (
  'new-derived-hash', 'new prompt', 'new preview', '["private"]',
  '["scanner"]', '{"private":1}', '{"evidence":"new prompt"}'
);
INSERT INTO ops_retry_attempts (attempt, response_preview, error_message)
VALUES (2, 'new answer preview', 'new private error');
INSERT INTO scheduled_test_results (status, response_text, error_message, latency_ms)
VALUES ('failed', 'new synthetic response', 'new synthetic error', 90);
INSERT INTO channel_monitor_histories (status, latency_ms, message)
VALUES ('failed', 95, 'new monitor response detail');
INSERT INTO batch_image_jobs (
  status, provider, provider_job_name, task_name,
  provider_input_ref, provider_output_ref, gcs_input_uri, gcs_output_uri,
  request_hash, manifest_hash, last_error_code, last_error_message, session_id
) VALUES (
  'failed', 'vertex', 'provider-task-new-safe-id', 'new private task label',
  'new private input', 'new private output', 'gs://new/private-input',
  'gs://new/private-output', 'new-private-request-hash',
  'new-private-manifest-hash', 'STABLE_NEW_CODE', 'new private error',
  'new-private-session-reference'
);
INSERT INTO batch_image_items (
  custom_id, request_hash, prompt_preview, provider_source_object,
  error_code, error_message
) VALUES (
  'new-request-item-safe-id', 'new-private-item-hash', 'new private prompt',
  'new/private/source', 'STABLE_NEW_ITEM_CODE', 'new private item error'
);
INSERT INTO batch_image_events (event_type, payload, event_hash)
VALUES ('new_event', '{"response":"new private response"}', 'new-private-event-hash');
INSERT INTO scheduler_outbox (event_type, account_id, payload, dedup_key)
VALUES (
  'account_changed', 7,
  '{"group_ids":[8,"private"],"prompt":"new private prompt"}',
  'safe-dedup-new'
);
UPDATE settings
SET value = 'true'
WHERE key = 'risk_control_enabled';
UPDATE settings
SET value = '{"enabled":true,"secret_access_key":"new-private-secret"}'
WHERE key = 'image_storage_config';
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM audit_logs WHERE request_body = 'prompt'
  ) OR NOT EXISTS (
    SELECT 1 FROM usage_logs
    WHERE model = 'guard-gap'
      AND prompt IS NULL
      AND messages IS NULL
      AND image_size_breakdown IS NULL
  ) OR NOT EXISTS (
    SELECT 1 FROM prompt_audit_events
    WHERE id = 2 AND prompt_hash = '' AND full_prompt = ''
      AND redacted_preview = '' AND categories = '[]'::jsonb
      AND matched_scanners = '[]'::jsonb
      AND scanner_scores = '{}'::jsonb
      AND scanner_evidence = '{}'::jsonb
  ) OR NOT EXISTS (
    SELECT 1 FROM ops_retry_attempts
    WHERE id = 2 AND response_preview = '' AND error_message = ''
  ) OR NOT EXISTS (
    SELECT 1 FROM scheduled_test_results
    WHERE id = 2 AND response_text = '' AND error_message = ''
      AND status = 'failed' AND latency_ms = 90
  ) OR NOT EXISTS (
    SELECT 1 FROM channel_monitor_histories
    WHERE id = 2 AND message = '' AND status = 'failed' AND latency_ms = 95
  ) OR NOT EXISTS (
    SELECT 1 FROM batch_image_jobs
    WHERE id = 2 AND status = 'failed'
      AND provider = 'vertex'
      AND provider_job_name = 'provider-task-new-safe-id'
      AND task_name = ''
      AND provider_input_ref IS NULL AND provider_output_ref IS NULL
      AND gcs_input_uri IS NULL AND gcs_output_uri IS NULL
      AND request_hash IS NULL AND manifest_hash IS NULL
      AND last_error_code = 'STABLE_NEW_CODE'
      AND last_error_message IS NULL AND session_id IS NULL
  ) OR NOT EXISTS (
    SELECT 1 FROM batch_image_items
    WHERE id = 2 AND custom_id = 'new-request-item-safe-id'
      AND request_hash IS NULL AND prompt_preview IS NULL
      AND provider_source_object IS NULL
      AND error_code = 'STABLE_NEW_ITEM_CODE'
      AND error_message IS NULL
  ) OR NOT EXISTS (
    SELECT 1 FROM batch_image_events
    WHERE id = 2 AND payload IS NULL AND event_hash IS NULL
  ) OR NOT EXISTS (
    SELECT 1 FROM scheduler_outbox
    WHERE id = 5 AND payload = '{"group_ids":[8]}'::jsonb
  ) OR NOT EXISTS (
    SELECT 1 FROM settings
    WHERE key = 'risk_control_enabled' AND value = 'false'
  ) OR NOT EXISTS (
    SELECT 1 FROM settings
    WHERE key = 'image_storage_config'
      AND value::jsonb = '{"enabled":false}'::jsonb
  ) THEN
    RAISE EXCEPTION 'write guard did not commit before historical scrub';
  END IF;
END
$$;
SQL

if docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "DELETE FROM settings WHERE key = 'image_storage_config'" \
  >/dev/null 2>&1; then
  echo "privacy settings trigger allowed protected setting deletion" >&2
  exit 1
fi
if docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "UPDATE settings SET key = 'image_storage_config_old' WHERE key = 'image_storage_config'" \
  >/dev/null 2>&1; then
  echo "privacy settings trigger allowed protected setting rename" >&2
  exit 1
fi

if docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "INSERT INTO batch_image_jobs (status, provider) VALUES ('running', 'vertex')" \
  >/dev/null 2>&1; then
  echo "privacy trigger accepted a new active content job" >&2
  exit 1
fi

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs DISABLE TRIGGER strip_conversation_content;'
if run_file postgres migrations/verify_conversation_guards.sql >/dev/null 2>&1; then
  echo "guard gate accepted a disabled trigger" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs ENABLE TRIGGER strip_conversation_content;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE settings DISABLE TRIGGER enforce_privacy_safe_settings;'
if run_file postgres migrations/verify_conversation_guards.sql >/dev/null 2>&1; then
  echo "guard gate accepted a disabled privacy settings trigger" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE settings ENABLE TRIGGER enforce_privacy_safe_settings;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs ADD COLUMN future_payload text;'
if run_file postgres migrations/verify_conversation_guards.sql >/dev/null 2>&1; then
  echo "guard gate accepted an unreviewed content-capable schema field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs DROP COLUMN future_payload;'

# Keep a writer active while the batched scrub runs. Its transaction commits
# after the scrub may already have passed usage_logs, so only the previously
# committed trigger can guarantee that these late rows are clean.
docker exec -i "$container_name" \
  env PGAPPNAME=privacy_concurrent_writer \
  psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL' &
DO $$
BEGIN
  FOR sequence IN 1..250 LOOP
    INSERT INTO usage_logs (
      input_tokens, prompt_tokens, output_tokens, actual_cost, model,
      duration_ms, prompt, messages, image_size_breakdown
    ) VALUES (
      1, 1, 1, 0.01, 'concurrent-' || sequence, 25,
      'concurrent private prompt',
      '[{"role":"user","content":"concurrent private prompt"}]',
      '{"private":"concurrent image detail"}'
    );
    PERFORM pg_sleep(0.004);
  END LOOP;
END
$$;
SQL
concurrent_writer_pid=$!

writer_seen=false
attempt=0
while [ "$attempt" -lt 100 ]; do
  writer_state="$(docker exec "$container_name" psql -U postgres -d postgres -Atc \
    "SELECT state FROM pg_stat_activity WHERE application_name = 'privacy_concurrent_writer' LIMIT 1")"
  if [ "$writer_state" = "active" ]; then
    writer_seen=true
    break
  fi
  attempt=$((attempt + 1))
  sleep 0.01
done
if [ "$writer_seen" != "true" ]; then
  echo "concurrent privacy writer did not become active" >&2
  wait "$concurrent_writer_pid" || true
  exit 1
fi

run_file postgres migrations/002_scrub_conversation_history.sql >/dev/null
wait "$concurrent_writer_pid"
if ! run_file postgres migrations/verify_no_conversation_content.sql >/dev/null; then
  docker exec "$container_name" psql -U postgres -d postgres -P pager=off \
    -c "SELECT id, model, prompt IS NULL AS prompt_cleared, messages IS NULL AS messages_cleared FROM usage_logs ORDER BY id;" >&2
  exit 1
fi

docker exec -i "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM request_logs
    WHERE request_id = 'req-test' AND input_tokens = 9 AND actual_cost = 0.1
  ) OR NOT EXISTS (
    SELECT 1 FROM usage_logs
    WHERE input_tokens = 9 AND prompt_tokens = 9
      AND output_tokens = 4 AND actual_cost = 0.1
  ) OR (SELECT count(*) FROM usage_logs WHERE model LIKE 'bulk-%') <> 2505
    OR EXISTS (
      SELECT 1 FROM usage_logs
      WHERE model LIKE 'bulk-%'
        AND (input_tokens <> 7 OR output_tokens <> 3 OR actual_cost <> 0.07)
  ) THEN
    RAISE EXCEPTION 'usage metadata was altered';
  END IF;
  IF EXISTS (
    SELECT 1 FROM usage_logs
    WHERE prompt IS NOT NULL OR messages IS NOT NULL
      OR image_size_breakdown IS NOT NULL OR session_id IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'usage content history was not scrubbed';
  END IF;
  IF (SELECT count(*) FROM usage_logs WHERE model LIKE 'concurrent-%') <> 250 THEN
    RAISE EXCEPTION 'concurrent writer did not overlap the privacy scrub';
  END IF;
  IF EXISTS (
    SELECT 1 FROM prompt_audit_events
    WHERE prompt_hash <> '' OR full_prompt <> '' OR redacted_preview <> ''
      OR categories <> '[]'::jsonb OR matched_scanners <> '[]'::jsonb
      OR scanner_scores <> '{}'::jsonb OR scanner_evidence <> '{}'::jsonb
  ) OR EXISTS (
    SELECT 1 FROM prompt_audit_jobs
    WHERE prompt_hash <> '' OR redacted_preview <> '' OR last_error_message <> ''
  ) THEN
    RAISE EXCEPTION 'Sub2API 0.1.173 prompt audit content was not scrubbed';
  END IF;
  IF (SELECT last_error_code FROM prompt_audit_jobs WHERE id = 1) <> 'stable_code' THEN
    RAISE EXCEPTION 'stable prompt audit error code was altered';
  END IF;
  IF EXISTS (
    SELECT 1 FROM ops_retry_attempts
    WHERE response_preview <> '' OR error_message <> ''
  ) THEN
    RAISE EXCEPTION 'retry preview history was not scrubbed';
  END IF;
  IF EXISTS (
    SELECT 1 FROM ops_job_heartbeats
    WHERE last_error IS NOT NULL OR last_result IS NOT NULL
  ) OR EXISTS (
    SELECT 1 FROM auth_cache_invalidation_outbox
    WHERE last_error IS NOT NULL
       OR cache_key <> repeat('a', 64)
  ) OR EXISTS (
    SELECT 1 FROM usage_cleanup_tasks
    WHERE error_message IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'background operational error history was not scrubbed';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM usage_cleanup_tasks
    WHERE filters = '{"model":"safe-model-metadata"}'::jsonb
  ) THEN
    RAISE EXCEPTION 'reviewed usage cleanup metadata was altered';
  END IF;
  IF EXISTS (
    SELECT 1 FROM scheduled_test_results
    WHERE response_text <> '' OR error_message <> ''
  ) OR EXISTS (
    SELECT 1 FROM channel_monitor_histories
    WHERE message <> ''
  ) THEN
    RAISE EXCEPTION 'synthetic response or monitor message history was not scrubbed';
  END IF;
  IF EXISTS (
    SELECT 1 FROM sora_generations
    WHERE prompt <> '' OR media_url <> '' OR media_urls IS NOT NULL
      OR s3_object_keys IS NOT NULL OR error_message <> ''
  ) OR NOT EXISTS (
    SELECT 1 FROM sora_generations
    WHERE model = 'sora-model' AND status = 'completed'
      AND upstream_task_id = 'provider-task-safe-id'
  ) THEN
    RAISE EXCEPTION 'legacy Sora content history was not safely scrubbed';
  END IF;
  IF EXISTS (
    SELECT 1 FROM batch_image_jobs
    WHERE task_name <> '' OR provider_input_ref IS NOT NULL
      OR provider_output_ref IS NOT NULL OR gcs_input_uri IS NOT NULL
      OR gcs_output_uri IS NOT NULL OR request_hash IS NOT NULL
      OR manifest_hash IS NOT NULL OR last_error_message IS NOT NULL
      OR session_id IS NOT NULL
  ) OR EXISTS (
    SELECT 1 FROM batch_image_items
    WHERE request_hash IS NOT NULL OR prompt_preview IS NOT NULL
      OR provider_source_object IS NOT NULL OR error_message IS NOT NULL
  ) OR EXISTS (
    SELECT 1 FROM batch_image_events
    WHERE payload IS NOT NULL OR event_hash IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'batch image content history was not scrubbed';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM batch_image_jobs
    WHERE id = 1 AND provider_job_name = 'provider-task-safe-id'
      AND last_error_code = 'STABLE_CODE'
  ) OR NOT EXISTS (
    SELECT 1 FROM batch_image_items
    WHERE id = 1 AND custom_id = 'request-item-safe-id'
      AND error_code = 'STABLE_ITEM_CODE'
  ) THEN
    RAISE EXCEPTION 'reviewed batch image metadata was altered';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM scheduler_outbox
    WHERE id = 1 AND payload = '{"group_ids":[1,2]}'::jsonb
  ) OR NOT EXISTS (
    SELECT 1 FROM scheduler_outbox
    WHERE id = 2
      AND payload = '{"account_ids":[3],"group_ids":[4]}'::jsonb
  ) OR NOT EXISTS (
    SELECT 1 FROM scheduler_outbox
    WHERE id = 3 AND payload = '{"last_used":{"5":1700000000}}'::jsonb
  ) OR NOT EXISTS (
    SELECT 1 FROM scheduler_outbox WHERE id = 4 AND payload IS NULL
  ) OR EXISTS (
    SELECT 1 FROM scheduler_outbox
    WHERE payload::text ~ '(private|prompt|body|response)'
  ) THEN
    RAISE EXCEPTION 'scheduler outbox payload was not reduced to safe metadata';
  END IF;
  IF (SELECT error_phase FROM ops_error_logs WHERE id = 1) <> 'internal' THEN
    RAISE EXCEPTION 'historical free-form error phase was not normalized';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM idempotency_records
    WHERE id = 1 AND request_fingerprint = ''
      AND response_body IS NULL AND error_reason = ''
  ) OR NOT EXISTS (
    SELECT 1 FROM idempotency_records
    WHERE id = 2
      AND request_fingerprint = 'sysop-a1b2c3'
      AND response_body IS NULL AND error_reason = ''
      AND status = 'processing'
  ) OR NOT EXISTS (
    SELECT 1 FROM idempotency_records
    WHERE id = 3 AND request_fingerprint = ''
      AND response_body IS NULL AND error_reason = ''
  ) THEN
    RAISE EXCEPTION 'idempotency request data was not reduced to the global-lock exception';
  END IF;
  IF public.sanitize_idempotency_response_body(
       NULL, 'succeeded',
       '{"operation_id":"sysop-null-scope","released":true}'
     ) IS NOT NULL
     OR public.sanitize_idempotency_response_body(
       'admin.system.operations.global_lock', NULL,
       '{"operation_id":"sysop-null-status","released":true}'
     ) IS NOT NULL THEN
    RAISE EXCEPTION 'NULL idempotency identity bypassed response sanitization';
  END IF;
  IF (SELECT count(*) FROM usage_billing_dedup) <> 2
     OR EXISTS (
       SELECT 1 FROM usage_billing_dedup WHERE request_fingerprint <> ''
     ) OR NOT EXISTS (
       SELECT 1 FROM usage_billing_dedup
       WHERE request_id = 'usage-request-1' AND api_key_id = 10
     ) OR NOT EXISTS (
       SELECT 1 FROM usage_billing_dedup
       WHERE request_id = 'usage-request-2' AND api_key_id = 10
     ) OR NOT EXISTS (
       SELECT 1 FROM usage_billing_dedup_archive
       WHERE request_id = 'usage-request-old' AND api_key_id = 10
         AND request_fingerprint = ''
     ) THEN
    RAISE EXCEPTION 'usage billing dedup metadata was not safely retained';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM payment_audit_logs
    WHERE detail = 'financial reconciliation metadata'
  ) THEN
    RAISE EXCEPTION 'financial audit metadata exception was altered';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM settings
    WHERE key = 'risk_control_enabled' AND value = 'false'
  ) OR NOT EXISTS (
    SELECT 1 FROM settings
    WHERE key = 'image_storage_config'
      AND value::jsonb = '{"enabled":false}'::jsonb
  ) THEN
    RAISE EXCEPTION 'privacy-sensitive settings were not reduced to safe values';
  END IF;
END
$$;

-- Exercise the exact ownership predicate used by Sub2API's global operation
-- lock, then its successful release response. The trigger must preserve only
-- the operation ID needed for renewal and the bounded release acknowledgement.
DO $$
DECLARE
  affected bigint;
BEGIN
  UPDATE idempotency_records
  SET locked_until = now() + interval '30 seconds',
      expires_at = now() + interval '1 hour'
  WHERE id = 2
    AND status = 'processing'
    AND request_fingerprint = 'sysop-a1b2c3';
  GET DIAGNOSTICS affected = ROW_COUNT;
  IF affected <> 1 THEN
    RAISE EXCEPTION 'global operation lock renewal lost its ownership fingerprint';
  END IF;

  UPDATE idempotency_records
  SET status = 'succeeded',
      response_body = '{"operation_id":"sysop-a1b2c3","released":true,"detail":"private"}',
      error_reason = 'private release detail'
  WHERE id = 2;
  IF NOT EXISTS (
    SELECT 1 FROM idempotency_records
    WHERE id = 2 AND status = 'succeeded'
      AND request_fingerprint = 'sysop-a1b2c3'
      AND response_body::jsonb = '{"operation_id":"sysop-a1b2c3","released":true}'::jsonb
      AND error_reason = ''
  ) THEN
    RAISE EXCEPTION 'global operation lock release was not safely projected';
  END IF;
END
$$;

CREATE TABLE migration_row_versions (
  relation_name text PRIMARY KEY,
  row_xmin text NOT NULL
);
INSERT INTO migration_row_versions (relation_name, row_xmin)
SELECT 'usage_logs', xmin::text FROM usage_logs WHERE id = 1
UNION ALL SELECT 'audit_logs', xmin::text FROM audit_logs WHERE id = 1
UNION ALL SELECT 'content_moderation_logs', xmin::text FROM content_moderation_logs WHERE id = 1
UNION ALL SELECT 'prompt_audit_events', xmin::text FROM prompt_audit_events WHERE id = 1
UNION ALL SELECT 'prompt_audit_jobs', xmin::text FROM prompt_audit_jobs WHERE id = 1
UNION ALL SELECT 'ops_error_logs', xmin::text FROM ops_error_logs WHERE id = 1
UNION ALL SELECT 'ops_retry_attempts', xmin::text FROM ops_retry_attempts WHERE id = 1
UNION ALL SELECT 'ops_job_heartbeats', xmin::text FROM ops_job_heartbeats WHERE id = 1
UNION ALL SELECT 'ops_system_logs', xmin::text FROM ops_system_logs WHERE id = 1
UNION ALL SELECT 'ops_system_log_cleanup_audits', xmin::text FROM ops_system_log_cleanup_audits WHERE id = 1
UNION ALL SELECT 'idempotency_records', xmin::text FROM idempotency_records WHERE id = 1
UNION ALL SELECT 'idempotency_records_global_lock', xmin::text FROM idempotency_records WHERE id = 2
UNION ALL SELECT 'usage_billing_dedup', xmin::text FROM usage_billing_dedup WHERE id = 1
UNION ALL SELECT 'auth_cache_invalidation_outbox', xmin::text FROM auth_cache_invalidation_outbox WHERE id = 1
UNION ALL SELECT 'usage_cleanup_tasks', xmin::text FROM usage_cleanup_tasks WHERE id = 1
UNION ALL SELECT 'scheduled_test_results', xmin::text FROM scheduled_test_results WHERE id = 1
UNION ALL SELECT 'channel_monitor_histories', xmin::text FROM channel_monitor_histories WHERE id = 1
UNION ALL SELECT 'sora_generations', xmin::text FROM sora_generations WHERE id = 1
UNION ALL SELECT 'batch_image_jobs', xmin::text FROM batch_image_jobs WHERE id = 1
UNION ALL SELECT 'batch_image_items', xmin::text FROM batch_image_items WHERE id = 1
UNION ALL SELECT 'batch_image_events', xmin::text FROM batch_image_events WHERE id = 1
UNION ALL SELECT 'scheduler_outbox', xmin::text FROM scheduler_outbox WHERE id = 1
UNION ALL SELECT 'settings', xmin::text FROM settings WHERE key = 'risk_control_enabled'
UNION ALL SELECT 'settings_image_storage', xmin::text FROM settings WHERE key = 'image_storage_config';
SQL

# Replaying every phase must not rewrite already-clean rows.
run_file postgres migrations/002_remove_conversation_capture.sql >/dev/null
run_file postgres migrations/verify_conversation_guards.sql >/dev/null
run_file postgres migrations/002_scrub_conversation_history.sql >/dev/null
run_file postgres migrations/verify_no_conversation_content.sql >/dev/null
docker exec -i "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE
  rewritten_relations text;
BEGIN
  WITH current_versions (relation_name, row_xmin) AS (
      SELECT 'usage_logs', xmin::text FROM usage_logs WHERE id = 1
      UNION ALL SELECT 'audit_logs', xmin::text FROM audit_logs WHERE id = 1
      UNION ALL SELECT 'content_moderation_logs', xmin::text FROM content_moderation_logs WHERE id = 1
      UNION ALL SELECT 'prompt_audit_events', xmin::text FROM prompt_audit_events WHERE id = 1
      UNION ALL SELECT 'prompt_audit_jobs', xmin::text FROM prompt_audit_jobs WHERE id = 1
      UNION ALL SELECT 'ops_error_logs', xmin::text FROM ops_error_logs WHERE id = 1
      UNION ALL SELECT 'ops_retry_attempts', xmin::text FROM ops_retry_attempts WHERE id = 1
      UNION ALL SELECT 'ops_job_heartbeats', xmin::text FROM ops_job_heartbeats WHERE id = 1
      UNION ALL SELECT 'ops_system_logs', xmin::text FROM ops_system_logs WHERE id = 1
      UNION ALL SELECT 'ops_system_log_cleanup_audits', xmin::text FROM ops_system_log_cleanup_audits WHERE id = 1
      UNION ALL SELECT 'idempotency_records', xmin::text FROM idempotency_records WHERE id = 1
      UNION ALL SELECT 'idempotency_records_global_lock', xmin::text FROM idempotency_records WHERE id = 2
      UNION ALL SELECT 'usage_billing_dedup', xmin::text FROM usage_billing_dedup WHERE id = 1
      UNION ALL SELECT 'auth_cache_invalidation_outbox', xmin::text FROM auth_cache_invalidation_outbox WHERE id = 1
      UNION ALL SELECT 'usage_cleanup_tasks', xmin::text FROM usage_cleanup_tasks WHERE id = 1
      UNION ALL SELECT 'scheduled_test_results', xmin::text FROM scheduled_test_results WHERE id = 1
      UNION ALL SELECT 'channel_monitor_histories', xmin::text FROM channel_monitor_histories WHERE id = 1
      UNION ALL SELECT 'sora_generations', xmin::text FROM sora_generations WHERE id = 1
      UNION ALL SELECT 'batch_image_jobs', xmin::text FROM batch_image_jobs WHERE id = 1
      UNION ALL SELECT 'batch_image_items', xmin::text FROM batch_image_items WHERE id = 1
      UNION ALL SELECT 'batch_image_events', xmin::text FROM batch_image_events WHERE id = 1
      UNION ALL SELECT 'scheduler_outbox', xmin::text FROM scheduler_outbox WHERE id = 1
      UNION ALL SELECT 'settings', xmin::text FROM settings WHERE key = 'risk_control_enabled'
      UNION ALL SELECT 'settings_image_storage', xmin::text FROM settings WHERE key = 'image_storage_config'
    )
    SELECT string_agg(previous.relation_name, ', ' ORDER BY previous.relation_name)
    INTO rewritten_relations
    FROM migration_row_versions AS previous
    FULL JOIN current_versions AS current USING (relation_name)
    WHERE previous.row_xmin IS DISTINCT FROM current.row_xmin;
  IF rewritten_relations IS NOT NULL THEN
    RAISE EXCEPTION 'migration replay rewrote already-scrubbed rows: %',
      rewritten_relations;
  END IF;
  IF (SELECT count(*) FROM usage_billing_dedup_archive) <> 1
     OR EXISTS (
       SELECT 1 FROM usage_billing_dedup_archive
       WHERE request_fingerprint <> ''
     ) THEN
    RAISE EXCEPTION 'migration replay changed scrubbed billing archive values';
  END IF;
END
$$;
DROP TABLE migration_row_versions;
SQL

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE settings DISABLE TRIGGER enforce_privacy_safe_settings;'
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "UPDATE settings SET value = 'true' WHERE key = 'risk_control_enabled';"
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE settings ENABLE TRIGGER enforce_privacy_safe_settings;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted re-enabled risk control" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "UPDATE settings SET value = 'false' WHERE key = 'risk_control_enabled';"

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE settings DISABLE TRIGGER enforce_privacy_safe_settings;'
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "UPDATE settings SET value = '{\"enabled\":true,\"secret_access_key\":\"bypassed-private-secret\"}' WHERE key = 'image_storage_config';"
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE settings ENABLE TRIGGER enforce_privacy_safe_settings;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted re-enabled async image storage" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "UPDATE settings SET value = '{\"enabled\":false}' WHERE key = 'image_storage_config';"

# The final gate rejects residue even if a privileged writer bypasses triggers.
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs DISABLE TRIGGER strip_conversation_content;'
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "UPDATE usage_logs SET prompt = 'bypassed prompt' WHERE id = 1;"
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs ENABLE TRIGGER strip_conversation_content;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted conversation residue" >&2
  exit 1
fi
run_file postgres migrations/002_scrub_conversation_history.sql >/dev/null
run_file postgres migrations/verify_no_conversation_content.sql >/dev/null

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE scheduler_outbox DISABLE TRIGGER strip_conversation_content;'
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c "UPDATE scheduler_outbox SET payload = '{\"group_ids\":[1],\"prompt\":\"bypassed prompt\"}' WHERE id = 1;"
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE scheduler_outbox ENABLE TRIGGER strip_conversation_content;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unsafe scheduler payload" >&2
  exit 1
fi
run_file postgres migrations/002_scrub_conversation_history.sql >/dev/null
run_file postgres migrations/verify_no_conversation_content.sql >/dev/null

# Type and schema drift checks remain fail closed.
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE ops_system_logs ADD COLUMN future_note text;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed text logging field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE ops_system_logs DROP COLUMN future_note;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE ops_system_logs ADD COLUMN future_context jsonb;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed JSON logging field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE ops_system_logs DROP COLUMN future_context;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs ADD COLUMN future_attachment bytea;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed binary logging field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs DROP COLUMN future_attachment;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE audit_logs ADD COLUMN future_markup xml;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed XML logging field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE audit_logs DROP COLUMN future_markup;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE ops_system_logs ADD COLUMN future_fragments text[];'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed array logging field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE ops_system_logs DROP COLUMN future_fragments;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs ALTER COLUMN prompt_tokens TYPE text USING prompt_tokens::text;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted prompt_tokens after a content-capable type drift" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_logs ALTER COLUMN prompt_tokens TYPE bigint USING prompt_tokens::bigint;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE batch_image_jobs ADD COLUMN future_response text;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed batch-image response field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE batch_image_jobs DROP COLUMN future_response;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_billing_dedup ADD COLUMN future_fingerprint text;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed billing fingerprint field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE usage_billing_dedup DROP COLUMN future_fingerprint;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE batch_image_jobs ADD COLUMN future_hash varchar;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed batch-image hash field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE batch_image_jobs DROP COLUMN future_hash;'

docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE batch_image_items ADD COLUMN future_ref text;'
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted an unreviewed batch-image reference field" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'ALTER TABLE batch_image_items DROP COLUMN future_ref;'

docker exec -i "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE DOMAIN private_note_domain AS text;
ALTER TABLE ops_system_logs ADD COLUMN future_domain private_note_domain;
SQL
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted a content-capable domain field" >&2
  exit 1
fi
docker exec -i "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
ALTER TABLE ops_system_logs DROP COLUMN future_domain;
DROP DOMAIN private_note_domain;
SQL

docker exec -i "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE SCHEMA archived_logging;
CREATE TABLE archived_logging.events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  payload text
);
SQL
if run_file postgres migrations/verify_no_conversation_content.sql >/dev/null 2>&1; then
  echo "privacy gate accepted a content-capable field in a non-public schema" >&2
  exit 1
fi
docker exec "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 \
  -c 'DROP SCHEMA archived_logging CASCADE;' >/dev/null
run_file postgres migrations/verify_no_conversation_content.sql >/dev/null

# Trigger behavior after the scrub retains usage metadata and strips all content.
docker exec -i "$container_name" psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO audit_logs (request_body, extra)
VALUES ('new prompt', '{"payload":"new prompt"}');
INSERT INTO content_moderation_logs (
  input_excerpt, error, matched_keyword, category_scores, threshold_snapshot
) VALUES (
  'new prompt', 'new detail', 'new keyword', '{"violence":0.9}', '{"violence":0.4}'
);
INSERT INTO prompt_audit_jobs (
  prompt_hash, redacted_preview, last_error_code, last_error_message
) VALUES ('new-derived-hash', 'new preview', 'stable_new_code', 'new detail');
INSERT INTO ops_error_logs (
  error_phase, error_type, error_source, error_owner, provider_error_code,
  provider_error_type, network_error_type, error_message, error_body,
  upstream_error_message, upstream_error_detail, upstream_errors
) VALUES (
  ' UPSTREAM ', 'new type detail', 'new source detail', 'new owner detail',
  'new provider code', 'new provider detail', 'new network detail',
  'new detail', 'new answer', 'new detail', 'new detail',
  '[{"body":"new answer"}]'
);
INSERT INTO usage_logs (
  input_tokens, prompt_tokens, output_tokens, actual_cost, model, duration_ms,
  prompt, messages, image_size_breakdown, session_id
) VALUES (
  5, 5, 2, 0.05, 'model-trigger', 90, 'new prompt',
  '[{"role":"user"}]', '{"private":"size"}', 'trigger-usage-session-reference'
);
UPDATE usage_logs
SET prompt_tokens = 10,
    prompt = 'updated prompt',
    messages = '[{"role":"user","content":"updated prompt"}]',
    image_size_breakdown = '{"private":"updated size"}',
    session_id = 'updated-usage-session-reference'
WHERE model = 'model-test';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM usage_logs
    WHERE model = 'model-test' AND prompt_tokens = 10
      AND prompt IS NULL AND messages IS NULL
      AND image_size_breakdown IS NULL AND session_id IS NULL
  ) OR NOT EXISTS (
    SELECT 1 FROM usage_logs
    WHERE model = 'model-trigger' AND input_tokens = 5
      AND prompt_tokens = 5 AND output_tokens = 2
      AND prompt IS NULL AND messages IS NULL
      AND image_size_breakdown IS NULL AND session_id IS NULL
  ) THEN
    RAISE EXCEPTION 'usage content trigger did not clear writes';
  END IF;
  IF (SELECT error_phase FROM ops_error_logs WHERE id = 2) <> 'upstream' THEN
    RAISE EXCEPTION 'ops error phase trigger accepted free-form classification';
  END IF;
  IF EXISTS (
    SELECT 1 FROM content_moderation_logs
    WHERE input_excerpt <> '' OR error <> '' OR matched_keyword <> ''
      OR category_scores <> '{}'::jsonb
      OR threshold_snapshot <> '{}'::jsonb
  ) THEN
    RAISE EXCEPTION 'moderation trigger retained conversation-capable content';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM prompt_audit_jobs
    WHERE id = 2 AND prompt_hash = '' AND redacted_preview = ''
      AND last_error_code = 'stable_new_code' AND last_error_message = ''
  ) THEN
    RAISE EXCEPTION 'prompt audit trigger mishandled stable metadata';
  END IF;
END
$$;
SQL

run_file postgres migrations/verify_no_conversation_content.sql >/dev/null
echo "PostgreSQL 18 privacy migration integration test passed"
