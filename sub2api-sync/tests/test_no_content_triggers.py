import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATION = (ROOT / "migrations" / "002_remove_conversation_capture.sql").read_text()
SCRUB_MIGRATION_PATH = ROOT / "migrations" / "002_scrub_conversation_history.sql"
GUARD_CHECK_PATH = ROOT / "migrations" / "verify_conversation_guards.sql"
SCRUB_MIGRATION = SCRUB_MIGRATION_PATH.read_text()
GUARD_CHECK = GUARD_CHECK_PATH.read_text()
RESIDUE_CHECK = (ROOT / "migrations" / "verify_no_conversation_content.sql").read_text()


class NoConversationContentMigrationTests(unittest.TestCase):
    def test_write_guards_commit_before_historical_scrubbing(self):
        self.assertTrue(SCRUB_MIGRATION_PATH.exists())
        self.assertTrue(GUARD_CHECK_PATH.exists())
        guard_migration = MIGRATION
        scrub_migration = SCRUB_MIGRATION_PATH.read_text()

        self.assertTrue(guard_migration.startswith("BEGIN;"))
        self.assertTrue(guard_migration.rstrip().endswith("COMMIT;"))
        self.assertNotIn("scrub_optional_content_columns", guard_migration)
        self.assertIn("scrub_optional_content_columns", scrub_migration)
        self.assertTrue(scrub_migration.startswith("\\set ON_ERROR_STOP on"))
        self.assertIn("strip_conversation_content", GUARD_CHECK)
        self.assertNotIn("UPDATE ", GUARD_CHECK.upper())
        self.assertNotIn("DELETE ", GUARD_CHECK.upper())

    def test_sub2api_0162_content_derived_fields_are_scrubbed(self):
        for field in (
            "prompt_hash",
            "request_hash",
            "manifest_hash",
            "event_hash",
            "categories",
            "matched_scanners",
            "scanner_scores",
            "image_size_breakdown",
        ):
            self.assertIn(f"'{field}'", MIGRATION)
        self.assertIn("public.conversation_content_policy()", RESIDUE_CHECK)

    def test_sensitive_log_identity_and_deleted_key_fields_are_scrubbed(self):
        for table, fields in {
            "audit_logs": (
                "actor_email", "credential_masked", "client_ip", "user_agent",
            ),
            "content_moderation_logs": (
                "user_email", "api_key_name", "group_name",
            ),
            "prompt_audit_events": (
                "username_snapshot", "user_email_snapshot",
                "api_key_name_snapshot", "group_name",
            ),
            "prompt_audit_jobs": (
                "username_snapshot", "user_email_snapshot",
                "api_key_name_snapshot", "group_name",
            ),
            "ops_error_logs": (
                "user_agent", "attempted_key_prefix", "deleted_key_name",
                "api_key_prefix",
            ),
            "usage_logs": ("user_agent", "ip_address"),
            "deleted_api_key_audits": ("key", "key_name"),
            "batch_image_jobs": ("idempotency_key",),
        }.items():
            self.assertIn(f"'{table}', jsonb_build_object(", MIGRATION)
            self.assertIn(f"to_regclass('public.{table}')", SCRUB_MIGRATION)
            for field in fields:
                self.assertIn(f"'{field}'", MIGRATION)

    def test_sub2api_batch_content_tables_are_guarded(self):
        expected = {
            "batch_image_jobs": (
                "task_name",
                "provider_input_ref",
                "provider_output_ref",
                "gcs_input_uri",
                "gcs_output_uri",
                "request_hash",
                "manifest_hash",
                "last_error_message",
                "session_id",
            ),
            "batch_image_items": (
                "request_hash",
                "prompt_preview",
                "provider_source_object",
                "error_message",
            ),
            "batch_image_events": ("payload", "event_hash"),
            "scheduled_test_results": ("response_text", "error_message"),
            "channel_monitor_histories": ("message",),
            "sora_generations": (
                "prompt",
                "media_url",
                "media_urls",
                "s3_object_keys",
                "error_message",
            ),
        }
        for table, fields in expected.items():
            self.assertIn(f"'{table}', jsonb_build_object(", MIGRATION)
            self.assertIn(f"to_regclass('public.{table}')", SCRUB_MIGRATION)
            for field in fields:
                self.assertIn(f"'{field}'", MIGRATION)

        for stable_field in (
            "provider_job_name",
            "last_error_code",
            "error_code",
            "custom_id",
        ):
            self.assertNotIn(f"'{stable_field}', NULL", MIGRATION)

    def test_unbounded_batch_session_references_are_scrubbed(self):
        batch_policy = MIGRATION.split(
            "'batch_image_jobs', jsonb_build_object(", 1
        )[1].split("'batch_image_items', jsonb_build_object(", 1)[0]
        self.assertIn("'session_id', NULL", batch_policy)
        reviewed_metadata = MIGRATION.split(
            "WHEN 'batch_image_jobs' THEN target_column = ANY", 1
        )[1].split("WHEN 'channel_monitor_histories'", 1)[0]
        self.assertNotIn("'session_id'", reviewed_metadata)

    def test_unbounded_usage_session_references_are_scrubbed(self):
        usage_policy = MIGRATION.split(
            "'usage_logs', jsonb_build_object(", 1
        )[1].split("'audit_logs', jsonb_build_object(", 1)[0]
        self.assertIn("'session_id', NULL", usage_policy)
        reviewed_metadata = MIGRATION.split(
            "WHEN 'usage_logs' THEN target_column = ANY", 1
        )[1].split("ELSE false", 1)[0]
        self.assertNotIn("'session_id'", reviewed_metadata)

    def test_active_content_jobs_fail_closed_before_guard_installation(self):
        self.assertIn("public.assert_no_active_conversation_jobs()", MIGRATION)
        self.assertIn("public.content_job_status_is_terminal", MIGRATION)
        self.assertIn("active content jobs must be drained or cancelled", MIGRATION)
        self.assertIn("active content jobs are disabled", MIGRATION)
        self.assertIn("public.assert_no_active_conversation_jobs()", GUARD_CHECK)
        self.assertIn("public.assert_no_active_conversation_jobs()", RESIDUE_CHECK)

    def test_scheduler_outbox_keeps_only_bounded_operational_metadata(self):
        self.assertIn("'scheduler_outbox', jsonb_build_object(", MIGRATION)
        self.assertIn("public.sanitize_scheduler_outbox_payload", MIGRATION)
        for event_type in (
            "account_changed",
            "account_groups_changed",
            "account_bulk_changed",
            "account_last_used",
        ):
            self.assertIn(f"'{event_type}'", MIGRATION)
        for safe_key in ("account_ids", "group_ids", "last_used"):
            self.assertIn(f"'{safe_key}'", MIGRATION)
        self.assertIn("normalize_scheduler_outbox_payloads", SCRUB_MIGRATION)
        self.assertIn("sanitize_scheduler_outbox_payload", RESIDUE_CHECK)
        self.assertNotIn("'prompt'", MIGRATION.split(
            "CREATE OR REPLACE FUNCTION public.sanitize_scheduler_outbox_payload", 1
        )[1])

    def test_background_response_and_error_histories_are_scrubbed(self):
        expected = {
            "ops_job_heartbeats": ("last_error", "last_result"),
            "auth_cache_invalidation_outbox": ("last_error",),
            "usage_cleanup_tasks": ("error_message",),
            "scheduled_test_results": ("response_text", "error_message"),
            "channel_monitor_histories": ("message",),
        }
        for table, fields in expected.items():
            self.assertIn(f"'{table}', jsonb_build_object(", MIGRATION)
            self.assertIn(f"to_regclass('public.{table}')", SCRUB_MIGRATION)
            for field in fields:
                self.assertIn(field, MIGRATION)

    def test_auth_cache_outbox_keeps_only_bounded_sha256_references(self):
        self.assertIn("public.is_safe_auth_cache_key", MIGRATION)
        self.assertIn("'cache_key', 'claimed_by'", MIGRATION)
        self.assertIn("auth cache key must remain a SHA-256 reference", MIGRATION)
        self.assertIn(
            "DELETE FROM public.auth_cache_invalidation_outbox",
            SCRUB_MIGRATION,
        )
        self.assertIn("public.is_safe_auth_cache_key(cache_key::text)", RESIDUE_CHECK)

    def test_usage_log_content_is_cleared_and_blocked(self):
        content_columns = (
            "prompt", "content", "messages", "input", "output", "payload",
            "request_body", "response_body", "request_headers",
            "response_headers", "body", "request", "response", "completion",
        )
        self.assertIn("'usage_logs', jsonb_build_object(", MIGRATION)
        self.assertIn("BEFORE INSERT OR UPDATE ON %s", MIGRATION)
        for column in content_columns:
            self.assertIn(f"'{column}', NULL", MIGRATION)

        usage_section = MIGRATION.split(
            "'usage_logs', jsonb_build_object(", 1
        )[1].split("'audit_logs', jsonb_build_object(", 1)[0]
        for metadata_column in (
            "prompt_tokens", "input_tokens", "output_tokens", "actual_cost",
            "model", "duration_ms",
        ):
            self.assertNotIn(f"'{metadata_column}', NULL", usage_section)

    def test_request_capture_columns_are_removed_idempotently(self):
        for column in (
            "request_headers",
            "body_text",
            "body_preview",
            "response_preview",
            "debug_response_body",
        ):
            self.assertIn(f"DROP COLUMN IF EXISTS {column}", MIGRATION)

    def test_content_moderation_text_is_cleared_and_blocked(self):
        self.assertIn("'content_moderation_logs', jsonb_build_object(", MIGRATION)
        self.assertIn("'input_excerpt', ''", MIGRATION)
        self.assertIn("matched_keyword", MIGRATION)
        self.assertIn("strip_conversation_content", MIGRATION)
        for column in ("category_scores", "threshold_snapshot"):
            self.assertIn(column, MIGRATION)
        self.assertIn("jsonb_each(target.replacements)", RESIDUE_CHECK)

    def test_ops_error_free_text_is_cleared_and_blocked(self):
        for column in (
            "request_headers",
            "request_body",
            "response_headers",
            "response_body",
            "error_message",
            "error_body",
            "upstream_error_message",
            "upstream_error_detail",
        ):
            self.assertIn(f"'{column}', NULL", MIGRATION)
        self.assertIn("'upstream_errors', '[]'::jsonb", MIGRATION)
        for phase in (
            "request", "auth", "routing", "upstream", "network", "internal",
        ):
            self.assertIn(f"'{phase}'", MIGRATION)
        self.assertIn("lower(btrim(error_phase::text)) NOT IN", RESIDUE_CHECK)
        self.assertIn("TG_TABLE_NAME = 'ops_error_logs'", MIGRATION)

    def test_system_log_payloads_are_cleared_and_blocked(self):
        self.assertIn("'ops_system_logs', jsonb_build_object(", MIGRATION)
        self.assertIn("'message', ''", MIGRATION)
        self.assertIn("'extra', '{}'::jsonb", MIGRATION)
        self.assertIn("BEFORE INSERT OR UPDATE ON %s", MIGRATION)
        self.assertIn("ops_system_log_cleanup_audits", MIGRATION)
        self.assertIn("'conditions', '{}'::jsonb", MIGRATION)

    def test_extended_error_and_idempotency_fields_are_cleared(self):
        for column in (
            "error_type", "error_source", "error_owner",
            "provider_error_code", "provider_error_type", "network_error_type",
            "error_reason",
        ):
            self.assertIn(column, MIGRATION)
        self.assertIn("jsonb_each(target.replacements)", RESIDUE_CHECK)
        self.assertIn("'idempotency_records', jsonb_build_object(", MIGRATION)
        self.assertIn("'request_fingerprint', ''", MIGRATION)
        self.assertIn("'response_body', NULL", MIGRATION)
        self.assertIn("sanitize_idempotency_request_fingerprint", MIGRATION)
        self.assertIn("sanitize_idempotency_response_body", MIGRATION)
        self.assertIn("admin.system.operations.global_lock", MIGRATION)
        self.assertIn("is_safe_system_operation_id", MIGRATION)
        self.assertIn("sanitize_idempotency_response_body", SCRUB_MIGRATION)
        self.assertIn("sanitize_idempotency_response_body", RESIDUE_CHECK)
        self.assertIn(
            "scope_name IS DISTINCT FROM 'admin.system.operations.global_lock'",
            MIGRATION,
        )
        self.assertIn("status_name IS DISTINCT FROM 'succeeded'", MIGRATION)

    def test_gateway_usage_billing_body_fingerprints_are_not_retained(self):
        for table in (
            "usage_billing_dedup",
            "usage_billing_dedup_archive",
        ):
            self.assertIn(f"'{table}', jsonb_build_object(", MIGRATION)
            self.assertIn("'request_fingerprint', ''", MIGRATION)
            self.assertIn(f"to_regclass('public.{table}')", SCRUB_MIGRATION)

        self.assertIn("SELECT ctid AS row_tid", SCRUB_MIGRATION)
        self.assertIn("target.ctid = candidates.row_tid", SCRUB_MIGRATION)

    def test_optional_retry_previews_are_cleared_when_table_exists(self):
        retry_policy = MIGRATION.split(
            "'ops_retry_attempts', jsonb_build_object(", 1
        )[1].split("'ops_system_logs', jsonb_build_object(", 1)[0]
        self.assertIn("'response_preview', ''", retry_policy)
        self.assertIn("'error_message', ''", retry_policy)
        self.assertIn("to_regclass('public.ops_retry_attempts')", SCRUB_MIGRATION)
        self.assertIn("ops_retry_attempts", GUARD_CHECK)
        self.assertIn("ops_retry_attempts", RESIDUE_CHECK)

    def test_audit_and_prompt_text_is_cleared_and_blocked(self):
        expected = {
            "audit_logs": ("request_body", "extra"),
            "prompt_audit_events": (
                "full_prompt",
                "redacted_preview",
                "scanner_evidence",
            ),
            "prompt_audit_jobs": ("redacted_preview", "last_error_message"),
        }
        for table, columns in expected.items():
            self.assertIn(f"'{table}', jsonb_build_object(", MIGRATION)
            self.assertIn(f"to_regclass('public.{table}')", SCRUB_MIGRATION)
            for column in columns:
                self.assertIn(column, MIGRATION)

        self.assertIn("risk_control_enabled", MIGRATION)
        self.assertIn("false", MIGRATION.lower())

    def test_privacy_sensitive_settings_are_forced_safe_and_guarded(self):
        for sql in (MIGRATION, SCRUB_MIGRATION, GUARD_CHECK, RESIDUE_CHECK):
            self.assertIn("risk_control_enabled", sql)
            self.assertIn("image_storage_config", sql)
            self.assertIn('{"enabled":false}', sql)

        self.assertIn("enforce_privacy_safe_settings", MIGRATION)
        self.assertIn("BEFORE INSERT OR UPDATE OR DELETE", MIGRATION)
        self.assertIn("privacy-safe setting cannot be deleted", MIGRATION)
        self.assertIn("privacy-safe setting cannot be renamed", MIGRATION)
        self.assertIn("risk control must remain disabled", RESIDUE_CHECK)
        self.assertIn("async image storage must remain disabled", RESIDUE_CHECK)
        self.assertIn("privacy-safe settings write guard missing", GUARD_CHECK)
        self.assertIn("privacy-safe settings write guard missing", RESIDUE_CHECK)

    def test_schema_drift_rejects_content_derived_identifiers(self):
        for sql in (GUARD_CHECK, RESIDUE_CHECK):
            self.assertIn("public.is_reviewed_content_metadata_column", sql)
            self.assertIn(
                "('idempotency_records', 'idempotency_key_hash')",
                sql,
            )
        self.assertIn("columns.data_type IN (", GUARD_CHECK)
        self.assertIn("public.is_conversation_capable_type", RESIDUE_CHECK)
        self.assertIn("pg_catalog.pg_attribute", RESIDUE_CHECK)
        self.assertIn("namespace.nspname <> 'public'", RESIDUE_CHECK)

    def test_optional_columns_are_scrubbed_without_schema_assumptions(self):
        self.assertIn("scrub_optional_content_columns", SCRUB_MIGRATION)
        self.assertIn(
            "CREATE OR REPLACE PROCEDURE pg_temp.scrub_optional_content_columns",
            SCRUB_MIGRATION,
        )
        self.assertNotIn(
            "CREATE OR REPLACE PROCEDURE public.scrub_optional_content_columns",
            SCRUB_MIGRATION,
        )
        self.assertIn("FOR UPDATE", SCRUB_MIGRATION)
        self.assertNotIn("SKIP LOCKED", SCRUB_MIGRATION)
        self.assertIn("CALL pg_temp.scrub_optional_content_columns", SCRUB_MIGRATION)
        self.assertIn("CALL pg_temp.normalize_ops_error_phases", SCRUB_MIGRATION)
        self.assertIn("1000", SCRUB_MIGRATION)
        self.assertIn("COMMIT;", SCRUB_MIGRATION)
        self.assertIn("replacements ? attribute.attname", SCRUB_MIGRATION)
        self.assertIn("jsonb_populate_record", SCRUB_MIGRATION)
        self.assertIn("to_jsonb(%1$I) IS DISTINCT FROM", SCRUB_MIGRATION)
        self.assertIn("UPDATE %s AS target SET %s", SCRUB_MIGRATION)
        self.assertIn(
            "DROP PROCEDURE pg_temp.scrub_optional_content_columns(regclass, jsonb, integer)",
            SCRUB_MIGRATION,
        )

    def test_migration_is_transactional_and_does_not_drop_usage_metadata(self):
        self.assertTrue(MIGRATION.startswith("BEGIN;"))
        self.assertTrue(MIGRATION.rstrip().endswith("COMMIT;"))
        self.assertNotIn("DROP TABLE usage_logs", MIGRATION)
        self.assertNotIn("DROP COLUMN IF EXISTS input_tokens", MIGRATION)
        self.assertNotIn("DROP COLUMN IF EXISTS actual_cost", MIGRATION)


if __name__ == "__main__":
    unittest.main()
