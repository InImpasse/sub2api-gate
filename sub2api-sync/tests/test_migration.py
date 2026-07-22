import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
MIGRATION = (ROOT / "migrations" / "001_default_to_openai_default.sql").read_text()


class GroupMigrationTests(unittest.TestCase):
    def test_migration_is_transactional_and_exact(self):
        self.assertTrue(MIGRATION.lstrip().startswith("BEGIN;"))
        self.assertTrue(MIGRATION.rstrip().endswith("COMMIT;"))
        self.assertIn("target.name = 'openai-default'", MIGRATION)
        self.assertIn("source.name = 'default'", MIGRATION)

    def test_migration_covers_all_known_group_references(self):
        for table in (
            "api_keys", "account_groups", "user_allowed_groups",
            "user_group_rate_multipliers", "user_subscriptions", "usage_logs",
            "redeem_codes", "content_moderation_logs", "channel_groups",
            "subscription_plans",
        ):
            self.assertIn(table, MIGRATION)

    def test_migration_aborts_on_unknown_references(self):
        self.assertIn("pg_constraint", MIGRATION)
        self.assertIn("generate_subscripts(fk.confkey, 1)", MIGRATION)
        self.assertNotIn("array_length(fk.conkey, 1) = 1", MIGRATION)
        self.assertIn("JOIN group_migration_ids AS ids", MIGRATION)
        self.assertIn("referencing.%I = ids.source_id", MIGRATION)
        self.assertNotIn("SELECT source_id INTO source", MIGRATION)
        self.assertIn("unmigrated group reference", MIGRATION)
        self.assertIn("RAISE EXCEPTION", MIGRATION)

    def test_migration_aborts_before_merging_dual_active_subscriptions(self):
        guard = "dual active user subscriptions require manual resolution"
        self.assertIn(guard, MIGRATION)
        self.assertNotIn("DELETE FROM user_subscriptions", MIGRATION)

    def test_migration_never_discards_channel_or_plan_relationships(self):
        self.assertIn("UPDATE channel_groups SET group_id", MIGRATION)
        self.assertIn("UPDATE subscription_plans SET group_id", MIGRATION)
        self.assertNotIn("DELETE FROM channel_groups", MIGRATION)
        self.assertNotIn("DELETE FROM subscription_plans", MIGRATION)


if __name__ == "__main__":
    unittest.main()
