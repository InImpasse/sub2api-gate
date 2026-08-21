import importlib.util
import json
import pathlib
import shutil
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "verify-release-policy.py"
SPEC = importlib.util.spec_from_file_location("verify_release_policy", TOOL_PATH)
POLICY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(POLICY)


class ReleasePolicyTests(unittest.TestCase):
    RELEASE_CONSUMERS = (
        "deploy/release-policy.json",
        "deploy/README.md",
        "deploy/configure-redis-acl.py",
        "deploy/migrate-app-metadata.py",
        "deploy/migrate-redis-allowlist.py",
        "deploy/security-preflight.sh",
        "deploy/test-app-role-least-privilege-pg18.sh",
        "deploy/test-redis-runtime-acl.sh",
        "deploy/test-sub2api-no-content-logging.sh",
        "deploy/traffic-canary.py",
        "deploy/verify-runtime-versions.sh",
        "deploy/redis-key-prefixes.json",
        "docker-compose.yml",
        "docker-compose.canary.yml",
        "docker-compose.sync-canary.yml",
        "docker-compose.traffic-canary.yml",
        "migrations/002_remove_conversation_capture.sql",
        "migrations/005_app_least_privilege.sql",
        "migrations/006_allow_sub2api_schema_migrations.sql",
        "migrations/007_allow_sub2api_function_trigger_migrations.sql",
        "migrations/008_allow_sub2api_additive_alter_migrations.sql",
        "migrations/009_allow_sub2api_deny_list_ddl_guard.sql",
        "migrations/sub2api_gate_guard_app_ddl.sql",
        "migrations/221_group_model_pricing.sql",
        "sub2api-sync/Dockerfile",
    )

    def _copy_release_fixture(self, directory):
        directory = pathlib.Path(directory)
        for relative in self.RELEASE_CONSUMERS:
            source = ROOT / relative
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)

    def test_reviewed_policy_matches_all_active_consumers(self):
        policy = POLICY.read_policy()
        self.assertTrue(POLICY.verify(policy))
        self.assertEqual(policy["sub2api"]["version"], "0.1.176")

    def test_policy_rejects_a_digest_or_source_revision_drift(self):
        policy = POLICY.read_policy()
        policy["sub2api"]["image"] = "weishaw/sub2api"
        with self.assertRaises(POLICY.ReleasePolicyError):
            POLICY.validate_policy_shape(policy)

        policy = POLICY.read_policy()
        policy["sub2api"]["source_revision"] = "not-a-commit"
        with self.assertRaises(POLICY.ReleasePolicyError):
            POLICY.validate_policy_shape(policy)

    def test_compose_consumer_rejects_an_unreviewed_sub2api_digest(self):
        policy = POLICY.read_policy()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "docker-compose.yml"
            path.write_text(
                "image: weishaw/sub2api@sha256:" + "0" * 64 + "\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(POLICY.ReleasePolicyError, "unreviewed Sub2API"):
                POLICY._check_runtime_compose(
                    path, policy, require_runtime_images=True
                )

    def test_runtime_compose_requires_all_three_pinned_images(self):
        policy = POLICY.read_policy()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "docker-compose.yml"
            path.write_text(
                "\n".join(
                    (
                        policy["sub2api"]["image"],
                        policy["postgres"]["image"],
                    )
                )
                + "\nSub2API 0.1.176\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(POLICY.ReleasePolicyError, "unreviewed Redis"):
                POLICY._check_runtime_compose(
                    path, policy, require_runtime_images=True
                )

    def test_local_gate_invokes_policy_before_runtime_tests(self):
        gate = (ROOT / "deploy" / "verify-local.sh").read_text(encoding="utf-8")
        self.assertIn("python3 -I deploy/verify-release-policy.py", gate)
        self.assertIn(
            "npm --prefix worker-allow-ip audit --audit-level=high "
            "--package-lock-only --ignore-scripts",
            gate,
        )

    def test_verifier_reads_every_release_consumer_from_the_supplied_root(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory)
            self._copy_release_fixture(fixture)
            self.assertTrue(POLICY.verify(root=fixture))

            (fixture / "docker-compose.canary.yml").unlink()
            with self.assertRaisesRegex(
                POLICY.ReleasePolicyError,
                "release consumer is unavailable",
            ):
                POLICY.verify(root=fixture)

    def test_verifier_reads_the_release_policy_from_the_supplied_root(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = pathlib.Path(directory)
            self._copy_release_fixture(fixture)
            policy_path = fixture / "deploy" / "release-policy.json"
            policy = json.loads(policy_path.read_text(encoding="ascii"))
            policy["schema"] = 2
            policy_path.write_text(
                json.dumps(policy, separators=(",", ":")),
                encoding="ascii",
            )
            with self.assertRaisesRegex(
                POLICY.ReleasePolicyError,
                "schema is unsupported",
            ):
                POLICY.verify(root=fixture)


if __name__ == "__main__":
    unittest.main()
