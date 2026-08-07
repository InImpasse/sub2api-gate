import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "verify-release-policy.py"
SPEC = importlib.util.spec_from_file_location("verify_release_policy", TOOL_PATH)
POLICY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(POLICY)


class ReleasePolicyTests(unittest.TestCase):
    def test_reviewed_policy_matches_all_active_consumers(self):
        policy = POLICY.read_policy()
        self.assertTrue(POLICY.verify(policy))
        self.assertEqual(policy["sub2api"]["version"], "0.1.171")

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
                + "\nSub2API 0.1.171\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(POLICY.ReleasePolicyError, "unreviewed Redis"):
                POLICY._check_runtime_compose(
                    path, policy, require_runtime_images=True
                )

    def test_local_gate_invokes_policy_before_runtime_tests(self):
        gate = (ROOT / "deploy" / "verify-local.sh").read_text(encoding="utf-8")
        self.assertIn("python3 -I deploy/verify-release-policy.py", gate)


if __name__ == "__main__":
    unittest.main()
