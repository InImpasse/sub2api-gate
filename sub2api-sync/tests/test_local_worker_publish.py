import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "local-worker-publish.py"
SPEC = importlib.util.spec_from_file_location("local_worker_publish", TOOL_PATH)
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)


class LocalWorkerPublishTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.config = self.root / "wrangler.private.jsonc"
        self.config.write_text("{}\n", encoding="ascii")
        self.config.chmod(0o600)

    def tearDown(self):
        self.temporary.cleanup()

    def test_release_stage_is_pinned_to_the_reviewed_source_and_secret_contract(self):
        compatibility = PUBLISHER.release_spec("compatibility")
        staged = PUBLISHER.release_spec("stage")
        promoted = PUBLISHER.release_spec("promoted")
        final_source = PUBLISHER.release_spec("final-source")

        self.assertEqual(compatibility.commit, PUBLISHER.COMPATIBILITY_RELEASE)
        self.assertEqual(compatibility.secret_requirement, "--forbid-totp-rotation-staging")
        self.assertEqual(staged.commit, PUBLISHER.COMPATIBILITY_RELEASE)
        self.assertEqual(promoted.commit, PUBLISHER.COMPATIBILITY_RELEASE)
        self.assertEqual(staged.secret_requirement, "--require-totp-rotation-staging")
        self.assertEqual(promoted.secret_requirement, "--require-totp-rotation-staging")
        self.assertEqual(final_source.commit, PUBLISHER.FINAL_SOURCE_RELEASE)
        self.assertTrue(final_source.verify_final_source)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "unsupported"):
            PUBLISHER.release_spec("unknown")

    def test_private_config_must_be_owned_single_link_regular_file_with_mode_0600(self):
        PUBLISHER.require_private_config(self.config, expected_uid=os.geteuid())

        self.config.chmod(0o640)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "mode-0600"):
            PUBLISHER.require_private_config(self.config, expected_uid=os.geteuid())

        self.config.chmod(0o600)
        linked = self.root / "linked.jsonc"
        os.link(self.config, linked)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "single-link"):
            PUBLISHER.require_private_config(self.config, expected_uid=os.geteuid())
        linked.unlink()

        replacement = self.root / "replacement.jsonc"
        replacement.write_text("{}\n", encoding="ascii")
        replacement.chmod(0o600)
        self.config.unlink()
        self.config.symlink_to(replacement)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "regular file"):
            PUBLISHER.require_private_config(self.config, expected_uid=os.geteuid())

    def test_publish_environment_uses_local_oauth_home_without_api_token_or_inherited_injection(self):
        environment = PUBLISHER.build_wrangler_environment(
            pathlib.Path("/opt/node/bin/node"), pathlib.Path("/home/operator")
        )

        self.assertEqual(environment["HOME"], "/home/operator")
        self.assertEqual(environment["PATH"], "/opt/node/bin:/usr/bin:/bin")
        self.assertEqual(environment["WRANGLER_SEND_METRICS"], "false")
        self.assertEqual(environment["CLOUDFLARE_INCLUDE_PROCESS_ENV"], "false")
        self.assertEqual(environment["CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV"], "false")
        self.assertNotIn("CLOUDFLARE_API_TOKEN", environment)
        self.assertNotIn("NODE_OPTIONS", environment)

    def test_plan_verifies_final_source_and_secret_names_before_deploy(self):
        stage = self.root / "release"
        worker = stage / "worker-allow-ip"
        worker.mkdir(parents=True)
        config = worker / "wrangler.private.jsonc"
        config.write_text("{}\n", encoding="ascii")
        commands = PUBLISHER.build_publish_plan(
            stage,
            PUBLISHER.release_spec("final-source"),
            pathlib.Path("/opt/node/bin/node"),
        )

        labels = [command.label for command in commands]
        self.assertEqual(labels[-1], "deploy")
        self.assertLess(labels.index("verify-final-source"), labels.index("verify-secret-names"))
        self.assertLess(labels.index("verify-secret-names"), labels.index("deploy-dry-run"))
        self.assertLess(labels.index("deploy-dry-run"), labels.index("deploy"))
        self.assertTrue(all("secret" not in command.output_label.lower() for command in commands))
        self.assertIn("--require-totp-rotation-staging", commands[labels.index("verify-secret-names")].arguments)

    def test_check_plan_has_no_publish_command(self):
        stage = self.root / "release"
        (stage / "worker-allow-ip").mkdir(parents=True)
        commands = PUBLISHER.build_publish_plan(
            stage,
            PUBLISHER.release_spec("compatibility"),
            pathlib.Path("/opt/node/bin/node"),
            apply=False,
        )
        self.assertNotIn("deploy", [command.label for command in commands])
        self.assertIn("deploy-dry-run", [command.label for command in commands])

    def test_secret_name_failure_stops_before_worker_publish(self):
        runner = RecordingRunner(fail_secret_list=True)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "publish gate failed"):
            PUBLISHER.run_publish_plan(
                self.root / "release",
                PUBLISHER.release_spec("compatibility"),
                pathlib.Path("/opt/node/bin/node"),
                pathlib.Path("/home/operator"),
                apply=True,
                runner=runner,
            )
        joined = [" ".join(call) for call in runner.calls]
        self.assertFalse(any(" deploy --config " in f" {call} " for call in joined))

    def test_check_mode_never_reads_remote_secret_names_or_publishes(self):
        runner = RecordingRunner()
        PUBLISHER.run_publish_plan(
            self.root / "release",
            PUBLISHER.release_spec("compatibility"),
            pathlib.Path("/opt/node/bin/node"),
            pathlib.Path("/home/operator"),
            apply=False,
            runner=runner,
        )

        joined = [" ".join(call) for call in runner.calls]
        self.assertFalse(any(" secret list " in f" {call} " for call in joined))
        self.assertFalse(any(" deploy --config " in f" {call} " for call in joined))
        self.assertTrue(any(" deploy --dry-run " in f" {call} " for call in joined))

    def test_unsupported_node_stops_before_dependency_installation(self):
        runner = RecordingRunner(node_version="v21.9.0\n")
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "Node.js 22"):
            PUBLISHER.run_publish_plan(
                self.root / "release",
                PUBLISHER.release_spec("compatibility"),
                pathlib.Path("/opt/node/bin/node"),
                pathlib.Path("/home/operator"),
                apply=False,
                runner=runner,
            )
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0][-1], "--version")

    def test_partial_worktree_setup_is_removed_when_release_identity_check_fails(self):
        runner = WorktreeFailureRunner(PUBLISHER.COMPATIBILITY_RELEASE)
        stage = self.root / "release"
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "does not match"):
            PUBLISHER.stage_release(
                self.root,
                stage,
                PUBLISHER.release_spec("compatibility"),
                runner=runner,
            )
        self.assertTrue(any(" worktree remove --force " in f" {' '.join(call)} " for call in runner.calls))


class RecordingRunner:
    def __init__(self, *, fail_secret_list=False, node_version="v24.15.0\n"):
        self.fail_secret_list = fail_secret_list
        self.node_version = node_version
        self.calls = []

    def __call__(self, arguments, **_kwargs):
        command = tuple(map(str, arguments))
        self.calls.append(command)
        if command[-1:] == ("--version",):
            if "wrangler.js" in command[1]:
                return subprocess.CompletedProcess(command, 0, "4.112.0\n", "")
            return subprocess.CompletedProcess(command, 0, self.node_version, "")
        if "secret" in command and "list" in command:
            if self.fail_secret_list:
                return subprocess.CompletedProcess(command, 1, "", "private error")
            return subprocess.CompletedProcess(command, 0, json.dumps([]), "")
        return subprocess.CompletedProcess(command, 0, "", "")


class WorktreeFailureRunner:
    def __init__(self, expected_commit):
        self.expected_commit = expected_commit
        self.calls = []

    def __call__(self, arguments, **_kwargs):
        command = tuple(map(str, arguments))
        self.calls.append(command)
        joined = " ".join(command)
        if "rev-parse --is-inside-work-tree" in joined:
            return subprocess.CompletedProcess(command, 0, "true\n", "")
        if "rev-parse --verify" in joined:
            return subprocess.CompletedProcess(command, 0, self.expected_commit + "\n", "")
        if "rev-parse HEAD" in joined:
            return subprocess.CompletedProcess(command, 0, "0" * 40 + "\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")


if __name__ == "__main__":
    unittest.main()
