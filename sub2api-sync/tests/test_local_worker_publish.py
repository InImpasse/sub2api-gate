import importlib.util
import contextlib
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "local-worker-publish.py"
SPEC = importlib.util.spec_from_file_location("local_worker_publish", TOOL_PATH)
PUBLISHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLISHER)
NODE = pathlib.Path(shutil.which("node") or "")


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

        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "owned"):
            PUBLISHER.require_private_config(self.config, expected_uid=os.geteuid() + 1)

        with self.config.open("wb") as oversized:
            oversized.truncate(PUBLISHER.MAX_CONFIG_BYTES + 1)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "too large"):
            PUBLISHER.require_private_config(self.config, expected_uid=os.geteuid())
        self.config.write_text("{}\n", encoding="ascii")
        self.config.chmod(0o600)

        replacement = self.root / "replacement.jsonc"
        replacement.write_text("{}\n", encoding="ascii")
        replacement.chmod(0o600)
        self.config.unlink()
        self.config.symlink_to(replacement)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "regular file"):
            PUBLISHER.require_private_config(self.config, expected_uid=os.geteuid())

    def test_private_config_copy_is_byte_exact_single_link_and_mode_0600(self):
        destination = self.root / "staged-private.jsonc"
        expected = self.config.read_bytes()

        PUBLISHER.copy_private_config(self.config, destination, expected_uid=os.geteuid())

        metadata = destination.stat()
        self.assertEqual(destination.read_bytes(), expected)
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)

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

    def test_reviewed_toolchain_overlay_is_hash_bound_and_limited_to_package_manifests(self):
        stage = self.root / "release"
        source_worker = ROOT / "worker-allow-ip"
        staged_worker = stage / "worker-allow-ip"
        staged_worker.mkdir(parents=True)
        marker = staged_worker / "src" / "worker-entry.js"
        marker.parent.mkdir()
        marker.write_text("reviewed source marker\n", encoding="ascii")
        for name in ("package.json", "package-lock.json"):
            (staged_worker / name).write_text("{}\n", encoding="ascii")

        attestation = PUBLISHER.overlay_reviewed_toolchain(ROOT, stage)

        self.assertEqual(marker.read_text(encoding="ascii"), "reviewed source marker\n")
        self.assertEqual(
            attestation,
            {
                "package.json": PUBLISHER.REVIEWED_TOOLCHAIN_SHA256["package.json"],
                "package-lock.json": PUBLISHER.REVIEWED_TOOLCHAIN_SHA256["package-lock.json"],
            },
        )
        for name, expected_hash in attestation.items():
            self.assertEqual((staged_worker / name).read_bytes(), (source_worker / name).read_bytes())
            self.assertEqual(PUBLISHER.sha256_file(staged_worker / name), expected_hash)

    def test_reviewed_toolchain_overlay_rejects_any_manifest_drift(self):
        source_worker = self.root / "source" / "worker-allow-ip"
        staged_worker = self.root / "release" / "worker-allow-ip"
        source_worker.mkdir(parents=True)
        staged_worker.mkdir(parents=True)
        for name in ("package.json", "package-lock.json"):
            payload = (ROOT / "worker-allow-ip" / name).read_bytes()
            (source_worker / name).write_bytes(payload)
            (staged_worker / name).write_text("{}\n", encoding="ascii")
        with (source_worker / "package-lock.json").open("ab") as lock:
            lock.write(b"\n")

        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "hash does not match"):
            PUBLISHER.overlay_reviewed_toolchain(self.root / "source", self.root / "release")

    def test_reviewed_toolchain_reader_rejects_unsafe_files_and_malformed_json(self):
        missing = self.root / "missing.json"
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "unavailable"):
            PUBLISHER._read_reviewed_toolchain(missing, "0" * 64)

        source = self.root / "source.json"
        source.write_text("{}\n", encoding="ascii")
        linked = self.root / "linked.json"
        os.link(source, linked)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "single-link"):
            PUBLISHER._read_reviewed_toolchain(source, "0" * 64)
        linked.unlink()

        with source.open("wb") as oversized:
            oversized.truncate(PUBLISHER.MAX_TOOLCHAIN_BYTES + 1)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "too large"):
            PUBLISHER._read_reviewed_toolchain(source, "0" * 64)

        source.write_text("{}\n", encoding="ascii")
        with (
            mock.patch.object(PUBLISHER.os, "open", side_effect=OSError("denied")),
            self.assertRaisesRegex(PUBLISHER.LocalPublishError, "could not be opened"),
        ):
            PUBLISHER._read_reviewed_toolchain(source, "0" * 64)

        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "valid JSON"):
            PUBLISHER._validate_reviewed_toolchain(b"{", b"{}")

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

    def test_apply_mode_validates_remote_secret_names_before_one_publish(self):
        runner = RecordingRunner()
        PUBLISHER.run_publish_plan(
            self.root / "release",
            PUBLISHER.release_spec("compatibility"),
            pathlib.Path("/opt/node/bin/node"),
            pathlib.Path("/home/operator"),
            apply=True,
            runner=runner,
        )

        joined = [" ".join(call) for call in runner.calls]
        self.assertEqual(sum(" secret list " in f" {call} " for call in joined), 1)
        self.assertEqual(sum(" deploy --config " in f" {call} " for call in joined), 1)
        self.assertLess(
            next(index for index, call in enumerate(joined) if " secret list " in f" {call} "),
            next(index for index, call in enumerate(joined) if " deploy --config " in f" {call} "),
        )

    def test_ambiguous_publish_is_not_reported_as_an_ordinary_gate_failure(self):
        runner = RecordingRunner(fail_deploy=True)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, r"^remote_outcome_unknown\b"):
            PUBLISHER.run_publish_plan(
                self.root / "release",
                PUBLISHER.release_spec("compatibility"),
                pathlib.Path("/opt/node/bin/node"),
                pathlib.Path("/home/operator"),
                apply=True,
                runner=runner,
            )

        joined = [" ".join(call) for call in runner.calls]
        self.assertEqual(sum(" deploy --config " in f" {call} " for call in joined), 1)

    def test_local_preflight_failure_is_not_misclassified_as_remote_unknown(self):
        runner = RecordingRunner(fail_npm_ci=True)
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, r"^local Worker publish gate failed$"):
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

    def test_environment_and_version_pins_fail_closed(self):
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "must be absolute"):
            PUBLISHER.build_wrangler_environment(pathlib.Path("node"), pathlib.Path("/home/operator"))
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "Node.js 22"):
            PUBLISHER.verify_node_version("not-a-version")
        with self.assertRaisesRegex(PUBLISHER.LocalPublishError, "locked Wrangler"):
            PUBLISHER.verify_node_and_wrangler("v24.15.0", "4.111.0")

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

    def test_cli_rejects_explicit_check_combined_with_apply(self):
        stderr = io.StringIO()
        with (
            contextlib.redirect_stderr(stderr),
            mock.patch.object(PUBLISHER.os, "geteuid", return_value=0),
            self.assertRaises(SystemExit) as raised,
        ):
            PUBLISHER.main(["check", "--apply"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("cannot be combined", stderr.getvalue())

    def test_cli_check_and_apply_select_the_expected_staged_operation(self):
        for arguments, expected_apply, expected_message in (
            (["check"], False, "no Worker was published"),
            (["--apply"], True, "local Worker publish completed"),
        ):
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as temporary:
                output = io.StringIO()
                with (
                    mock.patch.object(PUBLISHER, "run_staged_publish") as staged_publish,
                    contextlib.redirect_stdout(output),
                ):
                    result = PUBLISHER.main([
                        *arguments,
                        "--node", str(NODE),
                        "--home", temporary,
                        "--wrangler-config", str(self.config),
                    ])

                self.assertEqual(result, 0)
                self.assertIn(expected_message, output.getvalue())
                self.assertEqual(staged_publish.call_args.kwargs["apply"], expected_apply)

    def test_cli_rejects_unknown_arguments(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                PUBLISHER.main(["--unknown"])
        self.assertEqual(raised.exception.code, 2)

    def test_staged_publish_removes_worktree_when_toolchain_overlay_fails(self):
        stage = self.root / "release"
        with (
            mock.patch.object(PUBLISHER, "stage_release") as stage_release,
            mock.patch.object(
                PUBLISHER,
                "overlay_reviewed_toolchain",
                side_effect=PUBLISHER.LocalPublishError("toolchain rejected"),
            ),
            mock.patch.object(PUBLISHER, "remove_stage") as remove_stage,
            self.assertRaisesRegex(PUBLISHER.LocalPublishError, "toolchain rejected"),
        ):
            PUBLISHER.run_staged_publish(
                ROOT,
                stage,
                PUBLISHER.release_spec("compatibility"),
                self.config,
                pathlib.Path("/opt/node/bin/node"),
                pathlib.Path("/home/operator"),
                apply=False,
            )

        stage_release.assert_called_once()
        remove_stage.assert_called_once_with(ROOT, stage, runner=subprocess.run)

    def test_staged_publish_runs_every_gate_then_removes_the_worktree(self):
        stage = self.root / "release"
        with (
            mock.patch.object(PUBLISHER, "stage_release") as stage_release,
            mock.patch.object(PUBLISHER, "overlay_reviewed_toolchain") as overlay,
            mock.patch.object(PUBLISHER, "copy_private_config") as copy_config,
            mock.patch.object(PUBLISHER, "run_publish_plan") as publish_plan,
            mock.patch.object(PUBLISHER, "remove_stage") as remove_stage,
        ):
            PUBLISHER.run_staged_publish(
                ROOT,
                stage,
                PUBLISHER.release_spec("compatibility"),
                self.config,
                pathlib.Path("/opt/node/bin/node"),
                pathlib.Path("/home/operator"),
                apply=False,
            )

        stage_release.assert_called_once()
        overlay.assert_called_once()
        copy_config.assert_called_once()
        publish_plan.assert_called_once()
        remove_stage.assert_called_once()

    def test_cli_preconditions_fail_closed_without_staging(self):
        cases = (
            ([], {"euid": 0}, "OAuth-owning operator"),
            (["--node", str(self.root / "missing-node")], {"euid": os.geteuid()}, "unavailable"),
            (["--node", str(NODE), "--home", "."], {"euid": os.geteuid()}, "OAuth home"),
        )
        for extra, options, expected in cases:
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                stderr = io.StringIO()
                with (
                    mock.patch.object(PUBLISHER.os, "geteuid", return_value=options["euid"]),
                    mock.patch.object(PUBLISHER, "run_staged_publish") as staged,
                    contextlib.redirect_stderr(stderr),
                ):
                    result = PUBLISHER.main([
                        *extra,
                        "--home", temporary,
                        "--wrangler-config", str(self.config),
                    ] if "--home" not in extra else [*extra, "--wrangler-config", str(self.config)])
                self.assertEqual(result, 1)
                self.assertIn(expected, stderr.getvalue())
                staged.assert_not_called()


class RecordingRunner:
    def __init__(
        self,
        *,
        fail_secret_list=False,
        fail_deploy=False,
        fail_npm_ci=False,
        node_version="v24.15.0\n",
    ):
        self.fail_secret_list = fail_secret_list
        self.fail_deploy = fail_deploy
        self.fail_npm_ci = fail_npm_ci
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
        if self.fail_npm_ci and "npm" in pathlib.Path(command[0]).name and "ci" in command:
            return subprocess.CompletedProcess(command, 1, "", "private error")
        if self.fail_deploy and "deploy" in command and "--dry-run" not in command:
            return subprocess.CompletedProcess(command, 1, "", "private error")
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
