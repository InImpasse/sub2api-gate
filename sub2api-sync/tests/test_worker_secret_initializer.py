import importlib.util
import json
import pathlib
import os
import sys
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).parents[2]
SCRIPT = ROOT / "deploy" / "generate-worker-secrets.py"
SPEC = importlib.util.spec_from_file_location("worker_secret_initializer", SCRIPT)
SECRET_TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SECRET_TOOL)


class FakeRunner:
    def __init__(self, secret_lists, *, bulk_returncode=0):
        self.secret_lists = list(secret_lists)
        self.bulk_returncode = bulk_returncode
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), dict(kwargs)))
        if command[-1:] == ["check"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[2:4] == ["secret", "list"]:
            if not self.secret_lists:
                raise AssertionError("unexpected secret list request")
            value = self.secret_lists.pop(0)
            if isinstance(value, int):
                return subprocess.CompletedProcess(command, value, "", "private error")
            payload = json.dumps([{"name": name, "type": "secret_text"} for name in value])
            return subprocess.CompletedProcess(command, 0, payload, "")
        if command[2:4] == ["secret", "bulk"]:
            return subprocess.CompletedProcess(
                command,
                self.bulk_returncode,
                "remote output",
                "remote private error",
            )
        raise AssertionError(f"unexpected command: {command}")

    @property
    def bulk_calls(self):
        return [call for call in self.calls if call[0][2:4] == ["secret", "bulk"]]


class WorkerSecretInitializerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temp.name)
        self.wrangler = (
            root / "worker" / "node_modules" / "wrangler" / "bin" / "wrangler.js"
        )
        self.wrangler.parent.mkdir(parents=True)
        self.wrangler.touch()
        self.config = root / "worker" / "wrangler.private.jsonc"
        self.config.write_text("{}\n", encoding="utf-8")
        self.guard = root / "require-clean-worktree.sh"
        self.state = (
            root
            / ".local"
            / "worker-secret-state"
            / "invite-access-hmac-migration.key"
        )
        self.manifest = root / "required-secrets.json"
        self.manifest.write_text(
            json.dumps({"version": 1, "required": [
                "TURNSTILE_SECRET_KEY",
                *SECRET_TOOL.MANAGED_SECRET_NAMES,
            ]}),
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def initialize(self, runner, password_reader=None):
        kwargs = {
            "runner": runner,
            "wrangler": self.wrangler,
            "wrangler_config": self.config,
            "manifest_path": self.manifest,
            "release_guard": self.guard,
            "child_env": {"WRANGLER_SEND_METRICS": "false"},
            "hmac_state_path": self.state,
            "expected_uid": os.geteuid(),
        }
        if password_reader is not None:
            kwargs["password_reader"] = password_reader
        return SECRET_TOOL.initialize_missing_secrets(**kwargs)

    def test_rerun_does_not_prompt_or_overwrite_existing_managed_secrets(self):
        runner = FakeRunner([set(SECRET_TOOL.MANAGED_SECRET_NAMES)])

        def reject_prompt(_):
            raise AssertionError("password prompt must not run on a no-op rerun")

        initialized = self.initialize(runner, reject_prompt)
        self.assertEqual(initialized, ())
        self.assertEqual(runner.bulk_calls, [])
        self.assertEqual(len(runner.secret_lists), 0)

    def test_partial_initialization_uses_one_bulk_stdin_without_overwriting(self):
        existing = {"ADMIN_PASSWORD_PBKDF2"}
        complete = set(SECRET_TOOL.MANAGED_SECRET_NAMES)
        runner = FakeRunner([existing, existing, complete])

        def reject_prompt(_):
            raise AssertionError("existing admin password must not be requested")

        initialized = self.initialize(runner, reject_prompt)
        self.assertEqual(
            initialized,
            ("CREDENTIAL_ENCRYPTION_KEY", "INVITE_ACCESS_HMAC_KEY"),
        )
        self.assertEqual(len(runner.bulk_calls), 1)
        payload = json.loads(runner.bulk_calls[0][1]["input"])
        self.assertEqual(set(payload), set(initialized))
        self.assertNotIn("ADMIN_PASSWORD_PBKDF2", payload)
        self.assertEqual(self.state.read_text(), payload["INVITE_ACCESS_HMAC_KEY"] + "\n")
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.parent.stat().st_mode & 0o777, 0o700)
        self.assertNotIn(payload["CREDENTIAL_ENCRYPTION_KEY"], self.state.read_text())

    def test_concurrent_remote_hmac_creation_fails_closed_and_destroys_local_state(self):
        complete = set(SECRET_TOOL.MANAGED_SECRET_NAMES)
        runner = FakeRunner([set(), complete])
        prompts = []

        def password_reader(prompt):
            prompts.append(prompt)
            return "correct horse battery staple"

        with self.assertRaisesRegex(
            SECRET_TOOL.SecretInitializationError,
            "controlled rotation is required",
        ):
            self.initialize(runner, password_reader)
        self.assertEqual(len(prompts), 2)
        self.assertEqual(runner.bulk_calls, [])
        self.assertFalse(self.state.exists())

    def test_remote_list_failure_stops_before_prompt_or_bulk(self):
        runner = FakeRunner([1])

        def reject_prompt(_):
            raise AssertionError("password prompt must not follow a list failure")

        with self.assertRaisesRegex(
            SECRET_TOOL.SecretInitializationError,
            "could not list remote Worker Secret names",
        ):
            self.initialize(runner, reject_prompt)
        self.assertEqual(runner.bulk_calls, [])

    def test_bulk_failure_is_generic_and_never_replays_values(self):
        runner = FakeRunner([set(), set()], bulk_returncode=1)

        with self.assertRaisesRegex(
            SECRET_TOOL.SecretInitializationError,
            "bulk secret initialization failed",
        ) as raised:
            self.initialize(runner, lambda _: "correct horse battery staple")
        self.assertNotIn("correct horse", str(raised.exception))
        self.assertNotIn(self.state.read_text().strip(), str(raised.exception))
        self.assertEqual(len(runner.bulk_calls), 1)
        self.assertTrue(self.state.is_file())

    def test_post_write_name_verification_is_required(self):
        runner = FakeRunner([set(), set(), set()])
        with self.assertRaisesRegex(
            SECRET_TOOL.SecretInitializationError,
            "name verification failed",
        ):
            self.initialize(runner, lambda _: "correct horse battery staple")
        self.assertTrue(self.state.is_file())

    def test_existing_remote_hmac_is_never_recreated_when_state_is_missing(self):
        runner = FakeRunner([set(SECRET_TOOL.MANAGED_SECRET_NAMES)])
        self.assertEqual(self.initialize(runner), ())
        self.assertFalse(self.state.exists())

    def test_password_rejection_happens_before_hmac_state_creation(self):
        runner = FakeRunner([set()])
        passwords = iter(("long-password-one", "long-password-two"))
        with self.assertRaisesRegex(
            SECRET_TOOL.SecretInitializationError,
            "passwords do not match",
        ):
            self.initialize(runner, lambda _: next(passwords))
        self.assertFalse(self.state.exists())
        self.assertEqual(runner.bulk_calls, [])

    def test_hmac_state_symlink_is_rejected_without_changing_its_target(self):
        self.state.parent.mkdir(mode=0o700, parents=True)
        target = pathlib.Path(self.temp.name) / "target"
        target.write_text("x" * 64 + "\n")
        self.state.symlink_to(target)
        runner = FakeRunner([set(), set()])
        with self.assertRaisesRegex(
            SECRET_TOOL.SecretInitializationError,
            "unsafe|single-link",
        ):
            self.initialize(runner, lambda _: "correct horse battery staple")
        self.assertEqual(target.read_text(), "x" * 64 + "\n")

    def test_failed_upload_state_is_reused_verbatim_on_retry(self):
        failed = FakeRunner([set(), set()], bulk_returncode=1)
        with self.assertRaises(SECRET_TOOL.SecretInitializationError):
            self.initialize(failed, lambda _: "correct horse battery staple")
        retained = self.state.read_text().strip()

        complete = set(SECRET_TOOL.MANAGED_SECRET_NAMES)
        retry = FakeRunner([set(), set(), complete])
        initialized = self.initialize(
            retry,
            lambda _: "correct horse battery staple",
        )
        payload = json.loads(retry.bulk_calls[0][1]["input"])
        self.assertIn("INVITE_ACCESS_HMAC_KEY", initialized)
        self.assertEqual(payload["INVITE_ACCESS_HMAC_KEY"], retained)

    def test_hmac_state_check_uses_trusted_git_and_minimal_environment(self):
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, "", "")

        child_environment = {"PATH": "/usr/bin", "HOME": "/root"}
        SECRET_TOOL.require_ignored_state_path(
            self.temp.name,
            pathlib.Path(self.temp.name) / ".local" / "state",
            runner=runner,
            child_env=child_environment,
        )
        command, kwargs = calls.pop()
        self.assertEqual(command[0], "/usr/bin/git")
        self.assertEqual(kwargs["env"], child_environment)

    def test_wrangler_environment_is_a_minimal_allowlist(self):
        source = {
            "CLOUDFLARE_API_TOKEN": "must-not-survive",
            "DOCKER_HOST": "tcp://untrusted.invalid:2375",
            "NODE_OPTIONS": "--require=/tmp/untrusted.js",
            **{name: "must-not-survive" for name in SECRET_TOOL.MANAGED_SECRET_NAMES},
        }
        environment = SECRET_TOOL.build_wrangler_environment(source)
        expected = {
            "PATH": SECRET_TOOL.SAFE_WRANGLER_PATH,
            "HOME": "/root",
            "WRANGLER_SEND_METRICS": "false",
            "CLOUDFLARE_INCLUDE_PROCESS_ENV": "false",
            "CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV": "false",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
        }
        self.assertEqual(environment, expected)

    def test_apply_rejects_untrusted_tree_before_wrangler_runs(self):
        result = subprocess.run(
            [sys.executable, SCRIPT, "--apply"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trusted production release tree", result.stderr)

    def test_apply_context_precedes_wrangler_execution(self):
        source = SCRIPT.read_text(encoding="utf-8")
        main = source.split("def main(argv=None):", 1)[1]
        self.assertLess(
            main.index("require_production_apply_context"),
            main.index("version = subprocess.run"),
        )
        self.assertIn("env=child_env", main)


    def test_apply_context_rejects_each_missing_tty_before_release_validation(self):
        class Tty:
            def __init__(self, available):
                self.available = available

            def isatty(self):
                return self.available

        trusted_root = pathlib.Path("/trusted-worker-release")
        config = trusted_root / SECRET_TOOL.PRIVATE_WRANGLER_CONFIG_RELATIVE_PATH
        for missing in range(3):
            streams = tuple(Tty(index != missing) for index in range(3))
            with self.subTest(missing=missing), mock.patch.object(
                SECRET_TOOL.os, "geteuid", return_value=0
            ), mock.patch.object(
                SECRET_TOOL, "TRUSTED_RELEASE_ROOT", trusted_root
            ), mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                SECRET_TOOL, "require_trusted_release_tree"
            ) as trusted_tree:
                with self.assertRaisesRegex(
                    SECRET_TOOL.SecretInitializationError, "private interactive TTY"
                ):
                    SECRET_TOOL.require_production_apply_context(
                        trusted_root,
                        config,
                        streams=streams,
                    )
            trusted_tree.assert_not_called()

    def test_trusted_release_gate_binds_controller_guard_and_private_config(self):
        trusted_root = pathlib.Path("/trusted-worker-release")
        source = trusted_root / SECRET_TOOL.SECRET_INITIALIZER_SOURCE_RELATIVE_PATH
        guard = trusted_root / SECRET_TOOL.RELEASE_GUARD_RELATIVE_PATH
        attestor = trusted_root / SECRET_TOOL.RUNTIME_ATTESTOR_RELATIVE_PATH
        config = trusted_root / SECRET_TOOL.PRIVATE_WRANGLER_CONFIG_RELATIVE_PATH
        with mock.patch.object(
            SECRET_TOOL, "_require_trusted_release_path"
        ) as path_gate, mock.patch.object(
            SECRET_TOOL, "_require_trusted_private_wrangler_config"
        ) as config_gate:
            SECRET_TOOL.require_trusted_release_tree(
                trusted_root,
                config,
                source_path=source,
                release_guard=guard,
                trusted_root=trusted_root,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )

        expected_entries = (
            (SECRET_TOOL.TRUSTED_FILESYSTEM_ROOT, True, False, False),
            (trusted_root.parent, True, False, False),
            (trusted_root, True, False, False),
            *((trusted_root / value, True, False, False)
              for value in SECRET_TOOL.TRUSTED_RELEASE_DIRECTORIES),
            (source, False, False, True),
            (guard, False, True, True),
            (attestor, False, False, True),
        )
        self.assertEqual(
            path_gate.call_args_list,
            [
                mock.call(
                    path,
                    expects_directory=expects_directory,
                    expects_executable=expects_executable,
                    expects_single_link=expects_single_link,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )
                for path, expects_directory, expects_executable, expects_single_link
                in expected_entries
            ],
        )
        config_gate.assert_called_once_with(
            config,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )

    def test_private_wrangler_config_rejects_hardlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = root / "wrangler.private.jsonc"
            config.write_text("{}\n", encoding="utf-8")
            config.chmod(0o600)
            alias = root / "wrangler.private.alias"
            os.link(config, alias)
            with self.assertRaisesRegex(
                SECRET_TOOL.SecretInitializationError, "single-link mode-0600"
            ):
                SECRET_TOOL._require_trusted_private_wrangler_config(
                    config,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )


if __name__ == "__main__":
    unittest.main()
