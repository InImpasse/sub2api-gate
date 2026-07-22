import importlib.util
import json
import pathlib
import os
import subprocess
import tempfile
import unittest


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
        if command[1:3] == ["secret", "list"]:
            if not self.secret_lists:
                raise AssertionError("unexpected secret list request")
            value = self.secret_lists.pop(0)
            if isinstance(value, int):
                return subprocess.CompletedProcess(command, value, "", "private error")
            payload = json.dumps([{"name": name, "type": "secret_text"} for name in value])
            return subprocess.CompletedProcess(command, 0, payload, "")
        if command[1:3] == ["secret", "bulk"]:
            return subprocess.CompletedProcess(
                command,
                self.bulk_returncode,
                "remote output",
                "remote private error",
            )
        raise AssertionError(f"unexpected command: {command}")

    @property
    def bulk_calls(self):
        return [call for call in self.calls if call[0][1:3] == ["secret", "bulk"]]


class WorkerSecretInitializerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(self.temp.name)
        self.wrangler = root / "worker" / "node_modules" / ".bin" / "wrangler"
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

    def test_wrangler_environment_cannot_import_managed_secret_values(self):
        source = {
            "CLOUDFLARE_API_TOKEN": "test-only-cloudflare-token",
            "CLOUDFLARE_INCLUDE_PROCESS_ENV": "true",
            "CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV": "true",
            **{name: "must-not-survive" for name in SECRET_TOOL.MANAGED_SECRET_NAMES},
        }
        environment = SECRET_TOOL.build_wrangler_environment(source)
        self.assertEqual(
            environment["CLOUDFLARE_API_TOKEN"],
            "test-only-cloudflare-token",
        )
        self.assertEqual(environment["CLOUDFLARE_INCLUDE_PROCESS_ENV"], "false")
        self.assertEqual(
            environment["CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV"],
            "false",
        )
        for name in SECRET_TOOL.MANAGED_SECRET_NAMES:
            self.assertNotIn(name, environment)


if __name__ == "__main__":
    unittest.main()
