import importlib.util
import contextlib
import io
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
import urllib.parse
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "recover-worker-admin.py"
SPEC = importlib.util.spec_from_file_location("worker_admin_recovery", SCRIPT)
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)


class RecoveryRunner:
    VERSION_ID = "11111111-1111-4111-8111-111111111111"
    DEPLOYMENT_ID = "22222222-2222-4222-8222-222222222222"

    def __init__(
        self,
        required_secrets,
        *,
        version_readback_matches=True,
        deployment_readback_matches=True,
        upload_returncode=0,
        deploy_returncode=0,
        write_upload_output=True,
        write_deploy_output=True,
        version_readback_failures=0,
        deployment_readback_failures=0,
    ):
        self.calls = []
        self.events = []
        self.required_secrets = required_secrets
        self.secret_file = None
        self.version_readback_matches = version_readback_matches
        self.deployment_readback_matches = deployment_readback_matches
        self.upload_returncode = upload_returncode
        self.deploy_returncode = deploy_returncode
        self.write_upload_output = write_upload_output
        self.write_deploy_output = write_deploy_output
        self.version_readback_failures = version_readback_failures
        self.deployment_readback_failures = deployment_readback_failures

    def __call__(self, arguments, **kwargs):
        command = tuple(map(str, arguments))
        self.calls.append((command, kwargs))
        self.events.append(command)
        if command[-1:] == ("--version",):
            return subprocess.CompletedProcess(command, 0, "4.112.0\n", "")
        if "secret" in command and "list" in command:
            payload = [{"name": name, "type": "secret_text"} for name in self.required_secrets]
            return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")
        if "versions" in command and "upload" in command:
            self.secret_file = pathlib.Path(command[command.index("--secrets-file") + 1])
            self.assert_private_secret_file(self.secret_file)
            if self.write_upload_output:
                pathlib.Path(kwargs["env"]["WRANGLER_OUTPUT_FILE_PATH"]).write_text(
                    json.dumps({
                        "type": "version-upload",
                        "version": 1,
                        "version_id": self.VERSION_ID,
                    }) + "\n",
                    encoding="ascii",
                )
            return subprocess.CompletedProcess(command, self.upload_returncode, "", "private detail")
        elif "versions" in command and "view" in command:
            if self.version_readback_failures > 0:
                self.version_readback_failures -= 1
                return subprocess.CompletedProcess(command, 1, "", "private detail")
            bindings = [{"name": name, "type": "secret_text"} for name in self.required_secrets]
            return subprocess.CompletedProcess(command, 0, json.dumps({
                "id": self.VERSION_ID,
                "annotations": {
                    "workers/tag": RECOVERY.RECOVERY_TAG if self.version_readback_matches else "unexpected-version",
                    "workers/message": RECOVERY.RECOVERY_MESSAGE,
                },
                "resources": {"bindings": bindings},
            }), "")
        elif "versions" in command and "deploy" in command:
            if self.write_deploy_output:
                pathlib.Path(kwargs["env"]["WRANGLER_OUTPUT_FILE_PATH"]).write_text(
                    json.dumps({
                        "type": "version-deploy",
                        "version": 1,
                        "deployment_id": self.DEPLOYMENT_ID,
                    }) + "\n",
                    encoding="ascii",
                )
            return subprocess.CompletedProcess(command, self.deploy_returncode, "", "private detail")
        elif "deployments" in command and "status" in command:
            if self.deployment_readback_failures > 0:
                self.deployment_readback_failures -= 1
                return subprocess.CompletedProcess(command, 1, "", "private detail")
            return subprocess.CompletedProcess(command, 0, json.dumps({
                "id": self.DEPLOYMENT_ID if self.deployment_readback_matches else "33333333-3333-4333-8333-333333333333",
                "annotations": {"workers/message": RECOVERY.RECOVERY_MESSAGE},
                "versions": [{"version_id": self.VERSION_ID, "percentage": 100}],
            }), "")
        return subprocess.CompletedProcess(command, 0, "", "")

    def assert_private_secret_file(self, path):
        metadata = path.stat()
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise AssertionError("Secret file is not mode-0600")
        document = json.loads(path.read_text(encoding="ascii"))
        if set(document) != {"ADMIN_PASSWORD_PBKDF2", "ADMIN_TOTP_SECRET"}:
            raise AssertionError("unexpected Secret file fields")
        if not document["ADMIN_PASSWORD_PBKDF2"].startswith("pbkdf2_sha256$310000$"):
            raise AssertionError("password record is not protected")
        if document["ADMIN_TOTP_SECRET"] != "JBSWY3DPEHPK3PXP":
            raise AssertionError("TOTP seed was not normalized")


def prepare_recovery_stage(stage, required_secrets):
    worker = pathlib.Path(stage) / "worker-allow-ip"
    worker.mkdir()
    config = worker / "wrangler.private.jsonc"
    config.write_text(json.dumps({
        "vars": {
            "ADMIN_USERNAME": "admin-test-user",
            "SUB2API_DEFAULT_BASE_URL": "https://api.example.test/v1",
        },
    }), encoding="ascii")
    config.chmod(0o600)
    (worker / "required-secrets.json").write_text(
        json.dumps({"version": 1, "required": sorted(required_secrets)}) + "\n",
        encoding="ascii",
    )
    return worker


class WorkerAdminRecoveryTests(unittest.TestCase):
    def test_low_level_json_file_identifier_and_command_boundaries_fail_closed(self):
        failed = lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", "private detail")
        with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "gate failed"):
            RECOVERY.run(["false"], env={}, runner=failed)
        for payload in ('{"duplicate":1,"duplicate":2}', "x" * (RECOVERY.MAX_WRANGLER_JSON_BYTES + 1)):
            with self.subTest(payload_length=len(payload)), self.assertRaises(RECOVERY.AdminRecoveryError):
                RECOVERY._parse_json(payload, "test JSON")
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "manifest is unavailable"):
                RECOVERY._required_secret_names(root / "missing.json")
            existing = root / "existing"
            existing.write_text("occupied", encoding="ascii")
            with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "could not be created"):
                RECOVERY._create_private_file(existing)
            with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "output is unavailable"):
                RECOVERY._read_wrangler_output(root / "missing-output", "version-upload")
            invalid_manifest = root / "invalid-manifest.json"
            invalid_manifest.write_text("[]\n", encoding="ascii")
            with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "manifest is invalid"):
                RECOVERY._required_secret_names(invalid_manifest)
        with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "ID is invalid"):
            RECOVERY._validated_identifier("not-an-id", "version ID")

    def test_private_file_write_failure_removes_the_partial_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "recovery-secret.json"
            with (
                mock.patch.object(RECOVERY.os, "write", side_effect=OSError("disk failure")),
                self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "could not be created"),
            ):
                RECOVERY._create_private_file(target, b"private-test-sentinel")
            self.assertFalse(target.exists())

    def test_private_file_fsync_failure_removes_the_partial_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = pathlib.Path(temporary) / "recovery-secret.json"
            with (
                mock.patch.object(RECOVERY.os, "fsync", side_effect=OSError("disk failure")),
                self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "could not be created"),
            ):
                RECOVERY._create_private_file(target, b"private-test-sentinel")
            self.assertFalse(target.exists())

    def test_later_temporary_file_creation_failure_removes_the_secret_file(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(required_secrets)
        original_create = RECOVERY._create_private_file
        create_count = 0

        def fail_second_create(path, payload=b""):
            nonlocal create_count
            create_count += 1
            if create_count == 2:
                raise RECOVERY.AdminRecoveryError("injected temporary file failure")
            return original_create(path, payload)

        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)
            with (
                mock.patch.object(RECOVERY, "_create_private_file", side_effect=fail_second_create),
                self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "injected temporary file failure"),
            ):
                RECOVERY.publish_recovery_version(
                    stage,
                    "local-test-password-with-sufficient-length",
                    "JBSWY3DPEHPK3PXP",
                    pathlib.Path("/opt/node/bin/node"),
                    env={"HOME": "/home/operator"},
                    runner=runner,
                    login_prover=lambda *_args: None,
                )
            self.assertEqual(list(stage.glob(".admin-recovery-secrets-*.json")), [])

        self.assertEqual(runner.calls, [])

    def test_cleanup_attempts_every_temporary_file_after_one_unlink_fails(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        original_unlink = pathlib.Path.unlink
        attempted = []

        def fail_first_unlink(path, *args, **kwargs):
            attempted.append(path.name)
            if len(attempted) == 1:
                raise OSError("injected cleanup failure")
            return original_unlink(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)
            with (
                mock.patch.object(
                    RECOVERY,
                    "check_secret_names_at",
                    side_effect=RECOVERY.AdminRecoveryError("injected pre-upload failure"),
                ),
                mock.patch.object(pathlib.Path, "unlink", autospec=True, side_effect=fail_first_unlink),
                self.assertRaisesRegex(
                    RECOVERY.AdminRecoveryError,
                    "injected pre-upload failure.*temporary file cleanup failed",
                ),
            ):
                RECOVERY.publish_recovery_version(
                    stage,
                    "local-test-password-with-sufficient-length",
                    "JBSWY3DPEHPK3PXP",
                    pathlib.Path("/opt/node/bin/node"),
                    env={"HOME": "/home/operator"},
                    runner=RecoveryRunner(required_secrets),
                    login_prover=lambda *_args: None,
                )

            self.assertEqual(len(attempted), 3)
            self.assertEqual(list(stage.glob(".wrangler-*.json")), [])
            self.assertEqual(len(list(stage.glob(".admin-recovery-secrets-*.json"))), 1)

    def test_successful_recovery_reports_cleanup_failure_and_keeps_cleaning(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        original_unlink = pathlib.Path.unlink
        attempted = []
        failed_upload_cleanup = False

        def fail_upload_output_unlink(path, *args, **kwargs):
            nonlocal failed_upload_cleanup
            attempted.append(path.name)
            if path.name.startswith(".wrangler-upload-") and not failed_upload_cleanup:
                failed_upload_cleanup = True
                raise OSError("injected cleanup failure")
            return original_unlink(path, *args, **kwargs)

        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)
            with (
                mock.patch.object(
                    pathlib.Path,
                    "unlink",
                    autospec=True,
                    side_effect=fail_upload_output_unlink,
                ),
                self.assertRaisesRegex(
                    RECOVERY.AdminRecoveryError,
                    "^administrator recovery temporary file cleanup failed$",
                ),
            ):
                RECOVERY.publish_recovery_version(
                    stage,
                    "local-test-password-with-sufficient-length",
                    "JBSWY3DPEHPK3PXP",
                    pathlib.Path("/opt/node/bin/node"),
                    env={"HOME": "/home/operator"},
                    runner=RecoveryRunner(required_secrets),
                    login_prover=lambda *_args: None,
                )

            upload_attempt = next(
                index for index, name in enumerate(attempted) if name.startswith(".wrangler-upload-")
            )
            deploy_attempt = next(
                index for index, name in enumerate(attempted) if name.startswith(".wrangler-deploy-")
            )
            self.assertLess(upload_attempt, deploy_attempt)
            self.assertEqual(len(list(stage.glob(".wrangler-upload-*.json"))), 1)
            self.assertEqual(list(stage.glob(".wrangler-deploy-*.json")), [])
            self.assertEqual(list(stage.glob(".admin-recovery-secrets-*.json")), [])

    def test_seed_normalization_matches_worker_boundary(self):
        self.assertEqual(RECOVERY.validate_seed(" jbswy3dpehpk3pxp "), "JBSWY3DPEHPK3PXP")
        for invalid in ("A" * 15, "A" * 129, "INVALID-CHARACTERS"):
            with self.subTest(invalid=invalid), self.assertRaises(RECOVERY.AdminRecoveryError):
                RECOVERY.validate_seed(invalid)

    def test_password_record_uses_strong_pbkdf2_and_does_not_reuse_input(self):
        record = RECOVERY.password_record("local-test-password-with-sufficient-length")
        self.assertRegex(record, r"^pbkdf2_sha256\$310000\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$")
        self.assertNotIn("local-test-password", record)
        with self.assertRaises(RECOVERY.AdminRecoveryError):
            RECOVERY.password_record("too-short")

    def test_login_proof_requires_303_and_a_strict_secure_session_cookie(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = pathlib.Path(temporary) / "wrangler.private.jsonc"
            config.write_text(json.dumps({
                "vars": {
                    "ADMIN_USERNAME": "admin-test-user",
                    "SUB2API_DEFAULT_BASE_URL": "https://api.example.test/v1",
                },
            }), encoding="ascii")
            config.chmod(0o600)
            connection = LoginConnection(LoginResponse(
                303,
                [
                    ("Location", "/allow-ip/admin"),
                    (
                        "Set-Cookie",
                        "sub2api_allow_admin=" + "a" * 64
                        + "; Path=/allow-ip/admin; Max-Age=604800; HttpOnly; Secure; SameSite=Strict",
                    ),
                ],
            ))

            RECOVERY.prove_admin_login(
                config,
                "local-test-password-with-sufficient-length",
                "JBSWY3DPEHPK3PXP",
                connection_factory=connection.factory,
                now=1_700_000_000,
            )

        self.assertEqual(connection.host, "api.example.test")
        self.assertEqual(connection.path, "/allow-ip/admin")
        fields = urllib.parse.parse_qs(connection.body.decode("ascii"), strict_parsing=True)
        self.assertEqual(fields["action"], ["login"])
        self.assertEqual(fields["username"], ["admin-test-user"])
        self.assertEqual(fields["password"], ["local-test-password-with-sufficient-length"])
        self.assertRegex(fields["token"][0], r"^\d{6}$")
        self.assertTrue(connection.closed)

        for status, headers in (
            (200, connection.response.headers),
            (303, [("Location", "/allow-ip/admin"), ("Set-Cookie", "sub2api_allow_admin=" + "b" * 64 + "; Secure; HttpOnly")]),
            (303, [
                ("Location", "/allow-ip/admin"),
                (
                    "Set-Cookie",
                    "sub2api_allow_admin=" + "c" * 64
                    + "; Path=/allow-ip/admin; Max-Age=604800; Secure; HttpOnly; SameSite=Lax; SameSite=Strict",
                ),
            ]),
        ):
            with self.subTest(status=status, headers=headers), tempfile.TemporaryDirectory() as temporary:
                config = pathlib.Path(temporary) / "wrangler.private.jsonc"
                config.write_text(json.dumps({
                    "vars": {
                        "ADMIN_USERNAME": "admin-test-user",
                        "SUB2API_DEFAULT_BASE_URL": "https://api.example.test/v1",
                    },
                }), encoding="ascii")
                config.chmod(0o600)
                failing = LoginConnection(LoginResponse(status, headers))
                with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "login proof failed"):
                    RECOVERY.prove_admin_login(
                        config,
                        "local-test-password-with-sufficient-length",
                        "JBSWY3DPEHPK3PXP",
                        connection_factory=failing.factory,
                        now=1_700_000_000,
                    )

    def test_login_configuration_and_cookie_shapes_fail_closed(self):
        documents = (
            "not-json",
            json.dumps({"vars": {}}),
            json.dumps({"vars": {
                "ADMIN_USERNAME": "admin",
                "SUB2API_DEFAULT_BASE_URL": "https://api.example.test:bad/v1",
            }}),
            json.dumps({"vars": {
                "ADMIN_USERNAME": "admin",
                "SUB2API_DEFAULT_BASE_URL": "http://api.example.test/v1",
            }}),
        )
        for document in documents:
            with self.subTest(document=document), tempfile.TemporaryDirectory() as temporary:
                config = pathlib.Path(temporary) / "wrangler.private.jsonc"
                config.write_text(document, encoding="ascii")
                config.chmod(0o600)
                with self.assertRaises(RECOVERY.AdminRecoveryError):
                    RECOVERY._recovery_login_settings(config)
        cookie = "sub2api_allow_admin=" + "a" * 64 + "; Path=/allow-ip/admin; Max-Age=604800; HttpOnly; Secure; SameSite=Strict"
        self.assertFalse(RECOVERY._validate_login_cookie([("Set-Cookie", cookie), ("Set-Cookie", cookie)]))
        self.assertFalse(RECOVERY._validate_login_cookie([("Set-Cookie", "sub2api_allow_admin=invalid; Secure")]))

    def test_recovery_uploads_and_deploys_one_attested_version_before_login_proof(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(required_secrets)
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            worker = prepare_recovery_stage(stage, required_secrets)
            events = runner.events

            def login_prover(config, password, seed):
                self.assertEqual(config, worker / "wrangler.private.jsonc")
                self.assertEqual(password, "local-test-password-with-sufficient-length")
                self.assertEqual(seed, "JBSWY3DPEHPK3PXP")
                events.append("login-proof")

            result = RECOVERY.publish_recovery_version(
                stage,
                "local-test-password-with-sufficient-length",
                "JBSWY3DPEHPK3PXP",
                pathlib.Path("/opt/node/bin/node"),
                env={"HOME": "/home/operator"},
                runner=runner,
                login_prover=login_prover,
            )

        commands = [call[0] for call in runner.calls]
        joined = "\n".join(" ".join(command) for command in commands)
        self.assertNotIn(" secret bulk ", f" {joined} ")
        self.assertNotIn("local-test-password", joined)
        self.assertNotIn("JBSWY3DPEHPK3PXP", joined)
        command_inputs = "\n".join(str(call[1].get("input") or "") for call in runner.calls)
        self.assertNotIn("local-test-password", command_inputs)
        self.assertNotIn("JBSWY3DPEHPK3PXP", command_inputs)
        self.assertIn(" versions upload ", f" {joined} ")
        self.assertIn("--secrets-file", joined)
        self.assertIn("--strict", joined)
        self.assertIn(f"{RecoveryRunner.VERSION_ID}@100%", joined)
        self.assertFalse(runner.secret_file.exists())
        self.assertEqual(result["version_id"], RecoveryRunner.VERSION_ID)
        self.assertEqual(result["deployment_id"], RecoveryRunner.DEPLOYMENT_ID)
        upload_position = next(index for index, event in enumerate(events) if isinstance(event, tuple) and "upload" in event)
        view_position = next(index for index, event in enumerate(events) if isinstance(event, tuple) and "view" in event)
        deploy_position = next(index for index, event in enumerate(events) if isinstance(event, tuple) and "deploy" in event)
        status_position = next(index for index, event in enumerate(events) if isinstance(event, tuple) and "status" in event)
        self.assertLess(upload_position, view_position)
        self.assertLess(view_position, deploy_position)
        self.assertLess(deploy_position, status_position)
        self.assertEqual(events[-1], "login-proof")

    def test_nonzero_deploy_continues_after_exact_structured_readback(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(required_secrets, deploy_returncode=1)
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            worker = prepare_recovery_stage(stage, required_secrets)
            login_proved = False

            def login_prover(_config, _password, _seed):
                nonlocal login_proved
                login_proved = True

            result = RECOVERY.publish_recovery_version(
                stage,
                "local-test-password-with-sufficient-length",
                "JBSWY3DPEHPK3PXP",
                pathlib.Path("/opt/node/bin/node"),
                env={"HOME": "/home/operator"},
                runner=runner,
                login_prover=login_prover,
            )

        self.assertTrue(login_proved)
        self.assertEqual(result["deployment_id"], RecoveryRunner.DEPLOYMENT_ID)

    def test_nonzero_upload_continues_after_exact_structured_readback(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(required_secrets, upload_returncode=1)
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)

            result = RECOVERY.publish_recovery_version(
                stage,
                "local-test-password-with-sufficient-length",
                "JBSWY3DPEHPK3PXP",
                pathlib.Path("/opt/node/bin/node"),
                env={"HOME": "/home/operator"},
                runner=runner,
                login_prover=lambda *_args: None,
            )

        commands = [call[0] for call in runner.calls]
        self.assertTrue(any("versions" in command and "deploy" in command for command in commands))
        self.assertEqual(result["version_id"], RecoveryRunner.VERSION_ID)

    def test_unproven_upload_raises_stable_unknown_without_deploying(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(
            required_secrets,
            upload_returncode=1,
            write_upload_output=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)

            with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, r"^remote_outcome_unknown\b"):
                RECOVERY.publish_recovery_version(
                    stage,
                    "local-test-password-with-sufficient-length",
                    "JBSWY3DPEHPK3PXP",
                    pathlib.Path("/opt/node/bin/node"),
                    env={"HOME": "/home/operator"},
                    runner=runner,
                    login_prover=lambda *_args: None,
                )

        commands = [call[0] for call in runner.calls]
        self.assertFalse(any("versions" in command and "deploy" in command for command in commands))

    def test_invalid_uploaded_version_id_raises_stable_unknown(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(required_secrets)
        runner.VERSION_ID = "not-a-version-id"
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)
            with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, r"^remote_outcome_unknown\b"):
                RECOVERY.publish_recovery_version(
                    stage,
                    "local-test-password-with-sufficient-length",
                    "JBSWY3DPEHPK3PXP",
                    pathlib.Path("/opt/node/bin/node"),
                    env={"HOME": "/home/operator"},
                    runner=runner,
                    login_prover=lambda *_args: None,
                )

    def test_unproven_deploy_raises_stable_unknown_without_login_proof(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(
            required_secrets,
            deploy_returncode=1,
            write_deploy_output=False,
        )
        login_proved = False
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)

            def login_prover(*_args):
                nonlocal login_proved
                login_proved = True

            with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, r"^remote_outcome_unknown\b"):
                RECOVERY.publish_recovery_version(
                    stage,
                    "local-test-password-with-sufficient-length",
                    "JBSWY3DPEHPK3PXP",
                    pathlib.Path("/opt/node/bin/node"),
                    env={"HOME": "/home/operator"},
                    runner=runner,
                    login_prover=login_prover,
                )

        self.assertFalse(login_proved)

    def test_transient_version_readback_is_reconciled_without_reuploading(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(required_secrets, version_readback_failures=1)
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)

            result = RECOVERY.publish_recovery_version(
                stage,
                "local-test-password-with-sufficient-length",
                "JBSWY3DPEHPK3PXP",
                pathlib.Path("/opt/node/bin/node"),
                env={"HOME": "/home/operator"},
                runner=runner,
                login_prover=lambda *_args: None,
                sleeper=lambda _seconds: None,
            )

        commands = [call[0] for call in runner.calls]
        self.assertEqual(sum("versions" in command and "upload" in command for command in commands), 1)
        self.assertEqual(sum("versions" in command and "view" in command for command in commands), 2)
        self.assertEqual(result["version_id"], RecoveryRunner.VERSION_ID)

    def test_transient_deployment_readback_is_reconciled_without_redeploying(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(required_secrets, deployment_readback_failures=1)
        login_proved = False
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            prepare_recovery_stage(stage, required_secrets)

            def login_prover(*_args):
                nonlocal login_proved
                login_proved = True

            result = RECOVERY.publish_recovery_version(
                stage,
                "local-test-password-with-sufficient-length",
                "JBSWY3DPEHPK3PXP",
                pathlib.Path("/opt/node/bin/node"),
                env={"HOME": "/home/operator"},
                runner=runner,
                login_prover=login_prover,
                sleeper=lambda _seconds: None,
            )

        commands = [call[0] for call in runner.calls]
        self.assertEqual(sum("versions" in command and "deploy" in command for command in commands), 1)
        self.assertEqual(sum("deployments" in command and "status" in command for command in commands), 2)
        self.assertTrue(login_proved)
        self.assertEqual(result["deployment_id"], RecoveryRunner.DEPLOYMENT_ID)

    def test_attestation_mismatches_stop_before_the_next_irreversible_step(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        for mismatch, expected_deploy in (("version", False), ("deployment", True)):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as temporary:
                stage = pathlib.Path(temporary)
                prepare_recovery_stage(stage, required_secrets)
                runner = RecoveryRunner(
                    required_secrets,
                    version_readback_matches=mismatch != "version",
                    deployment_readback_matches=mismatch != "deployment",
                )
                login_called = False

                def login_prover(_config, _password, _seed):
                    nonlocal login_called
                    login_called = True

                with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, r"^remote_outcome_unknown\b"):
                    RECOVERY.publish_recovery_version(
                        stage,
                        "local-test-password-with-sufficient-length",
                        "JBSWY3DPEHPK3PXP",
                        pathlib.Path("/opt/node/bin/node"),
                        env={"HOME": "/home/operator"},
                        runner=runner,
                        login_prover=login_prover,
                        sleeper=lambda _seconds: None,
                    )

                commands = [call[0] for call in runner.calls]
                deployed = any("versions" in command and "deploy" in command for command in commands)
                self.assertEqual(deployed, expected_deploy)
                self.assertFalse(login_called)
                self.assertFalse(runner.secret_file.exists())

    def test_recovery_attestation_binds_the_full_source_and_toolchain_hashes(self):
        self.assertLessEqual(len(RECOVERY.RECOVERY_MESSAGE), 120)
        self.assertIn(RECOVERY.RECOVERY_RELEASE, RECOVERY.RECOVERY_MESSAGE)
        self.assertIn(RECOVERY.TOOLCHAIN_DIGEST, RECOVERY.RECOVERY_MESSAGE)

    def test_candidate_removes_worktree_when_a_local_gate_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = pathlib.Path(temporary) / "wrangler.private.jsonc"
            config.write_text("{}\n", encoding="ascii")
            config.chmod(0o600)
            with (
                mock.patch.object(RECOVERY.PUBLISHER, "stage_release") as stage_release,
                mock.patch.object(RECOVERY.PUBLISHER, "overlay_reviewed_toolchain"),
                mock.patch.object(RECOVERY.PUBLISHER, "copy_private_config"),
                mock.patch.object(
                    RECOVERY.PUBLISHER,
                    "run_publish_plan",
                    side_effect=RECOVERY.PUBLISHER.LocalPublishError("local gate failed"),
                ),
                mock.patch.object(RECOVERY.PUBLISHER, "remove_stage") as remove_stage,
                self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "candidate gate failed"),
            ):
                RECOVERY.run_recovery_candidate(
                    None,
                    None,
                    pathlib.Path("/opt/node/bin/node"),
                    pathlib.Path("/home/operator"),
                    config,
                    apply=False,
                )

        stage_release.assert_called_once()
        remove_stage.assert_called_once()

    def test_candidate_source_failure_and_recover_wrapper_fail_closed(self):
        with (
            mock.patch.object(
                RECOVERY.PUBLISHER,
                "stage_release",
                side_effect=RECOVERY.PUBLISHER.LocalPublishError("source unavailable"),
            ),
            mock.patch.object(RECOVERY.PUBLISHER, "remove_stage") as remove_stage,
            self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "source gate failed"),
        ):
            RECOVERY.run_recovery_candidate(
                None,
                None,
                pathlib.Path("/opt/node/bin/node"),
                pathlib.Path("/home/operator"),
                pathlib.Path("/private/config"),
                apply=False,
            )
        remove_stage.assert_not_called()

        with mock.patch.object(RECOVERY, "run_recovery_candidate", return_value={"ok": True}) as candidate:
            result = RECOVERY.recover(
                "local-test-password-with-sufficient-length",
                "JBSWY3DPEHPK3PXP",
                pathlib.Path("/opt/node/bin/node"),
                home=pathlib.Path("/home/operator"),
            )
        self.assertEqual(result, {"ok": True})
        self.assertTrue(candidate.call_args.kwargs["apply"])

    def test_private_input_validation_rejects_short_passwords_and_bad_seeds(self):
        with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "at least 16"):
            RECOVERY._validate_private_inputs("short", "JBSWY3DPEHPK3PXP")
        with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "Base32"):
            RECOVERY._validate_private_inputs("long-enough-password", "bad-seed")

    def test_oversized_password_is_rejected_before_any_remote_command(self):
        with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "at most 4096 characters"):
            RECOVERY.password_record("x" * 4097)

    def test_encoded_login_form_budget_is_enforced_before_remote_commands(self):
        required_secrets = {
            "TURNSTILE_SECRET_KEY",
            "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2",
            "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY",
            "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        }
        runner = RecoveryRunner(required_secrets)
        with tempfile.TemporaryDirectory() as temporary:
            stage = pathlib.Path(temporary)
            worker = stage / "worker-allow-ip"
            worker.mkdir()
            (worker / "wrangler.private.jsonc").write_text(json.dumps({
                "vars": {
                    "ADMIN_USERNAME": "admin-test-user",
                    "SUB2API_DEFAULT_BASE_URL": "https://api.example.test/v1",
                },
            }), encoding="ascii")
            (worker / "wrangler.private.jsonc").chmod(0o600)
            (worker / "required-secrets.json").write_text(
                json.dumps({"version": 1, "required": sorted(required_secrets)}) + "\n",
                encoding="ascii",
            )

            with self.assertRaisesRegex(RECOVERY.AdminRecoveryError, "login form exceeds 32 KiB"):
                RECOVERY.publish_recovery_version(
                    stage,
                    "\N{GRINNING FACE}" * 3000,
                    "JBSWY3DPEHPK3PXP",
                    pathlib.Path("/opt/node/bin/node"),
                    env={"HOME": "/home/operator"},
                    runner=runner,
                    login_prover=lambda *_args: None,
                )

        self.assertEqual(runner.calls, [])

    def test_cli_check_runs_only_the_local_candidate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = root / "wrangler.private.jsonc"
            config.write_text("{}\n", encoding="ascii")
            config.chmod(0o600)
            output = io.StringIO()
            with (
                mock.patch.object(RECOVERY, "run_recovery_candidate", return_value=None) as candidate,
                contextlib.redirect_stdout(output),
            ):
                result = RECOVERY.main([
                    "check",
                    "--node", "/usr/bin/node",
                    "--home", str(root),
                    "--wrangler-config", str(config),
                ])

        self.assertEqual(result, 0)
        self.assertIn("no Worker Secret was read or changed", output.getvalue())
        call = candidate.call_args
        self.assertEqual(call.args[:2], (None, None))
        self.assertFalse(call.kwargs["apply"])

    def test_cli_apply_uses_private_prompts_and_requires_the_full_proof_path(self):
        password = "local-test-password-with-sufficient-length"
        seed = "JBSWY3DPEHPK3PXP"
        answers = iter((password, password, seed, seed))
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = root / "wrangler.private.jsonc"
            config.write_text("{}\n", encoding="ascii")
            config.chmod(0o600)
            output = io.StringIO()
            errors = io.StringIO()
            with (
                mock.patch.object(RECOVERY, "run_recovery_candidate", return_value={}) as candidate,
                contextlib.redirect_stdout(output),
                contextlib.redirect_stderr(errors),
            ):
                result = RECOVERY.main(
                    [
                        "--apply",
                        "--node", "/usr/bin/node",
                        "--home", str(root),
                        "--wrangler-config", str(config),
                    ],
                    input_func=lambda _prompt: "RESET ADMIN ACCESS",
                    getpass_func=lambda _prompt: next(answers),
                    tty_streams=(PrivateTty(), PrivateTty(), PrivateTty()),
                )

        self.assertEqual(result, 0)
        self.assertIn("fresh administrator login proof passed", output.getvalue())
        self.assertNotIn(password, output.getvalue() + errors.getvalue())
        self.assertNotIn(seed, output.getvalue() + errors.getvalue())
        call = candidate.call_args
        self.assertEqual(call.args[:2], (password, seed))
        self.assertTrue(call.kwargs["apply"])

    def test_cli_rejects_conflicting_modes_and_unknown_arguments(self):
        for arguments in (("check", "--apply"), ("--unknown",)):
            with self.subTest(arguments=arguments):
                with contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as raised:
                        RECOVERY.main(list(arguments))
                self.assertEqual(raised.exception.code, 2)

    def test_cli_private_tty_home_and_confirmation_failures_do_not_stage(self):
        password = "local-test-password-with-sufficient-length"
        seed = "JBSWY3DPEHPK3PXP"
        scenarios = (
            ({"tty_streams": (PrivateTty(False), PrivateTty(), PrivateTty())}, (), "private local operator TTY"),
            ({"input_func": lambda _prompt: "NO"}, (), "not confirmed"),
            ({"input_func": lambda _prompt: "RESET ADMIN ACCESS", "getpass_func": sequence_getpass(password, "different")}, (), "do not match"),
            ({"input_func": lambda _prompt: "RESET ADMIN ACCESS", "getpass_func": sequence_getpass(password, password, seed, "different")}, (), "do not match"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            config = root / "wrangler.private.jsonc"
            config.write_text("{}\n", encoding="ascii")
            config.chmod(0o600)
            base = ["--apply", "--node", "/usr/bin/node", "--home", str(root), "--wrangler-config", str(config)]
            for kwargs, extra, expected in scenarios:
                with self.subTest(expected=expected):
                    stderr = io.StringIO()
                    defaults = {
                        "tty_streams": (PrivateTty(), PrivateTty(), PrivateTty()),
                        "input_func": lambda _prompt: "RESET ADMIN ACCESS",
                        "getpass_func": sequence_getpass(password, password, seed, seed),
                    }
                    defaults.update(kwargs)
                    with (
                        mock.patch.object(RECOVERY, "run_recovery_candidate") as candidate,
                        contextlib.redirect_stderr(stderr),
                    ):
                        result = RECOVERY.main([*base, *extra], **defaults)
                    self.assertEqual(result, 1)
                    self.assertIn(expected, stderr.getvalue())
                    candidate.assert_not_called()

            stderr = io.StringIO()
            with mock.patch.object(RECOVERY, "run_recovery_candidate") as candidate, contextlib.redirect_stderr(stderr):
                result = RECOVERY.main([
                    "check", "--node", "/usr/bin/node", "--home", ".", "--wrangler-config", str(config),
                ])
            self.assertEqual(result, 1)
            self.assertIn("must be absolute", stderr.getvalue())
            candidate.assert_not_called()

class LoginResponse:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers

    def getheaders(self):
        return self.headers

    def read(self, _size):
        return b""


class LoginConnection:
    def __init__(self, response):
        self.response = response
        self.host = None
        self.path = None
        self.body = None
        self.headers = None
        self.closed = False

    def factory(self, host, _port, **_kwargs):
        self.host = host
        return self

    def request(self, method, path, body=None, headers=None):
        self.path = path
        self.body = body
        self.headers = headers
        self.method = method

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class PrivateTty:
    def __init__(self, enabled=True):
        self.enabled = enabled

    def isatty(self):
        return self.enabled


def sequence_getpass(*answers):
    iterator = iter(answers)
    return lambda _prompt: next(iterator)


if __name__ == "__main__":
    unittest.main()
