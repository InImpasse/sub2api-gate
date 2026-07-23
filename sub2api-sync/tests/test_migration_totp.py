import concurrent.futures
import contextlib
import importlib.util
import io
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
HELPER_PATH = ROOT / "deploy" / "verify-migration-totp.py"


def load_helper():
    spec = importlib.util.spec_from_file_location("migration_totp", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MigrationTotpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()

    def test_default_verifier_and_replay_files_stay_in_private_directory(self):
        private_directory = pathlib.Path("/mnt/data/sub2api-gate/private")

        self.assertEqual(self.helper.DEFAULT_VERIFIER_PATH.parent, private_directory)
        lock_path, state_path = self.helper._replay_paths(
            self.helper.DEFAULT_VERIFIER_PATH
        )
        self.assertEqual(lock_path.parent, private_directory)
        self.assertEqual(state_path.parent, private_directory)

    def test_rfc6238_sha1_vectors(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        vectors = (
            (59, "94287082"),
            (1111111109, "07081804"),
            (1111111111, "14050471"),
            (1234567890, "89005924"),
            (2000000000, "69279037"),
            (20000000000, "65353130"),
        )
        for timestamp, expected in vectors:
            with self.subTest(timestamp=timestamp):
                self.assertEqual(
                    self.helper.totp(secret, timestamp, digits=8),
                    expected,
                )

    def test_base32_decode_matches_worker_for_every_residue_length(self):
        vectors = (
            ("ABCDEFGHIJKLMNOP", "00443214c74254b635cf"),
            ("ABCDEFGHIJKLMNOPQ", "00443214c74254b635cf"),
            ("ABCDEFGHIJKLMNOPQR", "00443214c74254b635cf84"),
            ("ABCDEFGHIJKLMNOPQRS", "00443214c74254b635cf84"),
            ("ABCDEFGHIJKLMNOPQRST", "00443214c74254b635cf8465"),
            ("ABCDEFGHIJKLMNOPQRSTU", "00443214c74254b635cf84653a"),
            ("ABCDEFGHIJKLMNOPQRSTUV", "00443214c74254b635cf84653a"),
            ("ABCDEFGHIJKLMNOPQRSTUVW", "00443214c74254b635cf84653a56"),
        )
        for secret, expected_hex in vectors:
            with self.subTest(length=len(secret), residue=len(secret) % 8):
                self.assertEqual(
                    self.helper.decode_base32_secret(secret),
                    bytes.fromhex(expected_hex),
                )

    def test_base32_decode_matches_worker_case_and_trim_normalization(self):
        canonical = "JBSWY3DPEHPK3PXP"
        expected = self.helper.decode_base32_secret(canonical)
        variants = (
            canonical.lower(),
            " \t\r\n" + canonical.lower() + "\v\f ",
            "\ufeff\u00a0" + canonical.lower() + "\u3000\u2029",
        )
        for secret in variants:
            with self.subTest(secret=repr(secret)):
                self.assertEqual(self.helper.decode_base32_secret(secret), expected)

    def test_base32_decode_rejects_text_the_worker_does_not_normalize(self):
        invalid_secrets = (
            "JBSWY3DP\nEHPK3PXP",
            "JBSWY3DPEHPK3PXP=",
            "JBSWY3DPEHPK3PX0",
            "JBSWY3DPEHPK3PX1",
            "Ä" * 16,
            "\u001cJBSWY3DPEHPK3PXP\u001c",
            "\u0085JBSWY3DPEHPK3PXP\u0085",
        )
        for secret in invalid_secrets:
            with self.subTest(secret=repr(secret)), self.assertRaises(ValueError):
                self.helper.decode_base32_secret(secret)

    def test_verification_accepts_only_current_or_adjacent_window(self):
        secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        for offset in (-30, 0, 30):
            code = self.helper.totp(secret, now + offset)
            self.assertTrue(self.helper.verify_totp(secret, code, now=now))
        outside = self.helper.totp(secret, now + 60)
        self.assertFalse(self.helper.verify_totp(secret, outside, now=now))

    def test_enrolled_admin_secret_rejects_a_different_self_selected_seed_and_code(self):
        registered_secret = "JBSWY3DPEHPK3PXP"
        attacker_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        verifier = self.helper.build_registered_secret_verifier(
            registered_secret,
            salt=b"0123456789abcdef",
        )

        self.assertTrue(
            self.helper.verify_registered_totp(
                verifier,
                registered_secret,
                self.helper.totp(registered_secret, now),
                now=now,
            )
        )
        self.assertFalse(
            self.helper.verify_registered_totp(
                verifier,
                attacker_secret,
                self.helper.totp(attacker_secret, now),
                now=now,
            )
        )

    def test_registered_admin_seed_uses_the_worker_length_boundary(self):
        self.assertEqual(len(self.helper.decode_base32_secret("A" * 16)), 10)
        self.assertEqual(len(self.helper.decode_base32_secret("A" * 128)), 80)
        for secret in ("A" * 15, "A" * 129):
            with self.subTest(length=len(secret)), self.assertRaises(ValueError):
                self.helper.build_registered_secret_verifier(
                    secret,
                    salt=b"0123456789abcdef",
                )

    def test_verifier_rejects_json_boolean_version_confusion(self):
        secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        verifier = self.helper.build_registered_secret_verifier(
            secret,
            salt=b"0123456789abcdef",
        )
        verifier["version"] = True

        self.assertFalse(
            self.helper.verify_registered_totp(
                verifier,
                secret,
                self.helper.totp(secret, now),
                now=now,
            )
        )

    def test_verifier_file_rejects_duplicate_json_keys(self):
        verifier = self.helper.build_registered_secret_verifier(
            "JBSWY3DPEHPK3PXP",
            salt=b"0123456789abcdef",
        )
        serialized = json.dumps(verifier, sort_keys=True, separators=(",", ":"))
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            verifier_path.write_text(
                '{"version":99,' + serialized[1:] + "\n",
                encoding="ascii",
            )
            verifier_path.chmod(0o600)

            with self.assertRaises(self.helper.TotpVerificationError):
                self.helper.read_registered_secret_verifier(
                    verifier_path,
                    expected_uid=os.geteuid(),
                )

    def test_verifier_file_rejects_missing_unsafe_mode_symlink_and_hardlink(self):
        verifier = self.helper.build_registered_secret_verifier(
            "JBSWY3DPEHPK3PXP",
            salt=b"0123456789abcdef",
        )
        payload = json.dumps(verifier, sort_keys=True, separators=(",", ":")) + "\n"
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            root = pathlib.Path(directory)
            verifier_path = root / "admin-totp-verifier.json"

            with self.assertRaises(self.helper.TotpVerificationError):
                self.helper.read_registered_secret_verifier(
                    verifier_path,
                    expected_uid=os.geteuid(),
                )

            verifier_path.write_text(payload, encoding="ascii")
            verifier_path.chmod(0o640)
            with self.assertRaisesRegex(
                self.helper.TotpVerificationError,
                "unsafe",
            ):
                self.helper.read_registered_secret_verifier(
                    verifier_path,
                    expected_uid=os.geteuid(),
                )

            verifier_path.unlink()
            target = root / "verifier-target.json"
            target.write_text(payload, encoding="ascii")
            target.chmod(0o600)
            verifier_path.symlink_to(target)
            with self.assertRaises(self.helper.TotpVerificationError):
                self.helper.read_registered_secret_verifier(
                    verifier_path,
                    expected_uid=os.geteuid(),
                )

            verifier_path.unlink()
            os.link(target, verifier_path)
            with self.assertRaisesRegex(
                self.helper.TotpVerificationError,
                "unsafe",
            ):
                self.helper.read_registered_secret_verifier(
                    verifier_path,
                    expected_uid=os.geteuid(),
                )

    def test_explicit_enrollment_creates_a_private_bound_verifier(self):
        secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        code = self.helper.totp(secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            with mock.patch.object(
                self.helper.sys.stdin, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.sys.stderr, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.getpass, "getpass", side_effect=[secret, code]
            ):
                self.helper.enroll_interactive(
                    verifier_path,
                    now=now,
                    expected_uid=os.geteuid(),
                )

            metadata = verifier_path.stat(follow_symlinks=False)
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            verifier_payload = verifier_path.read_text(encoding="ascii")
            self.assertNotIn(secret, verifier_payload)
            self.assertNotIn(code, verifier_payload)
            with mock.patch.object(
                self.helper.sys.stdin, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.sys.stderr, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.getpass, "getpass", side_effect=[secret, code]
            ):
                self.helper.verify_interactive(
                    now=now,
                    verifier_path=verifier_path,
                    expected_uid=os.geteuid(),
                )

            attacker_secret = "KRSXG5DSNFXGOIDB"
            with mock.patch.object(
                self.helper.sys.stdin, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.sys.stderr, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.getpass,
                "getpass",
                side_effect=[attacker_secret, self.helper.totp(attacker_secret, now)],
            ):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "verification failed",
                ):
                    self.helper.verify_interactive(
                        now=now,
                        verifier_path=verifier_path,
                        expected_uid=os.geteuid(),
                    )

            second_prompt = mock.Mock()
            with mock.patch.object(
                self.helper.sys.stdin, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.sys.stderr, "isatty", return_value=True
            ), mock.patch.object(self.helper.getpass, "getpass", second_prompt):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "already exists",
                ):
                    self.helper.enroll_interactive(
                        verifier_path,
                        now=now,
                        expected_uid=os.geteuid(),
                    )
            second_prompt.assert_not_called()

    def test_enrollment_cli_is_check_only_without_explicit_apply(self):
        result = subprocess.run(
            [sys.executable, HELPER_PATH, "enroll", "check"],
            cwd=ROOT,
            input="",
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("check only", result.stdout)
        self.assertIn("no TOTP secret was read", result.stdout)

    def test_rotation_cli_is_check_only_without_explicit_apply(self):
        result = subprocess.run(
            [sys.executable, HELPER_PATH, "rotate", "check"],
            cwd=ROOT,
            input="",
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("check only", result.stdout)
        self.assertIn("no TOTP secret was read", result.stdout)
        self.assertIn("no verifier or replay state was written", result.stdout)

    def test_rotation_cli_requires_worker_verification_acknowledgement(self):
        secret = "JBSWY3DPEHPK3PXP"
        code = "123456"

        def invoke(arguments):
            stdout = io.StringIO()
            stderr = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = self.helper.main(arguments)
            return result, stdout.getvalue(), stderr.getvalue()

        result, stdout, stderr = invoke(["rotate", "--apply"])
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn("--worker-totp-verified", stderr)

        result, stdout, stderr = invoke(
            ["rotate", "--apply", "--worker-totp-verified", secret, code]
        )
        self.assertEqual(result, 2)
        self.assertEqual(stdout, "")
        self.assertIn("must not be supplied as arguments", stderr)
        self.assertNotIn(secret, stdout + stderr)
        self.assertNotIn(code, stdout + stderr)

    def test_rotation_apply_cli_fails_closed_without_tty(self):
        result = subprocess.run(
            [
                sys.executable,
                HELPER_PATH,
                "rotate",
                "--apply",
                "--worker-totp-verified",
            ],
            cwd=ROOT,
            input="",
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("interactive TTY", result.stderr)
        self.assertNotIn("Rotated admin TOTP", result.stderr)

    def test_rotation_apply_requires_private_tty_before_prompting(self):
        prompt = mock.Mock()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            self.helper.sys.stdin, "isatty", return_value=False
        ), mock.patch.object(
            self.helper.sys.stderr, "isatty", return_value=False
        ), mock.patch.object(
            self.helper.getpass, "getpass", prompt
        ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = self.helper.main(
                ["rotate", "--apply", "--worker-totp-verified"]
            )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("interactive TTY", stderr.getvalue())
        prompt.assert_not_called()

    def test_rotation_validates_existing_verifier_before_prompting(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            verifier_path.write_text("{}\n", encoding="ascii")
            verifier_path.chmod(0o600)
            prompt = mock.Mock()

            with mock.patch.object(
                self.helper.sys.stdin, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.sys.stderr, "isatty", return_value=True
            ), mock.patch.object(self.helper.getpass, "getpass", prompt):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "registered TOTP verifier is invalid",
                ):
                    self.helper.rotate_interactive(
                        verifier_path,
                        expected_uid=os.geteuid(),
                    )

            prompt.assert_not_called()

    def test_rotation_validates_existing_replay_state_before_prompting(self):
        secret = "JBSWY3DPEHPK3PXP"
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            state_path.write_text(
                '{"version":1,"last_counter":true}\n',
                encoding="ascii",
            )
            state_path.chmod(0o600)
            prompt = mock.Mock()

            with mock.patch.object(
                self.helper.sys.stdin, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.sys.stderr, "isatty", return_value=True
            ), mock.patch.object(self.helper.getpass, "getpass", prompt):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "replay state is invalid",
                ):
                    self.helper.rotate_interactive(
                        verifier_path,
                        expected_uid=os.geteuid(),
                    )

            prompt.assert_not_called()

    def test_rotation_from_absent_replay_state_consumes_the_new_code(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        rotated_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        rotated_code = self.helper.totp(rotated_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.assertFalse(state_path.exists())

            with mock.patch.object(
                self.helper.sys.stdin, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.sys.stderr, "isatty", return_value=True
            ), mock.patch.object(
                self.helper.getpass,
                "getpass",
                side_effect=[rotated_secret, rotated_code],
            ):
                self.helper.rotate_interactive(
                    verifier_path,
                    now=now,
                    expected_uid=os.geteuid(),
                )

            self.assertTrue(lock_path.is_file())
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
            self.assertEqual(
                json.loads(state_path.read_text(encoding="ascii")),
                {
                    "version": self.helper.REPLAY_STATE_VERSION,
                    "last_counter": int(now) // self.helper.TOTP_PERIOD_SECONDS,
                },
            )
            replacement = self.helper.read_registered_secret_verifier(
                verifier_path,
                expected_uid=os.geteuid(),
            )
            self.assertFalse(
                self.helper.verify_registered_totp(
                    replacement,
                    old_secret,
                    self.helper.totp(old_secret, now),
                    now=now,
                )
            )
            self.assertTrue(
                self.helper.verify_registered_totp(
                    replacement,
                    rotated_secret,
                    rotated_code,
                    now=now,
                )
            )
            self.assertNotIn(rotated_secret, verifier_path.read_text(encoding="ascii"))
            with self.assertRaisesRegex(
                self.helper.TotpVerificationError,
                "verification failed",
            ):
                self.helper.verify_and_consume_registered_totp(
                    verifier_path,
                    rotated_secret,
                    rotated_code,
                    now=now,
                    expected_uid=os.geteuid(),
                )

            self.helper.verify_and_consume_registered_totp(
                verifier_path,
                rotated_secret,
                self.helper.totp(
                    rotated_secret,
                    now + self.helper.TOTP_PERIOD_SECONDS,
                ),
                now=now + self.helper.TOTP_PERIOD_SECONDS,
                expected_uid=os.geteuid(),
            )

    def test_rotation_restores_original_bytes_after_handled_write_failure(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        rotated_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        old_code = self.helper.totp(old_secret, now)
        rotated_code = self.helper.totp(rotated_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.helper._write_last_consumed_counter(
                state_path,
                int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
            )
            verifier_before = verifier_path.read_bytes()
            state_before = state_path.read_bytes()
            real_replace = self.helper._replace_rotation_path
            replacements = 0

            def fail_verifier_publish(source, destination):
                nonlocal replacements
                replacements += 1
                if replacements == 2:
                    raise OSError("injected write failure")
                return real_replace(source, destination)

            with mock.patch.object(
                self.helper,
                "_replace_rotation_path",
                side_effect=fail_verifier_publish,
            ):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "could not be applied",
                ) as error:
                    self.helper.rotate_registered_totp(
                        verifier_path,
                        rotated_secret,
                        rotated_code,
                        now=now,
                        expected_uid=os.geteuid(),
                    )

            self.assertNotIn(rotated_secret, str(error.exception))
            self.assertNotIn(rotated_code, str(error.exception))
            self.assertEqual(verifier_path.read_bytes(), verifier_before)
            self.assertEqual(state_path.read_bytes(), state_before)
            self.assertFalse(
                self.helper.verify_registered_totp(
                    self.helper.read_registered_secret_verifier(
                        verifier_path,
                        expected_uid=os.geteuid(),
                    ),
                    rotated_secret,
                    rotated_code,
                    now=now,
                )
            )
            self.helper.verify_and_consume_registered_totp(
                verifier_path,
                old_secret,
                old_code,
                now=now,
                expected_uid=os.geteuid(),
            )
            self.assertFalse(
                any("rotation-" in child.name for child in pathlib.Path(directory).iterdir())
            )

    def test_rotation_rejects_the_existing_seed_without_consuming_it(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        old_code = self.helper.totp(old_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.helper._write_last_consumed_counter(
                state_path,
                int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
            )
            verifier_before = verifier_path.read_bytes()
            state_before = state_path.read_bytes()

            with self.assertRaisesRegex(
                self.helper.TotpVerificationError,
                "requires a new administrator seed",
            ):
                self.helper.rotate_registered_totp(
                    verifier_path,
                    old_secret,
                    old_code,
                    now=now,
                    expected_uid=os.geteuid(),
                )

            self.assertEqual(verifier_path.read_bytes(), verifier_before)
            self.assertEqual(state_path.read_bytes(), state_before)
            self.helper.verify_and_consume_registered_totp(
                verifier_path,
                old_secret,
                old_code,
                now=now,
                expected_uid=os.geteuid(),
            )

    def test_rotation_syncs_replay_state_before_publishing_verifier(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        rotated_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        rotated_code = self.helper.totp(rotated_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.helper._write_last_consumed_counter(
                state_path,
                int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
            )
            events = []
            real_replace = self.helper._replace_rotation_path
            real_fsync = self.helper._fsync_directory

            def record_replace(source, destination):
                destination = pathlib.Path(destination)
                events.append(
                    "state-replace"
                    if destination == state_path
                    else "verifier-replace"
                )
                return real_replace(source, destination)

            def record_fsync(directory_path):
                events.append("directory-fsync")
                return real_fsync(directory_path)

            with mock.patch.object(
                self.helper,
                "_replace_rotation_path",
                side_effect=record_replace,
            ), mock.patch.object(
                self.helper,
                "_fsync_directory",
                side_effect=record_fsync,
            ):
                self.helper.rotate_registered_totp(
                    verifier_path,
                    rotated_secret,
                    rotated_code,
                    now=now,
                    expected_uid=os.geteuid(),
                )

            state_index = events.index("state-replace")
            verifier_index = events.index("verifier-replace")
            self.assertLess(state_index, verifier_index)
            self.assertIn(
                "directory-fsync",
                events[state_index + 1:verifier_index],
            )

    def test_rotation_restores_after_replay_state_sync_failure(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        rotated_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        rotated_code = self.helper.totp(rotated_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.helper._write_last_consumed_counter(
                state_path,
                int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
            )
            verifier_before = verifier_path.read_bytes()
            state_before = state_path.read_bytes()
            real_fsync = self.helper._fsync_directory
            fsync_calls = 0

            def fail_after_state_publish(directory_path):
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 2:
                    raise OSError("injected fsync failure")
                return real_fsync(directory_path)

            with mock.patch.object(
                self.helper,
                "_fsync_directory",
                side_effect=fail_after_state_publish,
            ):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "could not be applied",
                ):
                    self.helper.rotate_registered_totp(
                        verifier_path,
                        rotated_secret,
                        rotated_code,
                        now=now,
                        expected_uid=os.geteuid(),
                    )

            self.assertEqual(verifier_path.read_bytes(), verifier_before)
            self.assertEqual(state_path.read_bytes(), state_before)
            self.assertFalse(
                any("rotation-" in child.name for child in pathlib.Path(directory).iterdir())
            )

    def test_restore_rotation_file_normalizes_temporary_cleanup_error(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            backup = pathlib.Path(directory) / "verifier.backup"
            destination = pathlib.Path(directory) / "verifier.json"
            backup.write_bytes(b"old-verifier")
            destination.write_bytes(b"new-verifier")
            os.chmod(backup, 0o600)
            os.chmod(destination, 0o600)
            cleanup_error = OSError("injected temporary cleanup failure")

            with mock.patch.object(
                self.helper.os,
                "replace",
                side_effect=OSError("injected restore failure"),
            ), mock.patch.object(
                self.helper,
                "_unlink_if_present",
                side_effect=cleanup_error,
            ):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "could not be rolled back safely",
                ) as error:
                    self.helper._restore_rotation_file(
                        backup,
                        destination,
                        expected_uid=os.geteuid(),
                    )
            self.assertIs(error.exception.__cause__, cleanup_error)
            self.assertEqual(backup.read_bytes(), b"old-verifier")
            self.assertEqual(destination.read_bytes(), b"new-verifier")

    def test_rotation_preserves_backups_when_staged_temporary_cleanup_fails(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        rotated_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        rotated_code = self.helper.totp(rotated_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.helper._write_last_consumed_counter(
                state_path,
                int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
            )
            verifier_before = verifier_path.read_bytes()
            state_before = state_path.read_bytes()
            real_replace = self.helper._replace_rotation_path
            replacements = 0

            def fail_verifier_publish(source, destination):
                nonlocal replacements
                replacements += 1
                if replacements == 2:
                    raise OSError("injected verifier publish failure")
                return real_replace(source, destination)

            real_unlink = self.helper._unlink_if_present

            def fail_staged_temporary_cleanup(path):
                if ".rotation-tmp-" in pathlib.Path(path).name:
                    raise OSError("injected staged temporary cleanup failure")
                return real_unlink(path)

            with mock.patch.object(
                self.helper,
                "_replace_rotation_path",
                side_effect=fail_verifier_publish,
            ), mock.patch.object(
                self.helper,
                "_unlink_if_present",
                side_effect=fail_staged_temporary_cleanup,
            ):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "recovery backups were preserved",
                ) as error:
                    self.helper.rotate_registered_totp(
                        verifier_path,
                        rotated_secret,
                        rotated_code,
                        now=now,
                        expected_uid=os.geteuid(),
                    )

            self.assertIsInstance(error.exception.__cause__, OSError)
            self.assertEqual(verifier_path.read_bytes(), verifier_before)
            self.assertEqual(state_path.read_bytes(), state_before)
            backups = sorted(
                child
                for child in pathlib.Path(directory).iterdir()
                if ".rotation-backup-" in child.name
            )
            self.assertEqual(len(backups), 2)
            backup_payloads = [backup.read_bytes() for backup in backups]
            self.assertIn(verifier_before, backup_payloads)
            self.assertIn(state_before, backup_payloads)

    def test_rotation_preserves_recovery_backups_if_rollback_fails(self):
        rotated_secret = "KRSXG5DSNFXGOIDB"
        old_secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        rotated_code = self.helper.totp(rotated_secret, now)
        for has_replay_state, rollback_error_type in (
            (False, self.helper.TotpVerificationError),
            (False, OSError),
            (True, self.helper.TotpVerificationError),
            (True, OSError),
        ):
            with self.subTest(
                has_replay_state=has_replay_state,
                rollback_error=rollback_error_type.__name__,
            ), tempfile.TemporaryDirectory() as directory:
                os.chmod(directory, 0o700)
                verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
                self.helper.write_registered_secret_verifier(
                    verifier_path,
                    self.helper.build_registered_secret_verifier(
                        old_secret,
                        salt=b"0123456789abcdef",
                    ),
                    expected_uid=os.geteuid(),
                )
                _lock_path, state_path = self.helper._replay_paths(verifier_path)
                verifier_before = verifier_path.read_bytes()
                state_before = None
                if has_replay_state:
                    self.helper._write_last_consumed_counter(
                        state_path,
                        int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
                    )
                    state_before = state_path.read_bytes()
                real_replace = self.helper._replace_rotation_path
                replacements = 0

                def fail_verifier_publish(source, destination):
                    nonlocal replacements
                    replacements += 1
                    if replacements == 2:
                        raise OSError("injected write failure")
                    return real_replace(source, destination)

                with mock.patch.object(
                    self.helper,
                    "_replace_rotation_path",
                    side_effect=fail_verifier_publish,
                ), mock.patch.object(
                    self.helper,
                    "_restore_rotation_file",
                    side_effect=rollback_error_type(
                        "injected rollback failure"
                    ),
                ):
                    with self.assertRaisesRegex(
                        self.helper.TotpVerificationError,
                        "recovery backups were preserved",
                    ) as error:
                        self.helper.rotate_registered_totp(
                            verifier_path,
                            rotated_secret,
                            rotated_code,
                            now=now,
                            expected_uid=os.geteuid(),
                        )

                self.assertNotIn(rotated_secret, str(error.exception))
                self.assertNotIn(rotated_code, str(error.exception))
                backups = sorted(
                    child
                    for child in pathlib.Path(directory).iterdir()
                    if ".rotation-backup-" in child.name
                )
                self.assertEqual(len(backups), 2 if has_replay_state else 1)
                self.assertTrue(
                    all(stat.S_IMODE(backup.stat().st_mode) == 0o600 for backup in backups)
                )
                self.assertTrue(
                    all(backup.stat().st_uid == os.geteuid() for backup in backups)
                )
                backup_payloads = [backup.read_bytes() for backup in backups]
                self.assertIn(verifier_before, backup_payloads)
                if state_before is not None:
                    self.assertIn(state_before, backup_payloads)
                self.assertFalse(
                    any(".rotation-tmp-" in child.name for child in pathlib.Path(directory).iterdir())
                )

    def test_rotation_preserves_backups_when_rollback_fsync_fails(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        rotated_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        rotated_code = self.helper.totp(rotated_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.helper._write_last_consumed_counter(
                state_path,
                int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
            )
            verifier_before = verifier_path.read_bytes()
            state_before = state_path.read_bytes()
            real_fsync = self.helper._fsync_directory
            fsync_calls = 0

            def fail_commit_and_rollback_sync(directory_path):
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls in (3, 4):
                    raise OSError("injected fsync failure")
                return real_fsync(directory_path)

            with mock.patch.object(
                self.helper,
                "_fsync_directory",
                side_effect=fail_commit_and_rollback_sync,
            ):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "recovery backups were preserved",
                ):
                    self.helper.rotate_registered_totp(
                        verifier_path,
                        rotated_secret,
                        rotated_code,
                        now=now,
                        expected_uid=os.geteuid(),
                    )

            self.assertEqual(verifier_path.read_bytes(), verifier_before)
            self.assertEqual(state_path.read_bytes(), state_before)
            backups = sorted(
                child
                for child in pathlib.Path(directory).iterdir()
                if ".rotation-backup-" in child.name
            )
            self.assertEqual(len(backups), 2)
            self.assertIn(verifier_before, [backup.read_bytes() for backup in backups])
            self.assertIn(state_before, [backup.read_bytes() for backup in backups])

    def test_rotation_preserves_backups_after_partial_restore_failure(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        rotated_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        rotated_code = self.helper.totp(rotated_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.helper._write_last_consumed_counter(
                state_path,
                int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
            )
            verifier_before = verifier_path.read_bytes()
            state_before = state_path.read_bytes()
            real_fsync = self.helper._fsync_directory
            fsync_calls = 0
            real_restore = self.helper._restore_rotation_file
            restore_calls = 0

            def fail_commit_sync(directory_path):
                nonlocal fsync_calls
                fsync_calls += 1
                if fsync_calls == 3:
                    raise OSError("injected fsync failure")
                return real_fsync(directory_path)

            def fail_state_restore(*args, **kwargs):
                nonlocal restore_calls
                restore_calls += 1
                if restore_calls == 2:
                    raise self.helper.TotpVerificationError(
                        "injected state restore failure"
                    )
                return real_restore(*args, **kwargs)

            with mock.patch.object(
                self.helper,
                "_fsync_directory",
                side_effect=fail_commit_sync,
            ), mock.patch.object(
                self.helper,
                "_restore_rotation_file",
                side_effect=fail_state_restore,
            ):
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "recovery backups were preserved",
                ):
                    self.helper.rotate_registered_totp(
                        verifier_path,
                        rotated_secret,
                        rotated_code,
                        now=now,
                        expected_uid=os.geteuid(),
                    )

            self.assertEqual(verifier_path.read_bytes(), verifier_before)
            self.assertNotEqual(state_path.read_bytes(), state_before)
            backups = sorted(
                child
                for child in pathlib.Path(directory).iterdir()
                if ".rotation-backup-" in child.name
            )
            self.assertEqual(len(backups), 2)
            self.assertIn(verifier_before, [backup.read_bytes() for backup in backups])
            self.assertIn(state_before, [backup.read_bytes() for backup in backups])

    def test_rotation_and_verification_share_the_replay_lock(self):
        old_secret = "JBSWY3DPEHPK3PXP"
        rotated_secret = "KRSXG5DSNFXGOIDB"
        now = 1_700_000_000
        old_code = self.helper.totp(old_secret, now)
        rotated_code = self.helper.totp(rotated_secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    old_secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            _lock_path, state_path = self.helper._replay_paths(verifier_path)
            self.helper._write_last_consumed_counter(
                state_path,
                int(now) // self.helper.TOTP_PERIOD_SECONDS - 1,
            )
            start_barrier = threading.Barrier(2)

            def rotate():
                start_barrier.wait(timeout=5)
                try:
                    self.helper.rotate_registered_totp(
                        verifier_path,
                        rotated_secret,
                        rotated_code,
                        now=now,
                        expected_uid=os.geteuid(),
                    )
                except self.helper.TotpVerificationError:
                    return False
                return True

            def verify():
                start_barrier.wait(timeout=5)
                try:
                    self.helper.verify_and_consume_registered_totp(
                        verifier_path,
                        old_secret,
                        old_code,
                        now=now,
                        expected_uid=os.geteuid(),
                    )
                except self.helper.TotpVerificationError:
                    return False
                return True

            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                rotation_future = executor.submit(rotate)
                verification_future = executor.submit(verify)
                rotation_result = rotation_future.result(timeout=10)
                verification_future.result(timeout=10)

            self.assertTrue(rotation_result)
            replacement = self.helper.read_registered_secret_verifier(
                verifier_path,
                expected_uid=os.geteuid(),
            )
            self.assertFalse(
                self.helper.verify_registered_totp(
                    replacement,
                    old_secret,
                    old_code,
                    now=now,
                )
            )
            with self.assertRaisesRegex(
                self.helper.TotpVerificationError,
                "verification failed",
            ):
                self.helper.verify_and_consume_registered_totp(
                    verifier_path,
                    rotated_secret,
                    rotated_code,
                    now=now,
                    expected_uid=os.geteuid(),
                )

    def test_invalid_secret_and_code_are_rejected_without_echoing_values(self):
        for secret, code in (
            ("not-base32!", "123456"),
            ("JBSWY3DPEHPK3PXP", "12345"),
            ("JBSWY3DPEHPK3PXP", "abcdef"),
        ):
            with self.subTest(secret=secret, code=code):
                self.assertFalse(self.helper.verify_totp(secret, code, now=0))

        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    "JBSWY3DPEHPK3PXP",
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            with mock.patch.object(self.helper.sys.stdin, "isatty", return_value=True), \
                 mock.patch.object(self.helper.sys.stderr, "isatty", return_value=True), \
                 mock.patch.object(
                     self.helper.getpass,
                     "getpass",
                     side_effect=["JBSWY3DPEHPK3PXP", "000000"],
                 ):
                with self.assertRaisesRegex(self.helper.TotpVerificationError, "verification failed") as error:
                    self.helper.verify_interactive(
                        now=1_700_000_000,
                        verifier_path=verifier_path,
                        expected_uid=os.geteuid(),
                    )
        self.assertNotIn("JBSWY3DPEHPK3PXP", str(error.exception))
        self.assertNotIn("000000", str(error.exception))

    def test_failed_code_does_not_consume_the_totp_counter(self):
        secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        valid_code = self.helper.totp(secret, now)
        valid_window_codes = {
            self.helper.totp(secret, now + offset)
            for offset in (-30, 0, 30)
        }
        invalid_code = next(
            str(candidate).zfill(6)
            for candidate in range(1_000_000)
            if str(candidate).zfill(6) not in valid_window_codes
        )
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            lock_path, state_path = self.helper._replay_paths(verifier_path)

            with self.assertRaisesRegex(
                self.helper.TotpVerificationError,
                "verification failed",
            ):
                self.helper.verify_and_consume_registered_totp(
                    verifier_path,
                    secret,
                    invalid_code,
                    now=now,
                    expected_uid=os.geteuid(),
                )
            self.assertTrue(lock_path.is_file())
            self.assertFalse(state_path.exists())

            self.helper.verify_and_consume_registered_totp(
                verifier_path,
                secret,
                valid_code,
                now=now,
                expected_uid=os.geteuid(),
            )
            state_payload = state_path.read_text(encoding="ascii")
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
            self.assertEqual(
                json.loads(state_payload),
                {
                    "version": self.helper.REPLAY_STATE_VERSION,
                    "last_counter": int(now) // self.helper.TOTP_PERIOD_SECONDS,
                },
            )
            self.assertNotIn(secret, state_payload)
            self.assertNotIn(valid_code, state_payload)
            with self.assertRaisesRegex(
                self.helper.TotpVerificationError,
                "verification failed",
            ):
                self.helper.verify_and_consume_registered_totp(
                    verifier_path,
                    secret,
                    valid_code,
                    now=now,
                    expected_uid=os.geteuid(),
                )

    def test_same_totp_counter_is_consumed_once_under_concurrency(self):
        secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        code = self.helper.totp(secret, now)
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            self.helper.write_registered_secret_verifier(
                verifier_path,
                self.helper.build_registered_secret_verifier(
                    secret,
                    salt=b"0123456789abcdef",
                ),
                expected_uid=os.geteuid(),
            )
            start_barrier = threading.Barrier(8)

            def attempt_consumption():
                start_barrier.wait(timeout=5)
                try:
                    self.helper.verify_and_consume_registered_totp(
                        verifier_path,
                        secret,
                        code,
                        now=now,
                        expected_uid=os.geteuid(),
                    )
                except self.helper.TotpVerificationError:
                    return False
                return True

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                results = list(
                    executor.map(lambda _index: attempt_consumption(), range(8))
                )

            self.assertEqual(results.count(True), 1)
            self.assertEqual(results.count(False), 7)

            restarted_helper = load_helper()
            with self.assertRaisesRegex(
                restarted_helper.TotpVerificationError,
                "verification failed",
            ):
                restarted_helper.verify_and_consume_registered_totp(
                    verifier_path,
                    secret,
                    code,
                    now=now,
                    expected_uid=os.geteuid(),
                )

    def test_replay_lock_contention_has_a_fixed_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            verifier_path = pathlib.Path(directory) / "admin-totp-verifier.json"
            lock_path, _state_path = self.helper._replay_paths(verifier_path)
            first = self.helper._open_replay_lock(
                lock_path,
                expected_uid=os.geteuid(),
            )
            second = self.helper._open_replay_lock(
                lock_path,
                expected_uid=os.geteuid(),
            )
            try:
                self.helper._acquire_replay_lock(first)
                started = time.monotonic()
                with self.assertRaisesRegex(
                    self.helper.TotpVerificationError,
                    "lock is unavailable",
                ):
                    self.helper._acquire_replay_lock(
                        second,
                        timeout_seconds=0.05,
                    )
                self.assertLess(time.monotonic() - started, 0.5)
            finally:
                os.close(second)
                os.close(first)

    def test_command_fails_closed_without_tty_and_does_not_prompt_on_stdout(self):
        result = subprocess.run(
            [sys.executable, HELPER_PATH],
            cwd=ROOT,
            input="",
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("interactive TTY", result.stderr)


if __name__ == "__main__":
    unittest.main()
