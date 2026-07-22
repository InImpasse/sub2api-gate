import concurrent.futures
import importlib.util
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
