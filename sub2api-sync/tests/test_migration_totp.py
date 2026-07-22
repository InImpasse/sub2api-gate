import importlib.util
import pathlib
import subprocess
import sys
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

    def test_verification_accepts_only_current_or_adjacent_window(self):
        secret = "JBSWY3DPEHPK3PXP"
        now = 1_700_000_000
        for offset in (-30, 0, 30):
            code = self.helper.totp(secret, now + offset)
            self.assertTrue(self.helper.verify_totp(secret, code, now=now))
        outside = self.helper.totp(secret, now + 60)
        self.assertFalse(self.helper.verify_totp(secret, outside, now=now))

    def test_invalid_secret_and_code_are_rejected_without_echoing_values(self):
        for secret, code in (
            ("not-base32!", "123456"),
            ("JBSWY3DPEHPK3PXP", "12345"),
            ("JBSWY3DPEHPK3PXP", "abcdef"),
        ):
            with self.subTest(secret=secret, code=code):
                self.assertFalse(self.helper.verify_totp(secret, code, now=0))

        with mock.patch.object(self.helper.sys.stdin, "isatty", return_value=True), \
             mock.patch.object(self.helper.sys.stderr, "isatty", return_value=True), \
             mock.patch.object(
                 self.helper.getpass,
                 "getpass",
                 side_effect=["JBSWY3DPEHPK3PXP", "000000"],
             ):
            with self.assertRaisesRegex(self.helper.TotpVerificationError, "verification failed") as error:
                self.helper.verify_interactive(now=1_700_000_000)
        self.assertNotIn("JBSWY3DPEHPK3PXP", str(error.exception))
        self.assertNotIn("000000", str(error.exception))

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
