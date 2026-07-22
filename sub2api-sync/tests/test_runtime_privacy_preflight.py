import importlib.util
import os
import pathlib
import subprocess
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "deploy" / "verify-runtime-privacy.py"


def load_python_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimePrivacyPreflightTests(unittest.TestCase):
    def test_check_mode_does_not_open_a_database_connection(self):
        self.assertTrue(PREFLIGHT.exists())
        environment = os.environ.copy()
        environment.pop("SUB2API_DATABASE_URL", None)
        result = subprocess.run(
            [PREFLIGHT, "check"],
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("no database connection was opened", result.stdout)

    def test_fixed_query_requires_safe_settings_and_complete_trigger(self):
        preflight = load_python_script(PREFLIGHT, "runtime_privacy_sql")
        sql = preflight.PRIVACY_SQL
        self.assertIn("risk_control_enabled", sql)
        self.assertIn("lower(btrim(value)) = 'false'", sql)
        self.assertIn("image_storage_config", sql)
        self.assertIn("value::jsonb = '{\"enabled\":false}'::jsonb", sql)
        self.assertIn("enforce_privacy_safe_settings", sql)
        self.assertIn("tgtype = 31", sql)
        self.assertIn("tgenabled = 'O'", sql)
        self.assertIn("tgfoid = to_regprocedure", sql)
        self.assertIn("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", sql)
        self.assertNotIn("SELECT value", sql)

    def test_verify_keeps_credentials_out_of_argv_and_returns_only_status(self):
        preflight = load_python_script(PREFLIGHT, "runtime_privacy_verify")
        environment = {
            "PATH": os.environ["PATH"],
            "SUB2API_DATABASE_URL": (
                "postgresql://runtime_user:private-password@db.example.test:5544/"
                "sub2api?sslmode=verify-full&sslrootcert=system"
            ),
        }
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr=None)
        with mock.patch.object(
            preflight, "verify_no_postgres_log_artifacts"
        ) as artifact_gate, mock.patch.object(
            preflight.subprocess, "run", return_value=completed
        ) as run:
            preflight.verify_runtime_privacy(environment)

        command = run.call_args.args[0]
        child_environment = run.call_args.kwargs["env"]
        self.assertNotIn("private-password", " ".join(map(str, command)))
        self.assertNotIn("SUB2API_DATABASE_URL", child_environment)
        self.assertEqual(child_environment["PGHOST"], "db.example.test")
        self.assertEqual(child_environment["PGPORT"], "5544")
        self.assertEqual(child_environment["PGUSER"], "runtime_user")
        self.assertEqual(child_environment["PGPASSWORD"], "private-password")
        self.assertIn("default_transaction_read_only=on", child_environment["PGOPTIONS"])
        self.assertEqual(artifact_gate.call_count, 2)
        self.assertTrue(
            run.call_args.kwargs["input"].startswith(preflight.PRIVACY_SQL)
        )
        self.assertIn("pg_catalog.pg_settings", run.call_args.kwargs["input"])
        self.assertIn("current_logfiles", run.call_args.kwargs["input"])
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["timeout"], 8)

    def test_verify_fails_closed_without_echoing_database_output(self):
        preflight = load_python_script(PREFLIGHT, "runtime_privacy_failure")
        environment = {
            "SUB2API_DATABASE_URL": (
                "postgresql://user:password@db.example.test/sub2api"
                "?sslmode=verify-full&sslrootcert=system"
            )
        }
        with mock.patch.object(
            preflight, "verify_no_postgres_log_artifacts"
        ), mock.patch.object(
            preflight.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout="unsafe-private-value\n", stderr=None
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError, "runtime_privacy_gate_failed"
            ) as raised:
                preflight.verify_runtime_privacy(environment)
        self.assertNotIn("unsafe-private-value", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
