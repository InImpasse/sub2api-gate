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

    def test_verify_requires_an_absolute_private_file_and_explicit_database(self):
        environment = os.environ.copy()
        environment["SUB2API_DATABASE_URL"] = (
            "postgresql://ambient:must-not-be-used@127.0.0.1:5432/sub2api"
            "?sslmode=disable"
        )
        cases = (
            ([PREFLIGHT, "--verify"], "usage:"),
            (
                [
                    PREFLIGHT,
                    "--verify",
                    "--env-file",
                    "relative.env",
                    "--database",
                    "target",
                ],
                "private environment file path must be absolute",
            ),
            (
                [
                    PREFLIGHT,
                    "--verify",
                    "--env-file",
                    "/private/not-opened.env",
                    "--database",
                    "ambient",
                ],
                "usage:",
            ),
        )
        for command, expected_error in cases:
            with self.subTest(command=command):
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    env=environment,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected_error, result.stderr)

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
            "SUB2API_DATABASE_URL": "ambient-value-must-not-be-used",
        }
        selected_environment = {
            "PATH": os.environ["PATH"],
            "PGHOST": "db.example.test",
            "PGPORT": "5544",
            "PGUSER": "runtime_user",
            "PGPASSWORD": "private-password",
            "PGDATABASE": "sub2api",
            "PGOPTIONS": preflight.RUNTIME_PGOPTIONS,
        }
        pg_tool = mock.Mock()
        pg_tool.private_libpq_environment.return_value = selected_environment
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr=None)
        with mock.patch.object(
            preflight, "verify_no_postgres_log_artifacts"
        ) as artifact_gate, mock.patch.object(
            preflight.subprocess, "run", return_value=completed
        ) as run, mock.patch.object(
            preflight, "load_pg_environment_tool", return_value=pg_tool
        ):
            preflight.verify_runtime_privacy(
                environment, pathlib.Path("/private/sub2api.env"), "target"
            )

        command = run.call_args.args[0]
        child_environment = run.call_args.kwargs["env"]
        self.assertNotIn("private-password", " ".join(map(str, command)))
        self.assertNotIn("SUB2API_DATABASE_URL", child_environment)
        self.assertEqual(child_environment["PGHOST"], "db.example.test")
        self.assertEqual(child_environment["PGPORT"], "5544")
        self.assertEqual(child_environment["PGUSER"], "runtime_user")
        self.assertEqual(child_environment["PGPASSWORD"], "private-password")
        self.assertIn("default_transaction_read_only=on", child_environment["PGOPTIONS"])
        pg_tool.private_libpq_environment.assert_called_once_with(
            mock.ANY,
            pathlib.Path("/private/sub2api.env"),
            "SUB2API_TARGET_DATABASE_URL",
        )
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
        environment = {"SUB2API_DATABASE_URL": "ambient-value-must-not-be-used"}
        pg_tool = mock.Mock()
        pg_tool.private_libpq_environment.return_value = {"PGHOST": "db.example.test"}
        with mock.patch.object(
            preflight, "verify_no_postgres_log_artifacts"
        ), mock.patch.object(
            preflight.subprocess,
            "run",
            return_value=subprocess.CompletedProcess(
                [], 0, stdout="unsafe-private-value\n", stderr=None
            ),
        ), mock.patch.object(
            preflight, "load_pg_environment_tool", return_value=pg_tool
        ):
            with self.assertRaisesRegex(
                RuntimeError, "runtime_privacy_gate_failed"
            ) as raised:
                preflight.verify_runtime_privacy(
                    environment, pathlib.Path("/private/sub2api.env"), "target"
                )
        self.assertNotIn("unsafe-private-value", str(raised.exception))

    def test_source_verification_uses_exact_container_wrapper(self):
        preflight = load_python_script(PREFLIGHT, "runtime_privacy_source")
        environment = {"SUB2API_DATABASE_URL": "ambient-value-must-not-be-used"}
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr=None)
        source = {
            "source_app_container": "legacy-app",
            "source_app_id": "a" * 64,
            "source_postgres_container": "legacy-postgres",
            "source_postgres_id": "b" * 64,
        }
        with mock.patch.object(
            preflight, "verify_no_postgres_log_artifacts"
        ), mock.patch.object(
            preflight.subprocess, "run", return_value=completed
        ) as run:
            preflight.verify_runtime_privacy(
                environment,
                pathlib.Path("/private/sub2api.env"),
                "source",
                **source,
            )
        command = run.call_args.args[0]
        self.assertEqual(command[0:2], ["python3", str(preflight.SOURCE_PG_EXEC)])
        self.assertIn("--source-app-state", command)
        self.assertIn("running", command)
        self.assertIn("psql", command)
        self.assertNotIn("--file", command)
        self.assertNotIn("ambient-value-must-not-be-used", " ".join(command))
        self.assertNotIn("SUB2API_DATABASE_URL", run.call_args.kwargs["env"])


if __name__ == "__main__":
    unittest.main()
