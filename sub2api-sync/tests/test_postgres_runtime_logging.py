import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
VERIFY_TOOL = ROOT / "deploy" / "verify-runtime-privacy.py"
LOGGING_GATE = ROOT / "deploy" / "verify-postgres-runtime-logging.sql"
COMPOSE_PATHS = (
    ROOT / "docker-compose.yml",
    ROOT / "docker-compose.canary.yml",
    ROOT / "docker-compose.traffic-canary.yml",
)
REAL_PG18_TEST = ROOT / "deploy" / "test-postgres-runtime-logging-pg18.sh"
SUB2API_INTEGRATION_TEST = ROOT / "deploy" / "test-sub2api-no-content-logging.sh"


def load_verify_tool(name):
    spec = importlib.util.spec_from_file_location(name, VERIFY_TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PostgresRuntimeLoggingContractTests(unittest.TestCase):
    def test_every_compose_postgres_uses_command_line_privacy_overrides(self):
        required = (
            "logging_collector=off",
            "log_destination=stderr",
            "log_directory=log",
            "log_statement=none",
            "log_min_error_statement=panic",
            "log_min_messages=panic",
            "log_error_verbosity=terse",
            "log_parameter_max_length=0",
            "log_parameter_max_length_on_error=0",
            "log_duration=off",
            "log_min_duration_statement=-1",
            "log_min_duration_sample=-1",
            "log_statement_sample_rate=0",
            "log_transaction_sample_rate=0",
            "log_connections=off",
            "log_disconnections=off",
            "log_replication_commands=off",
            "log_checkpoints=off",
            "log_lock_waits=off",
            "log_temp_files=-1",
            "log_autovacuum_min_duration=-1",
            "debug_print_parse=off",
            "debug_print_rewritten=off",
            "debug_print_plan=off",
            "log_parser_stats=off",
            "log_planner_stats=off",
            "log_executor_stats=off",
            "log_statement_stats=off",
        )
        for path in COMPOSE_PATHS:
            source = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                for setting in required:
                    self.assertEqual(source.count(f"      - {setting}\n"), 1, setting)
                postgres_start = source.index("postgres@sha256:")
                command_start = source.index("    command:\n", postgres_start)
                logging_start = source.index("    logging:\n", command_start)
                self.assertLess(command_start, logging_start)
                self.assertIn('driver: "none"', source[logging_start:])

    def test_sql_gate_checks_settings_sources_and_runtime_files(self):
        source = LOGGING_GATE.read_text(encoding="ascii")
        self.assertIn("pg_catalog.pg_settings", source)
        self.assertIn("settings.source = 'command line'", source)
        self.assertIn("NOT settings.pending_restart", source)
        self.assertIn("pg_catalog.pg_file_settings", source)
        self.assertIn("current_logfiles", source)
        self.assertIn("pg_catalog.pg_stat_file", source)
        self.assertIn("pg_catalog.pg_ls_dir", source)
        self.assertIn("\\gset", source)
        self.assertIn("SELECT 1 / 0", source)
        self.assertNotIn("\\quit 1", source)
        self.assertNotIn("\\echo", source)

    def test_real_pg18_gate_covers_override_residue_and_restart(self):
        source = REAL_PG18_TEST.read_text(encoding="utf-8")
        self.assertIn("PostgreSQL\\) 18\\.", source)
        self.assertIn("--log-driver none", source)
        self.assertIn("dst=/var/lib/postgresql", source)
        self.assertIn("PGDATA=/var/lib/postgresql/18/docker", source)
        self.assertIn("--user 70:70", source)
        self.assertIn("--read-only", source)
        self.assertIn("--cap-drop ALL", source)
        self.assertIn("ALTER SYSTEM SET logging_collector", source)
        self.assertIn("runtime_layout_probe", source)
        self.assertIn("current_logfiles", source)
        self.assertIn("postgresql-stale.csv", source)
        self.assertIn("docker restart", source)
        self.assertNotIn("docker logs", source)

    def test_real_sub2api_integration_uses_the_same_postgres_gate(self):
        source = SUB2API_INTEGRATION_TEST.read_text(encoding="utf-8")
        self.assertIn("-c logging_collector=off", source)
        self.assertIn("-c log_destination=stderr", source)
        self.assertIn("-c log_statement=none", source)
        self.assertIn("-c log_parameter_max_length_on_error=0", source)
        self.assertEqual(source.count("verify-postgres-runtime-logging.sql"), 2)
        self.assertIn("--log-driver none", source)


class PostgresRuntimeLogArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tool = load_verify_tool(f"runtime_privacy_artifacts_{self._testMethodName}")
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name) / "sub2api-gate"
        (self.root / "postgres" / "pg_logical" / "snapshots").mkdir(parents=True)
        (self.root / "app").mkdir()
        self.tool.EXPECTED_DATA_ROOT = self.root
        self.environment = {"SUB2API_DATA_ROOT": str(self.root)}

    def tearDown(self):
        self.temporary.cleanup()

    def test_safe_postgres_internal_logical_directory_is_not_a_log_artifact(self):
        (self.root / "postgres" / "pg_logical" / "snapshots" / "state").touch()
        (self.root / "app" / "model_pricing.json").write_text("{}", encoding="ascii")
        self.tool.verify_no_postgres_log_artifacts(self.environment)

    def test_known_residue_shapes_fail_without_deletion(self):
        cases = (
            self.root / "postgres" / "current_logfiles",
            self.root / "postgres" / "postgresql-stale.csv",
            self.root / "postgres" / "postgresql-stale.json",
            self.root / "safe-backup" / "database.log",
            self.root / "postgres" / "log" / "custom-name",
        )
        for index, artifact in enumerate(cases):
            with self.subTest(artifact=artifact.relative_to(self.root)):
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_text("PRIVATE_SENTINEL", encoding="ascii")
                with self.assertRaisesRegex(
                    RuntimeError, "runtime_privacy_gate_failed"
                ):
                    self.tool.verify_no_postgres_log_artifacts(self.environment)
                self.assertTrue(artifact.exists())
                artifact.unlink()
                if artifact.parent.name == "log":
                    artifact.parent.rmdir()

    def test_log_directory_symlink_fails_closed(self):
        outside = pathlib.Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.root / "postgres" / "log").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "runtime_privacy_gate_failed"):
            self.tool.verify_no_postgres_log_artifacts(self.environment)

    def test_wrong_or_missing_data_root_fails_closed(self):
        for environment in ({}, {"SUB2API_DATA_ROOT": str(self.root.parent)}):
            with self.subTest(environment=environment):
                with self.assertRaisesRegex(
                    RuntimeError, "runtime_privacy_gate_failed"
                ):
                    self.tool.verify_no_postgres_log_artifacts(environment)

    def test_database_verification_scans_before_and_after_psql(self):
        completed = subprocess.CompletedProcess([], 0, stdout="ok\n", stderr=None)
        environment = {
            "PATH": os.environ["PATH"],
            "SUB2API_DATA_ROOT": str(self.root),
        }
        selected_environment = {
            "PATH": os.environ["PATH"],
            "PGHOST": "127.0.0.1",
            "PGPORT": "15432",
            "PGUSER": "runtime",
            "PGPASSWORD": "private",
            "PGDATABASE": "sub2api",
            "PGOPTIONS": self.tool.RUNTIME_PGOPTIONS,
        }
        pg_tool = mock.Mock()
        pg_tool.private_libpq_environment.return_value = selected_environment
        with mock.patch.object(
            self.tool, "verify_no_postgres_log_artifacts"
        ) as artifact_gate, mock.patch.object(
            self.tool.subprocess, "run", return_value=completed
        ) as run, mock.patch.object(
            self.tool, "load_pg_environment_tool", return_value=pg_tool
        ):
            self.tool.verify_runtime_privacy(
                environment, pathlib.Path("/private/sub2api.env"), "target"
            )
        self.assertEqual(artifact_gate.call_count, 2)
        self.assertIn("pg_catalog.pg_settings", run.call_args.kwargs["input"])
        self.assertIn("current_logfiles", run.call_args.kwargs["input"])
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.DEVNULL)


if __name__ == "__main__":
    unittest.main()
