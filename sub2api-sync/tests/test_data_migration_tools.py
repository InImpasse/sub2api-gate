import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
POSTGRES_MIGRATION = ROOT / "deploy" / "migrate-sanitized-postgres.sh"
LOCKED_POSTGRES_STREAM = ROOT / "deploy" / "locked-postgres-stream.py"
REDIS_MIGRATION = ROOT / "deploy" / "migrate-redis-allowlist.py"
APP_MIGRATION = ROOT / "deploy" / "migrate-app-metadata.py"
SAFE_EXPORT = ROOT / "deploy" / "export-safe-metadata.sh"
REDIS_POLICY = ROOT / "deploy" / "redis-key-prefixes.json"
PG_ENV_EXEC = ROOT / "deploy" / "pg-env-exec.py"
TARGET_VALIDATOR = ROOT / "deploy" / "verify-sanitized-target.sql"
PORTABILITY_GATE = ROOT / "deploy" / "verify-postgres-portability.sql"


def load_python_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DataMigrationToolTests(unittest.TestCase):
    def run_check(self, path):
        env = os.environ.copy()
        for name in (
            "SUB2API_DATABASE_URL",
            "SUB2API_SOURCE_DATABASE_URL",
            "SUB2API_TARGET_DATABASE_URL",
            "SUB2API_SOURCE_REDIS_URL",
            "SUB2API_TARGET_REDIS_URL",
            "SUB2API_SOURCE_REDIS_PASSWORD",
            "SUB2API_TARGET_REDIS_PASSWORD",
            "SUB2API_SOURCE_APP_DIR",
            "SUB2API_DATA_ROOT",
        ):
            env.pop(name, None)
        result = subprocess.run(
            [path, "check"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("no connection was opened", result.stdout)
        return result

    def test_all_migration_tools_are_read_only_without_explicit_apply(self):
        for path in (
            POSTGRES_MIGRATION,
            REDIS_MIGRATION,
            APP_MIGRATION,
            SAFE_EXPORT,
        ):
            with self.subTest(path=path.name):
                self.assertTrue(path.exists())
                self.run_check(path)

    def test_postgres_migration_is_a_deadline_bounded_logical_stream(self):
        script = POSTGRES_MIGRATION.read_text()
        coordinator = LOCKED_POSTGRES_STREAM.read_text()
        self.assertIn("SUB2API_MIGRATION_WRITES_STOPPED=YES", script)
        self.assertIn("verify_no_conversation_content.sql", script)
        self.assertIn('locked_stream="$repo_dir/deploy/locked-postgres-stream.py"', script)
        self.assertIn("pg_dump", coordinator)
        self.assertIn("stdout=self.target.stdin", coordinator)
        self.assertIn("--single-transaction", coordinator)
        self.assertIn("180", script)
        self.assertIn("checkpoint:", script)
        self.assertIn("sub2api_gate.expected_row_counts", coordinator)
        self.assertIn("sub2api_gate.expected_usage_aggregate", coordinator)
        self.assertIn("verify-sanitized-target.sql", coordinator)
        self.assertIn("verify-postgres-portability.sql", coordinator)
        self.assertIn("pg_control_system()", coordinator)
        self.assertIn("different physical PostgreSQL clusters", script)
        self.assertIn("sanitized_postgres_portability_gate_failed", script)
        self.assertGreaterEqual(script.count("2>/dev/null"), 2)
        self.assertIn("sanitized_postgres_stream_failed", script)
        self.assertIn('source_pg_exec="$repo_dir/deploy/source-postgres-exec.py"', script)
        self.assertIn('"--target-private-env-file"', coordinator)
        self.assertIn("--source-app-container", script)
        self.assertIn("--source-app-id", script)
        self.assertIn("--source-postgres-container", script)
        self.assertIn("--source-postgres-id", script)
        self.assertIn("--source-app-state stopped", script)
        self.assertNotIn("--source-private-env-file", script)
        self.assertNotIn("SUB2API_SOURCE_DATABASE_URL", script)
        source_file_function = script.split("run_source_sql_file() {", 1)[1].split(
            "\n}", 1
        )[0]
        self.assertIn('< "$sql_file"', source_file_function)
        self.assertNotIn("--file", source_file_function)
        self.assertNotIn("cat $stream_stderr", script + coordinator)
        self.assertIn("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", coordinator)
        self.assertIn("LOCK TABLE", coordinator)
        self.assertIn("IN SHARE MODE", coordinator)
        self.assertIn("pg_terminate_backend", coordinator)
        self.assertIn("--snapshot=", coordinator)
        self.assertIn("MAX_CONTROL_OUTPUT_BYTES", coordinator)
        execute = coordinator.split("    def execute(self):", 1)[1].split(
            "\n\n\ndef parse_arguments", 1
        )[0]
        self.assertLess(execute.index("self.clear_source_clients()"), execute.index("self.commit_target()"))
        self.assertLess(execute.index("self.commit_target()"), execute.index("self.stop_holder(self.lock_holder"))
        for forbidden in (
            "pg_basebackup",
            "pg_waldump",
            "/var/lib/postgresql/data",
            "--format=custom",
        ):
            self.assertNotIn(forbidden, script + coordinator)

    def test_safe_export_hashes_schema_without_persisting_schema_text(self):
        script = SAFE_EXPORT.read_text()
        self.assertIn("schema_fingerprint.sha256", script)
        self.assertIn("pg_dump", script)
        self.assertIn("sha256sum", script)
        self.assertNotIn('> "$partial_dir/schema.sql"', script)
        self.assertNotRegex(script, r"(?m)^\s*schema\.sql\s*$")
        self.assertIn("idle_in_transaction_session_timeout=600000", script)
        self.assertIn("snapshot_holder_stop", script)
        for relation in (
            "groups",
            "user_allowed_groups",
            "user_subscriptions",
            "api_keys",
            "usage_logs",
        ):
            self.assertIn(f"FROM public.{relation}", script)

    def test_postgres_url_wrapper_keeps_credentials_out_of_argv(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec")
        original = {
            "SUB2API_TARGET_DATABASE_URL": (
                "postgresql://user%40name:password%2Fvalue@db.example:5544/app%2Ddb"
                "?sslmode=verify-full&sslrootcert=system&connect_timeout=7"
            ),
            "PGHOST": "must-be-replaced",
            "PGPASSFILE": "/private/must-not-be-inherited",
            "PGSSLCRLDIR": "/private/must-not-be-inherited",
            "PGLOADBALANCEHOSTS": "random",
            "PG_FUTURE_LIBPQ_OPTION": "must-not-be-inherited",
            "SSL_CERT_FILE": "/private/must-not-be-inherited",
            "OPENSSL_CONF": "/private/must-not-be-inherited",
            "SSLKEYLOGFILE": "/private/must-not-be-created",
        }
        result = wrapper.libpq_environment(
            original, "SUB2API_TARGET_DATABASE_URL"
        )
        self.assertEqual(result["PGHOST"], "db.example")
        self.assertEqual(result["PGPORT"], "5544")
        self.assertEqual(result["PGUSER"], "user@name")
        self.assertEqual(result["PGPASSWORD"], "password/value")
        self.assertEqual(result["PGDATABASE"], "app-db")
        self.assertEqual(result["PGSSLMODE"], "verify-full")
        self.assertEqual(result["PGSSLROOTCERT"], "system")
        self.assertEqual(result["PGCONNECT_TIMEOUT"], "7")
        self.assertNotIn("SUB2API_SOURCE_DATABASE_URL", result)
        self.assertNotIn("SUB2API_TARGET_DATABASE_URL", result)
        for inherited_name in (
            "PGPASSFILE",
            "PGSSLCRLDIR",
            "PGLOADBALANCEHOSTS",
            "PG_FUTURE_LIBPQ_OPTION",
            "SSL_CERT_FILE",
            "OPENSSL_CONF",
            "SSLKEYLOGFILE",
        ):
            self.assertNotIn(inherited_name, result)

        script = POSTGRES_MIGRATION.read_text()
        self.assertNotIn('--dbname="$SUB2API_SOURCE_DATABASE_URL"', script)
        self.assertNotIn('--dbname="$SUB2API_TARGET_DATABASE_URL"', script)
        self.assertTrue(TARGET_VALIDATOR.exists())

    def test_private_source_database_selector_is_retired(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = pathlib.Path(directory) / "private.env"
            env_file.write_text(
                "SUB2API_SOURCE_DATABASE_URL="
                "postgresql://source-user:source-password@172.19.0.2:5432/sub2api"
                "?sslmode=disable\n"
                "SUB2API_TARGET_DATABASE_URL="
                "postgresql://target-user:target-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable\n"
                "SUB2API_DATABASE_URL="
                "postgresql://target-user:target-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable\n",
                encoding="ascii",
            )
            env_file.chmod(0o600)
            result = subprocess.run(
                [
                    sys.executable,
                    PG_ENV_EXEC,
                    "--source-private-env-file",
                    env_file,
                    sys.executable,
                    "-c",
                    "raise SystemExit(99)",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertNotIn("source-password", result.stdout)
        self.assertNotIn("source-password", result.stderr)

    def test_direct_source_database_selector_is_retired(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            env_file = directory_path / "private.env"
            marker = directory_path / "child-ran"
            environment = os.environ.copy()
            environment["SUB2API_SOURCE_DATABASE_URL"] = (
                "postgresql://source-user:private-test-password@172.19.0.2:5432/"
                "sub2api?sslmode=disable"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    PG_ENV_EXEC,
                    "SUB2API_SOURCE_DATABASE_URL",
                    sys.executable,
                    "-c",
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).touch()",
                    marker,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                env=environment,
            )
            marker_was_created = marker.exists()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(marker_was_created)
        self.assertNotIn("private-test-password", result.stdout)
        self.assertNotIn("private-test-password", result.stderr)

    def test_ambient_target_database_cli_selectors_are_retired(self):
        sentinel = "AMBIENT_TARGET_DATABASE_PASSWORD_SENTINEL"
        for selector in (
            "SUB2API_DATABASE_URL",
            "SUB2API_TARGET_DATABASE_URL",
        ):
            with self.subTest(selector=selector), tempfile.TemporaryDirectory() as directory:
                marker = pathlib.Path(directory) / "child-ran"
                environment = os.environ.copy()
                environment[selector] = (
                    "postgresql://target-user:"
                    + sentinel
                    + "@127.0.0.1:15432/sub2api?sslmode=disable"
                )
                result = subprocess.run(
                    [
                        sys.executable,
                        PG_ENV_EXEC,
                        selector,
                        sys.executable,
                        "-c",
                        "import pathlib,sys;pathlib.Path(sys.argv[1]).touch()",
                        marker,
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=environment,
                )

                self.assertEqual(result.returncode, 2)
                self.assertFalse(marker.exists())
                self.assertNotIn(sentinel, result.stdout + result.stderr)
                self.assertIn("--target-private-env-file", result.stderr)

    def test_private_target_accepts_canonical_source_and_exact_loopback_target(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_target_valid")
        values = {
            "SUB2API_SOURCE_DATABASE_URL": (
                "postgresql://source-user:source-password@172.19.0.2:5432/legacy"
                "?sslmode=disable"
            ),
            "SUB2API_TARGET_DATABASE_URL": (
                "postgres://target-owner:target-password@127.0.0.1:15432/"
                "sub2api%2Dprod?application_name=owner&sslmode=disable"
            ),
            "SUB2API_DATABASE_URL": (
                "postgresql://app-role:app-password@127.0.0.1:15432/sub2api-prod"
                "?connect_timeout=9&sslmode=disable"
            ),
        }

        with mock.patch.object(wrapper, "_load_private_environment", return_value=values):
            result = wrapper.private_libpq_environment(
                {}, "/private/runtime.env", "SUB2API_TARGET_DATABASE_URL"
            )

        self.assertEqual(result["PGHOST"], "127.0.0.1")
        self.assertEqual(result["PGPORT"], "15432")
        self.assertEqual(result["PGDATABASE"], "sub2api-prod")

    def test_private_target_rejects_noncanonical_source_endpoints(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_source_endpoint")
        target = (
            "postgresql://target-owner:target-password@127.0.0.1:15432/sub2api"
            "?sslmode=disable"
        )
        unsafe_sources = (
            "postgresql://source:password@localhost:5432/sub2api?sslmode=disable",
            "postgresql://source:password@127.0.0.1:5432/sub2api?sslmode=disable",
            "postgresql://source:password@172.19.0.2:5433/sub2api?sslmode=disable",
            "postgresql://source:password@172.19.0.2:5432/sub2api?sslmode=prefer",
            "postgresql://source:password@172.019.0.2:5432/sub2api?sslmode=disable",
            "postgresql://source:password@172.19.0.2:5432/sub2api?sslmode=disable&x=1",
            (
                "postgresql://"
                + ("u" * 64)
                + ":password@172.19.0.2:5432/sub2api?sslmode=disable"
            ),
            (
                "postgresql://source:password@172.19.0.2:5432/"
                + ("d" * 64)
                + "?sslmode=disable"
            ),
        )
        for source in unsafe_sources:
            values = {
                "SUB2API_SOURCE_DATABASE_URL": source,
                "SUB2API_TARGET_DATABASE_URL": target,
                "SUB2API_DATABASE_URL": target,
            }
            with self.subTest(source=source), mock.patch.object(
                wrapper, "_load_private_environment", return_value=values
            ), self.assertRaisesRegex(
                wrapper.ConfigurationError,
                "source PostgreSQL URL is not a canonical private container endpoint",
            ):
                wrapper.private_libpq_environment(
                    {}, "/private/runtime.env", "SUB2API_TARGET_DATABASE_URL"
                )

    def test_private_target_rejects_loopback_aliases_and_socket_hosts(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_target_aliases")
        source = (
            "postgresql://source:password@172.19.0.2:5432/sub2api?sslmode=disable"
        )
        aliases = (
            "localhost",
            "LOCALHOST.",
            "db.localhost",
            "127.0.0.2",
            "0.0.0.0",
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f000001",
            "[::1]",
            "[::]",
            "[::ffff:127.0.0.1]",
            "%31%32%37.0.0.1",
            "%2Fvar%2Frun%2Fpostgresql",
        )
        for alias in aliases:
            ssl = (
                "disable"
                if alias
                in {
                    "127.0.0.2",
                    "0.0.0.0",
                    "[::1]",
                    "[::]",
                    "[::ffff:127.0.0.1]",
                }
                else "verify-full&sslrootcert=system"
            )
            url = (
                f"postgresql://target:password@{alias}:15432/sub2api?sslmode={ssl}"
            )
            values = {
                "SUB2API_SOURCE_DATABASE_URL": source,
                "SUB2API_TARGET_DATABASE_URL": url,
                "SUB2API_DATABASE_URL": url,
            }
            with self.subTest(alias=alias), mock.patch.object(
                wrapper, "_load_private_environment", return_value=values
            ), self.assertRaises(wrapper.ConfigurationError):
                wrapper.private_libpq_environment(
                    {}, "/private/runtime.env", "SUB2API_TARGET_DATABASE_URL"
                )

    def test_private_target_and_application_must_use_the_same_exact_endpoint(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_target_mismatch")
        source = (
            "postgresql://source:password@172.19.0.2:5432/legacy?sslmode=disable"
        )
        target = (
            "postgresql://owner:password@127.0.0.1:15432/sub2api?sslmode=disable"
        )
        mismatched_application_urls = (
            "postgresql://app:password@127.0.0.2:15432/sub2api?sslmode=disable",
            "postgresql://app:password@[::1]:15432/sub2api?sslmode=disable",
            "postgresql://app:password@127.0.0.1:15433/sub2api?sslmode=disable",
            "postgresql://app:password@127.0.0.1:15432/other?sslmode=disable",
        )
        for application_url in mismatched_application_urls:
            values = {
                "SUB2API_SOURCE_DATABASE_URL": source,
                "SUB2API_TARGET_DATABASE_URL": target,
                "SUB2API_DATABASE_URL": application_url,
            }
            with self.subTest(application_url=application_url), mock.patch.object(
                wrapper, "_load_private_environment", return_value=values
            ), self.assertRaisesRegex(
                wrapper.ConfigurationError, "target PostgreSQL identity is invalid"
            ):
                wrapper.private_libpq_environment(
                    {}, "/private/runtime.env", "SUB2API_TARGET_DATABASE_URL"
                )

    def test_private_database_interface_can_select_only_the_target(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_private_selection")
        values = {
            "SUB2API_SOURCE_DATABASE_URL": (
                "postgresql://source-user:source-password@172.19.0.2:5432/legacy"
                "?sslmode=disable"
            ),
            "SUB2API_TARGET_DATABASE_URL": (
                "postgresql://target-owner:target-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable"
            ),
            "SUB2API_DATABASE_URL": (
                "postgres://app-role:app-password@127.0.0.1:15432/sub2api"
                "?application_name=app&sslmode=disable"
            ),
        }
        with mock.patch.object(wrapper, "_load_private_environment", return_value=values):
            target = wrapper.private_libpq_environment(
                {"UNRELATED": "preserved"},
                "/private/runtime.env",
                "SUB2API_TARGET_DATABASE_URL",
            )
            for forbidden_name in (
                "SUB2API_SOURCE_DATABASE_URL",
                "SUB2API_DATABASE_URL",
            ):
                with self.subTest(forbidden_name=forbidden_name), self.assertRaisesRegex(
                    wrapper.ConfigurationError,
                    "private PostgreSQL URL selection is not allowed",
                ):
                    wrapper.private_libpq_environment(
                        {}, "/private/runtime.env", forbidden_name
                    )
        with self.assertRaisesRegex(
            wrapper.ConfigurationError,
            "PostgreSQL URL environment name is not allowed",
        ):
            wrapper.libpq_environment(
                values, "SUB2API_SOURCE_DATABASE_URL"
            )

        self.assertEqual(target["PGHOST"], "127.0.0.1")
        self.assertEqual(target["PGPORT"], "15432")
        self.assertEqual(target["PGUSER"], "target-owner")
        self.assertEqual(target["PGPASSWORD"], "target-password")
        self.assertEqual(target["PGDATABASE"], "sub2api")
        self.assertEqual(target["UNRELATED"], "preserved")
        self.assertTrue(wrapper.ALL_URL_ENVIRONMENT_NAMES.isdisjoint(target))

    def test_private_target_cli_mode_executes_with_only_target_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = pathlib.Path(directory) / "private.env"
            env_file.write_text(
                "SUB2API_SOURCE_DATABASE_URL="
                "postgresql://source-user:source-password@172.19.0.2:5432/legacy"
                "?sslmode=disable\n"
                "SUB2API_TARGET_DATABASE_URL="
                "postgresql://target-owner:target-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable\n"
                "SUB2API_DATABASE_URL="
                "postgres://app-role:app-password@127.0.0.1:15432/sub2api"
                "?application_name=app&sslmode=disable\n",
                encoding="ascii",
            )
            env_file.chmod(0o600)
            child_check = (
                "import os,sys;"
                "expected={'PGHOST':'127.0.0.1','PGPORT':'15432',"
                "'PGUSER':'target-owner','PGPASSWORD':'target-password',"
                "'PGDATABASE':'sub2api','PGSSLMODE':'disable'};"
                "urls={'SUB2API_SOURCE_DATABASE_URL','SUB2API_TARGET_DATABASE_URL',"
                "'SUB2API_DATABASE_URL'};"
                "sys.exit(0 if all(os.environ.get(k)==v for k,v in expected.items()) "
                "and urls.isdisjoint(os.environ) else 9)"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    PG_ENV_EXEC,
                    "--target-private-env-file",
                    env_file,
                    sys.executable,
                    "-c",
                    child_check,
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_private_target_cli_rejects_relative_private_file_before_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            env_file = directory_path / "private.env"
            marker = directory_path / "child-ran"
            env_file.write_text(
                "SUB2API_SOURCE_DATABASE_URL="
                "postgresql://source:source-password@172.19.0.2:5432/sub2api"
                "?sslmode=disable\n"
                "SUB2API_TARGET_DATABASE_URL="
                "postgresql://target:target-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable\n"
                "SUB2API_DATABASE_URL="
                "postgresql://app:app-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable\n",
                encoding="ascii",
            )
            env_file.chmod(0o600)
            result = subprocess.run(
                [
                    sys.executable,
                    PG_ENV_EXEC,
                    "--target-private-env-file",
                    env_file.name,
                    sys.executable,
                    "-c",
                    "import pathlib,sys;pathlib.Path(sys.argv[1]).touch()",
                    marker,
                ],
                cwd=directory_path,
                capture_output=True,
                text=True,
                check=False,
            )
            marker_was_created = marker.exists()

        self.assertEqual(result.returncode, 1)
        self.assertFalse(marker_was_created)
        self.assertNotIn("source-password", result.stderr)
        self.assertNotIn("target-password", result.stderr)
        self.assertNotIn("app-password", result.stderr)

    def test_postgres_url_wrapper_rejects_malformed_percent_encoding(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_percent_encoding")
        malformed_components = (
            "user%",
            "user%2",
            "user%GG",
            "%FF",
        )
        for value in malformed_components:
            urls = (
                f"postgresql://{value}:password@127.0.0.1:5432/sub2api?sslmode=disable",
                f"postgresql://user:{value}@127.0.0.1:5432/sub2api?sslmode=disable",
                f"postgresql://user:password@127.0.0.1:5432/{value}?sslmode=disable",
            )
            for url in urls:
                with self.subTest(url=url), self.assertRaisesRegex(
                    wrapper.ConfigurationError, "percent encoding"
                ):
                    wrapper.libpq_environment(
                        {"SUB2API_DATABASE_URL": url}, "SUB2API_DATABASE_URL"
                    )

        malformed_queries = ("%GG", "%FF", "sslmode=disable%")
        for query in malformed_queries:
            with self.subTest(query=query), self.assertRaises(
                wrapper.ConfigurationError
            ):
                wrapper.libpq_environment(
                    {
                        "SUB2API_DATABASE_URL": (
                            "postgresql://user:password@127.0.0.1:5432/sub2api?"
                            + query
                        )
                    },
                    "SUB2API_DATABASE_URL",
                )

    def test_postgres_url_wrapper_rejects_literal_control_separators(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_control_separator")
        for separator in ("\t", "\n", "\r", "\x1f", "\x7f"):
            url = (
                "postgresql://user:pass"
                + separator
                + "word@127.0.0.1:5432/sub2api?sslmode=disable"
            )
            with self.subTest(separator=repr(separator)), self.assertRaisesRegex(
                wrapper.ConfigurationError, "PostgreSQL URL is invalid"
            ):
                wrapper.libpq_environment(
                    {"SUB2API_DATABASE_URL": url}, "SUB2API_DATABASE_URL"
                )

    def test_canonical_host_collapses_all_loopback_spellings(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_loopback_identity")
        aliases = (
            "127.0.0.1",
            "127.0.0.2",
            "0.0.0.0",
            "0",
            "::1",
            "::",
            "::ffff:127.0.0.1",
            "0:0:0:0:0:ffff:7f00:1",
            "localhost",
            "LOCALHOST.",
            "db.localhost",
            "127.1",
            "2130706433",
            "0177.0.0.1",
            "0x7f000001",
            "%31%32%37.0.0.1",
        )
        for alias in aliases:
            with self.subTest(alias=alias):
                self.assertEqual(wrapper._canonical_database_host(alias), "loopback")

        for host in ("%2Fvar%2Frun%2Fpostgresql", "%5C%5C.pipe", "host%"):
            with self.subTest(host=host), self.assertRaises(wrapper.ConfigurationError):
                wrapper._canonical_database_host(host)

    def test_postgres_url_wrapper_enforces_transport_security_by_location(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec_tls")

        loopback = wrapper.libpq_environment(
            {
                "SUB2API_DATABASE_URL": (
                    "postgresql://local-user:local-password@127.0.0.1:5432/sub2api"
                    "?sslmode=disable"
                )
            },
            "SUB2API_DATABASE_URL",
        )
        self.assertEqual(loopback["PGHOST"], "127.0.0.1")
        self.assertEqual(loopback["PGSSLMODE"], "disable")

        mapped_loopback = wrapper.libpq_environment(
            {
                "SUB2API_DATABASE_URL": (
                    "postgresql://local-user:local-password@"
                    "[::ffff:127.0.0.1]:5432/sub2api?sslmode=disable"
                )
            },
            "SUB2API_DATABASE_URL",
        )
        self.assertEqual(mapped_loopback["PGHOST"], "::ffff:127.0.0.1")
        self.assertEqual(mapped_loopback["PGSSLMODE"], "disable")

        remote = wrapper.libpq_environment(
            {
                "SUB2API_DATABASE_URL": (
                    "postgresql://remote-user:remote-password@db.example.test/sub2api"
                    "?sslmode=verify-full&sslrootcert=/etc/sub2api-gate/postgres-ca.pem"
                )
            },
            "SUB2API_DATABASE_URL",
        )
        self.assertEqual(remote["PGSSLMODE"], "verify-full")
        self.assertEqual(
            remote["PGSSLROOTCERT"], "/etc/sub2api-gate/postgres-ca.pem"
        )

        rejected = (
            "postgresql://user:password@127.0.0.1/sub2api",
            "postgresql://user:password@127.0.0.1/sub2api?sslmode=prefer",
            (
                "postgresql://user:password@[::ffff:127.0.0.1]/sub2api"
                "?sslmode=verify-full&sslrootcert=system"
            ),
            "postgresql://user:password@db.example.test/sub2api?sslmode=disable",
            "postgresql://user:password@db.example.test/sub2api?sslmode=prefer",
            "postgresql://user:password@db.example.test/sub2api?sslmode=require",
            "postgresql://user:password@db.example.test/sub2api?sslmode=verify-ca",
            "postgresql://user:password@db.example.test/sub2api?sslmode=verify-full",
            (
                "postgresql://user:password@db.example.test/sub2api"
                "?sslmode=verify-full&sslrootcert=relative-ca.pem"
            ),
        )
        for url in rejected:
            with self.subTest(url=url), self.assertRaises(wrapper.ConfigurationError):
                wrapper.libpq_environment(
                    {"SUB2API_DATABASE_URL": url}, "SUB2API_DATABASE_URL"
                )

    def test_redis_policy_copies_only_nonce_markers_and_discards_app_state(self):
        policy = json.loads(REDIS_POLICY.read_text())
        self.assertEqual(policy["version"], 2)
        self.assertEqual(
            set(policy["categories"]),
            {"session", "oauth", "scheduler", "billing", "concurrency", "sync_nonce"},
        )
        redis_migration = load_python_script(REDIS_MIGRATION, "redis_migration")
        allowed, discarded, forbidden = redis_migration.load_prefix_policy(REDIS_POLICY)
        nonce_key = b"sub2api-sync:nonce:" + b"c" * 64
        self.assertTrue(redis_migration.is_allowed_key(nonce_key, allowed, forbidden))
        for key in (
            b"refresh_token:" + b"a" * 64,
            b"user_refresh_tokens:1",
            b"token_family:" + b"b" * 32,
            b"billing:balance:1",
            b"rpm:u:1:123456",
            b"oauth:token:account",
            b"sched:acc:1",
            b"sticky_session:1:0123456789abcdef",
            b"cyber_session_block:" + b"c" * 64,
            b"masked_session:1",
            b"concurrency:account:1",
            b"wait:account:1",
            b"umq:{1}:lock",
        ):
            self.assertFalse(redis_migration.is_allowed_key(key, allowed, forbidden))
            self.assertTrue(redis_migration.is_discarded_key(key, discarded))
        self.assertFalse(
            redis_migration.is_discarded_key(b"scheduler_outbox:deadbeef", discarded)
        )
        for key in (
            b"openai:response:request-id",
            b"sub2api:prompt_audit:payload:1",
            b"content_moderation:flagged_hashes",
            b"image_task:1",
            b"unknown:key",
        ):
            self.assertFalse(redis_migration.is_allowed_key(key, allowed, forbidden))

        copy_prefixes = {rule.prefix for rule in allowed}
        self.assertEqual(copy_prefixes, {b"sub2api-sync:nonce:"})
        self.assertNotIn(b"oauth:token:", copy_prefixes)
        self.assertNotIn(b"sticky_session:", copy_prefixes)
        self.assertNotIn(b"scheduler_outbox:", copy_prefixes)

    def test_redis_protocol_encoder_preserves_binary_dump_payloads(self):
        redis_migration = load_python_script(REDIS_MIGRATION, "redis_protocol")
        payload = b"\x00\xff\r\nserialized-value\x00"
        encoded = redis_migration.encode_command(b"RESTORE", b"key", 0, payload)
        self.assertIn(payload, encoded)
        self.assertTrue(encoded.startswith(b"*4\r\n"))
        self.assertEqual(encoded.count(payload), 1)

    def test_redis_scan_rejects_unknown_keys_before_target_access(self):
        redis_migration = load_python_script(REDIS_MIGRATION, "redis_scan_gate")
        allowed, discarded, forbidden = redis_migration.load_prefix_policy(REDIS_POLICY)

        class Endpoint:
            database = 0

        class Source:
            endpoint = Endpoint()

            def execute(self, command, *args):
                if command == "INFO":
                    return b"redis_version:8.8.0\r\nrun_id:source\r\n"
                if command == "SCAN":
                    return [b"0", [b"billing:balance:1", b"openai:response:1"]]
                raise AssertionError((command, args))

        class Target:
            endpoint = Endpoint()

            def __init__(self):
                self.commands = []

            def execute(self, *parts):
                self.commands.append(parts)
                raise AssertionError("target was accessed before the source scan passed")

        target = Target()
        with self.assertRaisesRegex(
            redis_migration.MigrationError, "unknown Redis key prefix"
        ):
            redis_migration.migrate_redis(
                Source(), target, allowed, discarded, forbidden
            )
        self.assertEqual(target.commands, [])

    def test_redis_migration_restores_only_ttl_nonce_into_fsync_always_aof(self):
        redis_migration = load_python_script(REDIS_MIGRATION, "redis_restore")
        allowed, discarded, forbidden = redis_migration.load_prefix_policy(REDIS_POLICY)
        key = b"sub2api-sync:nonce:" + b"a" * 64
        payload = b"\x00\xff\r\nserialized-value\x00"

        class Endpoint:
            database = 0

        class Source:
            endpoint = Endpoint()

            def execute(self, command, *args):
                responses = {
                    "INFO": b"redis_version:8.8.0\r\nrun_id:source\r\n",
                    "SCAN": [b"0", [key]],
                    "TYPE": b"string",
                    "GET": b"1",
                    "DUMP": payload,
                    "PTTL": 60_000,
                }
                return responses[command]

        class Target:
            endpoint = Endpoint()

            def __init__(self):
                self.commands = []

            def execute(self, command, *args):
                self.commands.append((command, args))
                if command == "INFO":
                    return b"redis_version:8.8.0\r\nrun_id:target\r\n"
                if command == "DBSIZE":
                    return 0
                if command == "CONFIG":
                    values = {
                        "appendonly": b"yes",
                        "appendfsync": b"always",
                        "save": b"",
                        "maxmemory": b"33554432",
                        "maxmemory-policy": b"noeviction",
                    }
                    return [args[-1].encode(), values[args[-1]]]
                return b"OK"

        target = Target()
        redis_migration.migrate_redis(
            Source(), target, allowed, discarded, forbidden
        )
        self.assertIn(("RESTORE", (key, 60_000, payload)), target.commands)
        self.assertNotIn(("SAVE", ()), target.commands)
        self.assertFalse(any(command == "CONFIG" and args[:1] == ("SET",)
                             for command, args in target.commands))

    def test_redis_restore_timeout_rolls_back_the_ambiguous_key(self):
        redis_migration = load_python_script(REDIS_MIGRATION, "redis_restore_timeout")
        allowed, discarded, forbidden = redis_migration.load_prefix_policy(REDIS_POLICY)
        key = b"sub2api-sync:nonce:" + b"b" * 64

        class Endpoint:
            database = 0

        class Source:
            endpoint = Endpoint()

            def execute(self, command, *args):
                responses = {
                    "INFO": b"redis_version:8.8.0\r\nrun_id:source\r\n",
                    "SCAN": [b"0", [key]],
                    "TYPE": b"string",
                    "GET": b"1",
                    "DUMP": b"serialized",
                    "PTTL": 60_000,
                }
                return responses[command]

        class Target:
            endpoint = Endpoint()

            def __init__(self):
                self.commands = []

            def execute(self, command, *args):
                self.commands.append((command, args))
                if command == "INFO":
                    return b"redis_version:8.8.0\r\nrun_id:target\r\n"
                if command == "DBSIZE":
                    return 0
                if command == "CONFIG":
                    values = {
                        "appendonly": b"yes",
                        "appendfsync": b"always",
                        "save": b"",
                        "maxmemory": b"33554432",
                        "maxmemory-policy": b"noeviction",
                    }
                    return [args[-1].encode(), values[args[-1]]]
                if command == "RESTORE":
                    raise TimeoutError("response lost after commit")
                return 1

        target = Target()
        with self.assertRaises(TimeoutError):
            redis_migration.migrate_redis(
                Source(), target, allowed, discarded, forbidden
            )
        self.assertIn(("UNLINK", (key,)), target.commands)

    def test_redis_discards_raw_access_tokens_and_content_derived_sessions(self):
        redis_migration = load_python_script(REDIS_MIGRATION, "redis_discard")
        allowed, discarded, forbidden = redis_migration.load_prefix_policy(REDIS_POLICY)
        keys = [
            b"refresh_token:" + b"a" * 64,
            b"billing:balance:1",
            b"oauth:token:account-1",
            b"sticky_session:1:0123456789abcdef",
            b"cyber_session_block:" + b"c" * 64,
            b"masked_session:1",
            b"sched:acc:1",
            b"concurrency:account:1",
            b"wait:account:1",
            b"umq:{1}:lock",
        ]

        class Source:
            def execute(self, command, *args):
                if command == "SCAN":
                    return [b"0", keys]
                raise AssertionError("discarded values must never be read")

        copied, discarded_count = redis_migration.scan_source_keys(
            Source(), allowed, discarded, forbidden
        )
        self.assertEqual(copied, [])
        self.assertEqual(discarded_count, len(keys))

    def test_redis_value_shape_is_verified_before_target_access(self):
        redis_migration = load_python_script(REDIS_MIGRATION, "redis_value_gate")
        allowed, discarded, forbidden = redis_migration.load_prefix_policy(REDIS_POLICY)
        key = b"sub2api-sync:nonce:" + b"d" * 64

        class Endpoint:
            database = 0

        class Source:
            endpoint = Endpoint()

            def execute(self, command, *args):
                responses = {
                    "INFO": b"redis_version:8.8.0\r\nrun_id:source\r\n",
                    "SCAN": [b"0", [key]],
                    "TYPE": b"string",
                    "GET": b"not-a-marker",
                }
                return responses[command]

        class Target:
            endpoint = Endpoint()

            def __init__(self):
                self.commands = []

            def execute(self, *parts):
                self.commands.append(parts)
                raise AssertionError("target was accessed before value validation passed")

        target = Target()
        with self.assertRaisesRegex(redis_migration.MigrationError, "marker value is invalid"):
            redis_migration.migrate_redis(
                Source(), target, allowed, discarded, forbidden
            )
        self.assertEqual(target.commands, [])

    def test_redis_target_requires_named_one_time_migration_principal(self):
        source = REDIS_MIGRATION.read_text()
        self.assertIn('MIGRATION_USERNAME = "sub2api_migration"', source)
        self.assertIn('("AUTH", self.username, self.password)', source)
        self.assertIn("appendfsync", source)
        self.assertNotIn('target.execute("SAVE")', source)

    def test_app_metadata_validator_accepts_pricing_and_rejects_content(self):
        app_migration = load_python_script(APP_MIGRATION, "app_migration")
        valid = {
            "gpt-example": {
                "input_cost_per_token": 0.000001,
                "output_cost_per_token": 0.000002,
                "litellm_provider": "openai",
            }
        }
        normalized = app_migration.validate_model_pricing(
            json.dumps(valid).encode("utf-8")
        )
        self.assertEqual(normalized, valid)

        unsafe = {
            "gpt-example": {
                "input_cost_per_token": 0.000001,
                "prompt": "conversation text",
            }
        }
        with self.assertRaisesRegex(ValueError, "unsupported field"):
            app_migration.validate_model_pricing(
                json.dumps(unsafe).encode("utf-8")
            )

        for field, value in (
            ("notes", "conversation text"),
            ("description", "conversation text"),
            ("provider_specific_entry", {"prompt": "conversation text"}),
        ):
            with self.subTest(field=field):
                invalid = {
                    "gpt-example": {
                        "input_cost_per_token": 0.000001,
                        field: value,
                    }
                }
                with self.assertRaisesRegex(ValueError, "unsupported field"):
                    app_migration.validate_model_pricing(
                        json.dumps(invalid).encode("utf-8")
                    )

    def test_app_metadata_copy_is_atomic_and_owned_by_sub2api(self):
        app_migration = load_python_script(APP_MIGRATION, "app_migration_owner")
        pricing = {
            "gpt-example": {
                "input_cost_per_token": 0.000001,
                "output_cost_per_token": 0.000002,
                "litellm_provider": "openai",
            }
        }
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "sub2api-gate"
            target = root / "app"
            source = pathlib.Path(directory) / "source"
            target.mkdir(parents=True, mode=0o700)
            root.chmod(0o700)
            target.chmod(0o700)
            source.mkdir()
            (source / "model_pricing.json").write_text(json.dumps(pricing))
            app_migration.EXPECTED_DATA_ROOT = root
            app_migration.DATA_ROOT_UID = os.getuid()
            app_migration.DATA_ROOT_GID = os.getgid()
            app_migration.APP_UID = os.getuid()
            app_migration.APP_GID = os.getgid()
            with mock.patch.dict(
                os.environ,
                {
                    "SUB2API_DATA_ROOT": str(root),
                    "SUB2API_COPY_MODEL_PRICING": "YES",
                    "SUB2API_SOURCE_APP_DIR": str(source),
                },
                clear=False,
            ):
                copied = app_migration.migrate_app_metadata(time.monotonic() + 10)

            self.assertEqual(copied, 1)
            destination = target / "model_pricing.json"
            info = destination.stat()
            self.assertEqual((info.st_uid, info.st_gid), (os.getuid(), os.getgid()))
            self.assertEqual(info.st_mode & 0o777, 0o600)
            marker_info = (target / ".installed").stat()
            self.assertEqual(
                (marker_info.st_uid, marker_info.st_gid),
                (os.getuid(), os.getgid()),
            )
            self.assertEqual(marker_info.st_mode & 0o777, 0o400)
            self.assertNotIn("password", (target / ".installed").read_text())
            self.assertFalse(any(".partial-" in item.name for item in target.iterdir()))

            destination.unlink()
            (target / ".installed").unlink()
            target.chmod(0o750)
            with mock.patch.dict(
                os.environ,
                {
                    "SUB2API_DATA_ROOT": str(root),
                    "SUB2API_COPY_MODEL_PRICING": "NO",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(
                    app_migration.MigrationError, "owned by 1000:1000 with mode 0700"
                ):
                    app_migration.migrate_app_metadata(time.monotonic() + 10)

    def test_app_metadata_requires_a_private_real_data_root(self):
        app_migration = load_python_script(APP_MIGRATION, "app_migration_root")
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory)
            root = parent / "sub2api-gate"
            app = root / "app"
            app.mkdir(parents=True, mode=0o700)
            root.chmod(0o750)
            app_migration.EXPECTED_DATA_ROOT = root
            app_migration.DATA_ROOT_UID = os.getuid()
            app_migration.DATA_ROOT_GID = os.getgid()
            with mock.patch.dict(
                os.environ,
                {
                    "SUB2API_DATA_ROOT": str(root),
                    "SUB2API_COPY_MODEL_PRICING": "NO",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(
                    app_migration.MigrationError, "root:root with mode 0700"
                ):
                    app_migration.migrate_app_metadata(time.monotonic() + 10)

            root.chmod(0o700)
            alias = parent / "data-root-alias"
            alias.symlink_to(root, target_is_directory=True)
            with mock.patch.dict(
                os.environ,
                {
                    "SUB2API_DATA_ROOT": str(alias),
                    "SUB2API_COPY_MODEL_PRICING": "NO",
                },
                clear=False,
            ):
                with self.assertRaisesRegex(
                    app_migration.MigrationError,
                    "must be /mnt/data/sub2api-gate",
                ):
                    app_migration.migrate_app_metadata(time.monotonic() + 10)

    def test_redis_migration_requires_private_data_and_nonce_directories(self):
        redis_migration = load_python_script(REDIS_MIGRATION, "redis_storage_gate")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "sub2api-gate"
            redis_root = root / "redis"
            nonce = redis_root / "nonce"
            nonce.mkdir(parents=True, mode=0o700)
            root.chmod(0o700)
            redis_root.chmod(0o700)
            nonce.chmod(0o700)
            redis_migration.EXPECTED_DATA_ROOT = root
            redis_migration.DATA_ROOT_UID = os.getuid()
            redis_migration.DATA_ROOT_GID = os.getgid()
            redis_migration.REDIS_UID = os.getuid()
            redis_migration.REDIS_GID = os.getgid()
            with mock.patch.dict(
                os.environ, {"SUB2API_DATA_ROOT": str(root)}, clear=False
            ):
                self.assertEqual(
                    redis_migration.require_private_migration_storage(), nonce
                )
                nonce.chmod(0o750)
                with self.assertRaisesRegex(
                    redis_migration.MigrationError,
                    "nonce directory must be owned by 999:1000 with mode 0700",
                ):
                    redis_migration.require_private_migration_storage()

    def test_safe_export_uses_one_exported_read_only_snapshot(self):
        script = SAFE_EXPORT.read_text()
        self.assertIn("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", script)
        self.assertIn("pg_export_snapshot()", script)
        self.assertIn("SET TRANSACTION SNAPSHOT", script)
        self.assertIn("--snapshot=", script)
        self.assertIn('cat "$portability_gate"', script)
        self.assertIn(".partial-", script)
        self.assertIn("SHA256SUMS", script)
        self.assertIn("COMPLETE", script)
        self.assertIn("manifest.json.partial", script)
        self.assertIn("source_postgres_identity", script)
        self.assertIn("source_postgres_database_oid", script)
        self.assertIn("source_postgres_database_name_hex", script)
        self.assertIn("policy_files", script)
        self.assertIn("HEAD^{commit}", script)
        self.assertIn('require_private_directory "$data_root" "0:0:700"', script)
        self.assertIn('require_private_directory "$backup_root" "0:0:700"', script)
        self.assertLess(
            script.index('require_private_directory "$data_root" "0:0:700"'),
            script.index("coproc SNAPSHOT_HOLDER"),
        )
        self.assertIn("deploy/verify-migration-totp.py", script)
        self.assertIn("deploy/source-postgres-exec.py", script)
        self.assertIn("safe_export_deadline_seconds=600", script)
        self.assertIn("safe_export_min_free_bytes=10737418240", script)
        self.assertIn("safe_export_max_output_bytes=4294967296", script)
        self.assertIn('"$TIMEOUT" --foreground -s TERM -k 5', script)
        self.assertIn("prlimit --fsize=", script)
        self.assertIn("df --output=avail --block-size=1", script)
        self.assertIn("du --apparent-size --summarize --block-size=1", script)
        self.assertGreaterEqual(script.count("require_fresh_capacity"), 4)
        self.assertGreaterEqual(script.count("require_output_bound"), 3)
        self.assertLess(
            script.index("require_fresh_capacity"),
            script.index("coproc SNAPSHOT_HOLDER"),
        )
        self.assertLess(
            script.rindex("require_fresh_capacity"),
            script.index('mv "$partial_dir" "$final_dir"'),
        )

    def test_safe_export_uses_only_the_private_source_database_identity(self):
        script = SAFE_EXPORT.read_text()
        self.assertIn("--env-file ABSOLUTE_PATH", script)
        self.assertIn("safe metadata export --apply requires --env-file", script)
        self.assertIn('source_pg_exec="$repo_dir/deploy/source-postgres-exec.py"', script)
        self.assertIn("--source-app-container", script)
        self.assertIn("--source-app-id", script)
        self.assertIn("--source-postgres-container", script)
        self.assertIn("--source-postgres-id", script)
        self.assertIn("--source-app-state running", script)
        self.assertNotIn("--source-private-env-file", script)
        self.assertNotIn("SUB2API_DATABASE_URL", script)
        self.assertNotIn('--file "$runtime_logging_gate"', script)

        missing_env = "/private/path/not-opened-by-safe-export-check.env"
        result = subprocess.run(
            ["bash", SAFE_EXPORT, "check", "--env-file", missing_env],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("private environment file was not read", result.stdout)

    def test_postgres_portability_gate_rejects_fdw_and_unreviewed_extensions(self):
        gate = PORTABILITY_GATE.read_text()
        self.assertIn("pg_catalog.pg_extension", gate)
        self.assertIn(
            "NOT IN ('plpgsql', 'pgcrypto', 'pg_trgm')",
            gate,
        )
        for catalog in (
            "pg_foreign_data_wrapper",
            "pg_foreign_server",
            "pg_user_mapping",
            "pg_foreign_table",
        ):
            self.assertIn(f"pg_catalog.{catalog}", gate)
        self.assertNotIn("srvoptions", gate)
        self.assertNotIn("umoptions", gate)


if __name__ == "__main__":
    unittest.main()
