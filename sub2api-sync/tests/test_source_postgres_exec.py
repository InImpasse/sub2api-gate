import contextlib
import importlib.util
import io
import json
import pathlib
import subprocess
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "source-postgres-exec.py"


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SourcePostgresExecTests(unittest.TestCase):
    def binding_harness(self, tool, **changes):
        values = {
            "source_url": (
                "postgresql://sub2api:unused-password@172.19.0.2:5432/sub2api"
                "?sslmode=disable"
            ),
            "postgres_identity": "b" * 64,
            "postgres_running": "true",
            "postgres_networks": {
                "legacy": {
                    "IPAddress": "172.19.0.2",
                    "Aliases": ["legacy-postgres", "postgres"],
                }
            },
            "app_identity": "a" * 64,
            "app_running": "true",
            "app_networks": {
                "legacy": {
                    "IPAddress": "172.19.0.3",
                    "Aliases": ["legacy-app"],
                }
            },
            "postgres_environment": "POSTGRES_USER=sub2api\nPOSTGRES_DB=sub2api\n",
            "app_environment": (
                "DATABASE_HOST=postgres\n"
                "DATABASE_PORT=5432\n"
                "DATABASE_DBNAME=sub2api\n"
            ),
            "control_identity": "1234567890123456789",
            "database_identity": "1234567890123456789|16384|73756232617069",
            "target_host": "127.0.0.1",
            "target_port": "15432",
            "target_database": "sub2api",
            "application_database": "sub2api",
        }
        values.update(changes)
        calls = []
        private_values = {
            "SUB2API_SOURCE_DATABASE_URL": values["source_url"],
            "SUB2API_TARGET_DATABASE_URL": (
                "postgresql://target:target-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable"
            ),
            "SUB2API_DATABASE_URL": (
                "postgresql://app:app-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable"
            ),
        }

        def runner(argv, **_kwargs):
            calls.append(list(argv))
            if argv[:3] == [str(tool.DOCKER_BINARY), "inspect", "--format"]:
                template = argv[3]
                container = argv[4]
                if "NetworkSettings.Networks" in template:
                    if container == "legacy-postgres":
                        parts = (
                            values["postgres_identity"],
                            "/legacy-postgres",
                            values["postgres_running"],
                            json.dumps(values["postgres_networks"]),
                        )
                    else:
                        parts = (
                            values["app_identity"],
                            "/legacy-app",
                            values["app_running"],
                            json.dumps(values["app_networks"]),
                        )
                    return types.SimpleNamespace(returncode=0, stdout="|".join(parts) + "\n")
                return types.SimpleNamespace(
                    returncode=0,
                    stdout=(
                        values["postgres_environment"]
                        if container in {"legacy-postgres", values["postgres_identity"]}
                        else values["app_environment"]
                    ),
                )
            if argv[:2] == [str(tool.DOCKER_BINARY), "exec"] and "pg_controldata" in argv[-1]:
                return types.SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "Database system identifier: "
                        + values["control_identity"]
                        + "\n"
                    ),
                )
            if argv[:2] == [str(tool.DOCKER_BINARY), "exec"]:
                return types.SimpleNamespace(
                    returncode=0, stdout=values["database_identity"] + "\n"
                )
            raise AssertionError(argv)

        private_module = types.SimpleNamespace(
            read_private_environment=lambda _path: private_values
        )
        pg_module = types.SimpleNamespace(
            libpq_environment=lambda _environment, name: {
                "PGHOST": values["target_host"],
                "PGPORT": values["target_port"],
                "PGDATABASE": (
                    values["target_database"]
                    if name == "SUB2API_TARGET_DATABASE_URL"
                    else values["application_database"]
                ),
            }
        )
        options = types.SimpleNamespace(
            env_file=pathlib.Path("/private/sub2api.env"),
            source_app_container="legacy-app",
            source_app_id="a" * 64,
            source_postgres_container="legacy-postgres",
            source_postgres_id="b" * 64,
            source_app_state="running",
        )
        patches = (
            mock.patch.object(tool, "load_private_env_tool", return_value=private_module),
            mock.patch.object(tool, "load_pg_env_tool", return_value=pg_module),
        )
        return options, runner, patches, calls

    def test_exact_legacy_container_and_shared_network_are_accepted(self):
        tool = load_tool("source_postgres_exec_valid")
        postgres_id = "b" * 64
        app_id = "a" * 64
        calls = []

        private_values = {
            "SUB2API_SOURCE_DATABASE_URL": (
                "postgresql://sub2api:unused-password@172.19.0.2:5432/sub2api"
                "?sslmode=disable"
            ),
            "SUB2API_TARGET_DATABASE_URL": (
                "postgresql://target:target-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable"
            ),
            "SUB2API_DATABASE_URL": (
                "postgresql://app:app-password@127.0.0.1:15432/sub2api"
                "?sslmode=disable"
            ),
        }

        def runner(argv, **_kwargs):
            calls.append(list(argv))
            if argv[:3] == [str(tool.DOCKER_BINARY), "inspect", "--format"]:
                template = argv[3]
                container = argv[4]
                if "NetworkSettings.Networks" in template:
                    if container == "legacy-postgres":
                        return types.SimpleNamespace(
                            returncode=0,
                            stdout=(
                                postgres_id
                                + "|/legacy-postgres|true|"
                                + json.dumps(
                                    {
                                        "legacy": {
                                            "IPAddress": "172.19.0.2",
                                            "Aliases": ["legacy-postgres", "postgres"],
                                        }
                                    }
                                )
                                + "\n"
                            ),
                        )
                    return types.SimpleNamespace(
                        returncode=0,
                        stdout=(
                            app_id
                            + "|/legacy-app|true|"
                            + json.dumps(
                                {
                                    "legacy": {
                                        "IPAddress": "172.19.0.3",
                                        "Aliases": ["legacy-app"],
                                    }
                                }
                            )
                            + "\n"
                        ),
                    )
                if container in {"legacy-postgres", postgres_id}:
                    return types.SimpleNamespace(
                        returncode=0,
                        stdout="POSTGRES_USER=sub2api\nPOSTGRES_DB=sub2api\n",
                    )
                return types.SimpleNamespace(
                    returncode=0,
                    stdout=(
                        "DATABASE_HOST=postgres\n"
                        "DATABASE_PORT=5432\n"
                        "DATABASE_DBNAME=sub2api\n"
                    ),
                )
            if argv[:2] == [str(tool.DOCKER_BINARY), "exec"] and "pg_controldata" in argv[-1]:
                return types.SimpleNamespace(
                    returncode=0,
                    stdout="Database system identifier: 1234567890123456789\n",
                )
            if argv[:2] == [str(tool.DOCKER_BINARY), "exec"]:
                return types.SimpleNamespace(
                    returncode=0,
                    stdout="1234567890123456789|16384|73756232617069\n",
                )
            raise AssertionError(argv)

        private_module = types.SimpleNamespace(
            read_private_environment=lambda _path: private_values
        )
        pg_module = types.SimpleNamespace(
            libpq_environment=lambda environment, name: {
                "PGHOST": "127.0.0.1",
                "PGPORT": "15432",
                "PGDATABASE": "sub2api",
            }
        )
        options = types.SimpleNamespace(
            env_file=pathlib.Path("/private/sub2api.env"),
            source_app_container="legacy-app",
            source_app_id=app_id,
            source_postgres_container="legacy-postgres",
            source_postgres_id=postgres_id,
            source_app_state="running",
        )
        with mock.patch.object(
            tool, "load_private_env_tool", return_value=private_module
        ), mock.patch.object(tool, "load_pg_env_tool", return_value=pg_module):
            binding = tool.verify_source_binding(options, runner=runner)

        self.assertEqual(binding.system_identifier, "1234567890123456789")
        self.assertEqual(binding.database_oid, "16384")
        self.assertEqual(binding.database_name_hex, "73756232617069")
        self.assertEqual(binding.postgres_id, postgres_id)
        self.assertTrue(all("unused-password" not in " ".join(call) for call in calls))

    def test_source_url_rejects_dns_loopback_socket_ipv6_and_target_port_aliases(self):
        tool = load_tool("source_postgres_exec_url_aliases")
        authorities = (
            "localhost:5432",
            "127.0.0.1:5432",
            "127.1.2.3:5432",
            "[::1]:5432",
            "db.internal:5432",
            "172.19.0.2:15432",
            "%2Fvar%2Frun%2Fpostgresql:5432",
            "203.0.113.9:5432",
        )
        for authority in authorities:
            with self.subTest(authority=authority), self.assertRaises(
                tool.SourcePostgresError
            ):
                tool.parse_source_url(
                    f"postgresql://sub2api:private-value@{authority}/sub2api"
                    "?sslmode=disable"
                )

    def test_argument_parser_requires_absolute_path_full_ids_and_allowed_client(self):
        tool = load_tool("source_postgres_exec_arguments")
        base = [
            "--env-file",
            "/private/sub2api.env",
            "--source-app-container",
            "legacy-app",
            "--source-app-id",
            "a" * 64,
            "--source-postgres-container",
            "legacy-postgres",
            "--source-postgres-id",
            "b" * 64,
            "--source-app-state",
            "running",
        ]
        poisoned = (
            [*base[:1], "relative.env", *base[2:], "identity"],
            [*base[:5], "a" * 63, *base[6:], "identity"],
            [*base[:9], "B" * 64, *base[10:], "identity"],
            [*base, "shell"],
        )
        for argv in poisoned:
            with self.subTest(argv=argv), contextlib.redirect_stderr(
                io.StringIO()
            ), self.assertRaises(SystemExit):
                tool.parse_arguments(argv)

    def test_command_validation_never_echoes_an_accidental_database_url(self):
        sentinel = "postgresql://operator:accidental-secret@10.0.0.2:5432/sub2api"
        result = subprocess.run(
            [TOOL_PATH, f"--database-url={sentinel}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertNotIn(sentinel, result.stdout + result.stderr)
        self.assertIn("command validation failed", result.stderr)

    def test_container_state_network_and_identity_poisoning_fail_closed(self):
        tool = load_tool("source_postgres_exec_runtime_poisoning")
        cases = (
            {"postgres_identity": "c" * 64},
            {"postgres_running": "false"},
            {"app_running": "false"},
            {
                "app_networks": {
                    "other": {"IPAddress": "172.20.0.3", "Aliases": ["legacy-app"]}
                }
            },
            {
                "postgres_networks": {
                    "legacy": {
                        "IPAddress": "172.19.0.9",
                        "Aliases": ["postgres"],
                    }
                }
            },
            {"control_identity": "1234567890123456788"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                options, runner, patches, _calls = self.binding_harness(tool, **changes)
                with patches[0], patches[1], self.assertRaises(tool.SourcePostgresError):
                    tool.verify_source_binding(options, runner=runner)

    def test_database_configuration_poisoning_fails_without_credentials_in_error(self):
        tool = load_tool("source_postgres_exec_database_poisoning")
        cases = (
            {"postgres_environment": "POSTGRES_USER=other\nPOSTGRES_DB=sub2api\n"},
            {
                "postgres_environment": (
                    "POSTGRES_USER=sub2api\nPOSTGRES_USER=sub2api\nPOSTGRES_DB=sub2api\n"
                )
            },
            {"postgres_environment": "POSTGRES_USER=sub2api\nBROKEN=value\n"},
            {"app_environment": "DATABASE_HOST=other\nDATABASE_PORT=5432\nDATABASE_DBNAME=sub2api\n"},
            {"app_environment": "DATABASE_HOST=postgres\nDATABASE_PORT=5433\nDATABASE_DBNAME=sub2api\n"},
            {"app_environment": "DATABASE_HOST=postgres\nDATABASE_PORT=5432\nDATABASE_DBNAME=other\n"},
            {"database_identity": "1234567890123456788|16384|73756232617069"},
            {"database_identity": "1234567890123456789|16384|6f74686572"},
            {"target_host": "localhost"},
            {"target_port": "5432"},
            {"application_database": "other"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                options, runner, patches, calls = self.binding_harness(tool, **changes)
                with patches[0], patches[1], self.assertRaises(
                    tool.SourcePostgresError
                ) as raised:
                    tool.verify_source_binding(options, runner=runner)
                self.assertNotIn("unused-password", str(raised.exception))
            self.assertTrue(
                all("unused-password" not in " ".join(call) for call in calls)
            )

    def test_environment_reads_stay_pinned_to_verified_container_ids(self):
        tool = load_tool("source_postgres_exec_name_replacement")
        options, runner, patches, calls = self.binding_harness(tool)

        with patches[0], patches[1]:
            binding = tool.verify_source_binding(options, runner=runner)

        self.assertEqual(binding.postgres_id, options.source_postgres_id)
        environment_inspects = [
            call
            for call in calls
            if call[:3] == [str(tool.DOCKER_BINARY), "inspect", "--format"]
            and "NetworkSettings.Networks" not in call[3]
        ]
        self.assertEqual(
            [call[4] for call in environment_inspects],
            [options.source_postgres_id, options.source_app_id],
        )
        self.assertNotIn(options.source_postgres_container, environment_inspects[0][4:])
        self.assertNotIn(options.source_app_container, environment_inspects[1][4:])

    def test_client_builder_uses_exact_positive_option_allowlists(self):
        tool = load_tool("source_postgres_exec_client_boundary")
        binding = tool.SourceBinding(
            "b" * 64,
            "sub2api",
            "sub2api",
            "1234567890123456789",
            "16384",
            "73756232617069",
        )
        with self.assertRaises(tool.SourcePostgresError):
            tool.docker_client_command(binding, "sh", (), "")
        with self.assertRaises(tool.SourcePostgresError):
            tool.docker_client_command(binding, "psql", ("x" * 4097,), "")
        connection_overrides = (
            ("-h", "other"),
            ("-hother",),
            ("-p5433",),
            ("-Uother",),
            ("-dother",),
            ("--host=other",),
            ("--port", "5433"),
            ("--username=other",),
            ("--dbname", "other"),
            ("--password",),
            ("--file", "/host/private.sql"),
            ("--hos=other",),
            ("--por=5433",),
            ("--user=other",),
            ("--dbn=other",),
            ("--pass",),
            ("--fi=/host/private.sql",),
            ("--output=/tmp/query-output",),
            ("--log-file=/tmp/query-log",),
            ("-o", "/tmp/query-output"),
            ("positional-database",),
        )
        for arguments in connection_overrides:
            with self.subTest(arguments=arguments), self.assertRaises(
                tool.SourcePostgresError
            ):
                tool.docker_client_command(binding, "psql", arguments, "")
        psql_arguments = (
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--field-separator=|",
            "-v",
            "ON_ERROR_STOP=1",
            "--command",
            "SELECT 1",
        )
        command = tool.docker_client_command(
            binding, "psql", psql_arguments, "-c statement_timeout=5000"
        )
        self.assertNotIn("unused-password", " ".join(command))
        self.assertIn("--host=/var/run/postgresql", command)
        self.assertEqual(
            command[command.index("psql") + 1:][:len(psql_arguments)],
            list(psql_arguments),
        )

        pg_dump_arguments = (
            "--format=plain",
            "--encoding=UTF8",
            "--no-owner",
            "--no-privileges",
            "--no-comments",
            "--no-security-labels",
            "--no-tablespaces",
            "--no-publications",
            "--no-subscriptions",
            "--no-large-objects",
            "--serializable-deferrable",
            "--schema-only",
            "--snapshot=00000003-0000001B-1",
        )
        dump_command = tool.docker_client_command(
            binding, "pg_dump", pg_dump_arguments, ""
        )
        self.assertEqual(
            dump_command[dump_command.index("pg_dump") + 1:][:len(pg_dump_arguments)],
            list(pg_dump_arguments),
        )

        invalid_allowlisted_values = (
            ("psql", ("--set", "OTHER=value")),
            ("psql", ("--field-separator=,",)),
            ("pg_dump", ("--format=custom",)),
            ("pg_dump", ("--encoding=LATIN1",)),
            ("pg_dump", ("--snapshot=not-a-snapshot",)),
            ("pg_dump", ("--schem",)),
        )
        for client, arguments in invalid_allowlisted_values:
            with self.subTest(client=client, arguments=arguments), self.assertRaises(
                tool.SourcePostgresError
            ):
                tool.docker_client_command(binding, client, arguments, "")

    def test_stopped_app_state_is_accepted_for_the_maintenance_stream(self):
        tool = load_tool("source_postgres_exec_stopped_app")
        options, runner, patches, _calls = self.binding_harness(
            tool, app_running="false"
        )
        options.source_app_state = "stopped"
        with patches[0], patches[1]:
            binding = tool.verify_source_binding(options, runner=runner)
        self.assertEqual(binding.postgres_id, "b" * 64)


if __name__ == "__main__":
    unittest.main()
