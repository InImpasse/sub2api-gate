import importlib.util
import json
import pathlib
import subprocess
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "active-postgres-exec.py"


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ActivePostgresExecTests(unittest.TestCase):
    def binding_harness(self, tool, **changes):
        values = {
            "postgres_identity": "b" * 64,
            "app_identity": "a" * 64,
            "postgres_networks": {
                "production-data": {
                    "IPAddress": "172.20.0.2",
                    "Aliases": ["sub2api-postgres", "postgres"],
                }
            },
            "app_networks": {
                "production-data": {
                    "IPAddress": "172.20.0.3",
                    "Aliases": ["sub2api"],
                },
                "production-egress": {
                    "IPAddress": "172.21.0.3",
                    "Aliases": ["sub2api"],
                },
            },
            "postgres_contract": (
                "healthy|postgres@sha256:" + "1" * 64
                + "|70:70|true|none|sub2api-gate-release|postgres|"
                + "/opt/sub2api-gate-release|"
                + "/opt/sub2api-gate-release/docker-compose.yml|"
                + '{"5432/tcp":null}'
            ),
            "postgres_mounts": [
                {
                    "Type": "bind",
                    "Source": "/mnt/data/sub2api-gate/postgres",
                    "Destination": "/var/lib/postgresql",
                    "RW": True,
                }
            ],
            "app_contract": (
                "healthy|1000:1000|none|sub2api-gate-release|sub2api|"
                "/opt/sub2api-gate-release|"
                "/opt/sub2api-gate-release/docker-compose.yml|"
                '{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"8080"}]}'
            ),
            "postgres_environment": "POSTGRES_USER=sub2api\nPOSTGRES_DB=sub2api\n",
            "app_environment": (
                "DATABASE_HOST=postgres\n"
                "DATABASE_PORT=5432\n"
                "DATABASE_DBNAME=sub2api\n"
            ),
            "image_identity": "sha256:" + "2" * 64,
            "running_image_identity": "sha256:" + "2" * 64,
            "control_identity": "1234567890123456789",
            "database_identity": "1234567890123456789|16384|73756232617069",
            "target_host": "127.0.0.1",
            "target_port": "15432",
            "target_user": "sub2api",
            "target_database": "sub2api",
            "application_database": "sub2api",
        }
        values.update(changes)
        calls = []
        private_values = {
            # This endpoint is intentionally stale after the completed cutover.
            "SUB2API_SOURCE_DATABASE_URL": "not-a-live-source-endpoint",
            "SUB2API_TARGET_DATABASE_URL": (
                "postgresql://sub2api:target-private-sentinel@127.0.0.1:15432/"
                "sub2api?sslmode=disable"
            ),
            "SUB2API_DATABASE_URL": (
                "postgresql://sub2api:app-private-sentinel@127.0.0.1:15432/"
                "sub2api?sslmode=disable"
            ),
        }

        def runner(argv, **_kwargs):
            calls.append(list(argv))
            if argv[:3] == [str(tool.DOCKER_BINARY), "inspect", "--format"]:
                template = argv[3]
                container = argv[4]
                if "NetworkSettings.Networks" in template:
                    if container == tool.POSTGRES_NAME:
                        parts = (
                            values["postgres_identity"],
                            f"/{tool.POSTGRES_NAME}",
                            "true",
                            json.dumps(values["postgres_networks"]),
                        )
                    else:
                        parts = (
                            values["app_identity"],
                            f"/{tool.APP_NAME}",
                            "true",
                            json.dumps(values["app_networks"]),
                        )
                    return types.SimpleNamespace(
                        returncode=0, stdout="|".join(parts) + "\n"
                    )
                if template == tool.POSTGRES_CONTRACT_TEMPLATE:
                    return types.SimpleNamespace(
                        returncode=0,
                        stdout=(
                            values["running_image_identity"]
                            + "|"
                            + values["postgres_contract"]
                            + "\n"
                        ),
                    )
                if template == tool.APP_CONTRACT_TEMPLATE:
                    return types.SimpleNamespace(
                        returncode=0, stdout=values["app_contract"] + "\n"
                    )
                if template == tool.MOUNTS_TEMPLATE:
                    return types.SimpleNamespace(
                        returncode=0,
                        stdout=json.dumps(values["postgres_mounts"]) + "\n",
                    )
                return types.SimpleNamespace(
                    returncode=0,
                    stdout=(
                        values["postgres_environment"]
                        if container == values["postgres_identity"]
                        else values["app_environment"]
                    ),
                )
            if argv[:4] == [
                str(tool.DOCKER_BINARY),
                "image",
                "inspect",
                "--format",
            ]:
                return types.SimpleNamespace(
                    returncode=0, stdout=values["image_identity"] + "\n"
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

        def libpq_environment(_environment, name):
            return {
                "PGHOST": values["target_host"],
                "PGPORT": values["target_port"],
                "PGUSER": values["target_user"],
                "PGPASSWORD": (
                    "target-private-sentinel"
                    if name == "SUB2API_TARGET_DATABASE_URL"
                    else "app-private-sentinel"
                ),
                "PGDATABASE": (
                    values["target_database"]
                    if name == "SUB2API_TARGET_DATABASE_URL"
                    else values["application_database"]
                ),
                "PGSSLMODE": "disable",
            }

        pg_module = types.SimpleNamespace(libpq_environment=libpq_environment)
        options = types.SimpleNamespace(
            env_file=pathlib.Path("/private/sub2api.env"),
            app_id="a" * 64,
            postgres_id="b" * 64,
        )
        patches = (
            mock.patch.object(tool, "load_private_env_tool", return_value=private_module),
            mock.patch.object(tool, "load_pg_env_tool", return_value=pg_module),
            mock.patch.object(
                tool, "reviewed_postgres_image", return_value="postgres@sha256:" + "1" * 64
            ),
        )
        return options, runner, patches, calls

    def test_exact_active_binding_ignores_retired_source_url(self):
        tool = load_tool("active_postgres_exec_valid")
        options, runner, patches, calls = self.binding_harness(tool)
        with patches[0], patches[1], patches[2]:
            binding = tool.verify_active_binding(options, runner=runner)

        self.assertEqual(binding.postgres_id, "b" * 64)
        self.assertEqual(binding.database, "sub2api")
        flattened = "\n".join(" ".join(call) for call in calls)
        self.assertNotIn("target-private-sentinel", flattened)
        self.assertNotIn("app-private-sentinel", flattened)

    def test_runtime_contract_poisoning_fails_closed(self):
        tool = load_tool("active_postgres_exec_poisoning")
        cases = (
            {"postgres_identity": "c" * 64},
            {"running_image_identity": "sha256:" + "3" * 64},
            {"postgres_contract": "unhealthy|bad"},
            {"app_contract": "unhealthy|bad"},
            {"postgres_mounts": []},
            {"target_host": "localhost"},
            {"target_port": "5432"},
            {"target_user": "other"},
            {"application_database": "other"},
            {"app_networks": {}},
            {"control_identity": "1234567890123456788"},
        )
        for changes in cases:
            with self.subTest(changes=changes):
                options, runner, patches, _calls = self.binding_harness(tool, **changes)
                with patches[0], patches[1], patches[2], self.assertRaises(
                    tool.ActivePostgresError
                ):
                    tool.verify_active_binding(options, runner=runner)

    def test_client_command_contains_no_private_url_or_password(self):
        tool = load_tool("active_postgres_exec_client")
        binding = tool.ActiveBinding(
            "b" * 64,
            "sub2api",
            "sub2api",
            "1234567890123456789",
            "16384",
            "73756232617069",
        )
        command = tool.active_client_command(
            binding,
            (
                "--no-psqlrc",
                "--quiet",
                "-v",
                "ON_ERROR_STOP=1",
            ),
            "-c statement_timeout=5000",
        )
        rendered = " ".join(command)
        self.assertNotIn("postgresql://", rendered)
        self.assertNotIn("private-sentinel", rendered)
        self.assertEqual(command[0], str(tool.DOCKER_BINARY))

    def test_argument_errors_never_echo_accidental_credentials(self):
        sentinel = "postgresql://operator:accidental-secret@127.0.0.1/db"
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

    def test_main_checks_production_context_before_private_environment(self):
        tool = load_tool("active_postgres_exec_context")
        arguments = [
            "--env-file",
            "/tmp/never-read.env",
            "--app-id",
            "a" * 64,
            "--postgres-id",
            "b" * 64,
            "identity",
        ]
        with mock.patch.object(
            tool,
            "require_production_context",
            side_effect=tool.ActivePostgresError("blocked"),
        ) as context_gate, mock.patch.object(tool, "pin_docker_socket") as socket_gate:
            self.assertEqual(tool.main(arguments), 1)
        context_gate.assert_called_once_with()
        socket_gate.assert_not_called()

    def test_root_context_checks_every_transitive_helper(self):
        tool = load_tool("active_postgres_exec_root_context")
        source_path = pathlib.Path(tool.__file__).resolve()
        with mock.patch.object(tool.os, "geteuid", return_value=0), \
             mock.patch.object(tool, "REPO_DIR", tool.TRUSTED_RELEASE_ROOT), \
             mock.patch.object(tool, "TRUSTED_CONTROLLER", source_path), \
             mock.patch.object(tool, "require_trusted_release_path") as path_gate:
            tool.require_production_context()
        checked = {call.args[0] for call in path_gate.call_args_list}
        self.assertIn(tool.PRIVATE_ENV_TOOL, checked)
        self.assertIn(tool.PG_ENV_TOOL, checked)
        self.assertIn(tool.SOURCE_HELPER, checked)
        self.assertIn(tool.RELEASE_POLICY, checked)


if __name__ == "__main__":
    unittest.main()
