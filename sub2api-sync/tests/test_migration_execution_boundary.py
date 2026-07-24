import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest

from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATION_RUNNER = ROOT / "deploy" / "run-database-migration.sh"
SAFE_EXPORT = ROOT / "deploy" / "export-safe-metadata.sh"
SOURCE_EXEC = ROOT / "deploy" / "source-postgres-exec.py"
PG_ENV_EXEC = ROOT / "deploy" / "pg-env-exec.py"


def load_tool(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class MigrationExecutionBoundaryTests(unittest.TestCase):
    @staticmethod
    def apply_arguments():
        return [
            "--env-file",
            "/tmp/not-opened-before-security-gate.env",
            "--source-app-container",
            "sub2api",
            "--source-app-id",
            "a" * 64,
            "--source-postgres-container",
            "sub2api-postgres",
            "--source-postgres-id",
            "b" * 64,
        ]

    def test_apply_shell_entrypoints_reject_before_path_controlled_commands(self):
        cases = (
            (
                MIGRATION_RUNNER,
                ["privacy", "--apply", *self.apply_arguments()],
                "sha256sum",
            ),
            (SAFE_EXPORT, ["--apply", *self.apply_arguments()], "timeout"),
        )
        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            for script, arguments, command_name in cases:
                with self.subTest(script=script.name):
                    marker = directory_path / f"{script.stem}-{command_name}-ran"
                    fake_command = directory_path / command_name
                    fake_command.write_text(
                        "#!/bin/sh\n" f": > {marker}\n" "exit 0\n",
                        encoding="ascii",
                    )
                    fake_command.chmod(0o700)
                    environment = os.environ.copy()
                    environment["PATH"] = f"{directory_path}:/usr/bin:/bin"
                    result = subprocess.run(
                        ["/bin/bash", script, *arguments],
                        cwd=ROOT,
                        env=environment,
                        text=True,
                        capture_output=True,
                        check=False,
                    )
                    self.assertFalse(
                        marker.exists(),
                        result.stdout + result.stderr,
                    )
                    fake_command.unlink()

    def test_source_postgres_pins_the_docker_binary_and_child_environment(self):
        tool = load_tool(SOURCE_EXEC, "source_postgres_execution_boundary")
        environment = tool.docker_environment(
            {
                "PATH": "/tmp/attacker-bin",
                "LD_PRELOAD": "/tmp/attacker-library.so",
                "DOCKER_HOST": "tcp://remote.example:2376",
            }
        )
        self.assertEqual(
            environment,
            {
                "PATH": tool.SAFE_COMMAND_PATH,
                "LANG": "C",
                "LC_ALL": "C",
                "TZ": "UTC",
                "DOCKER_HOST": "unix:///var/run/docker.sock",
            },
        )
        binding = tool.SourceBinding(
            "b" * 64,
            "sub2api",
            "sub2api",
            "1234567890123456789",
            "16384",
            "73756232617069",
        )
        command = tool.docker_client_command(
            binding,
            "psql",
            ("--no-psqlrc", "--quiet", "-v", "ON_ERROR_STOP=1"),
            "",
        )
        self.assertEqual(command[0], str(tool.DOCKER_BINARY))

    def test_source_postgres_main_checks_production_context_before_docker(self):
        tool = load_tool(SOURCE_EXEC, "source_postgres_context_gate")
        arguments = [
            "--env-file",
            "/tmp/never-read.env",
            "--source-app-container",
            "sub2api",
            "--source-app-id",
            "a" * 64,
            "--source-postgres-container",
            "sub2api-postgres",
            "--source-postgres-id",
            "b" * 64,
            "--source-app-state",
            "running",
            "identity",
        ]
        with mock.patch.object(
            tool,
            "require_production_context",
            side_effect=tool.SourcePostgresError("blocked"),
        ) as context_gate, mock.patch.object(tool, "pin_docker_socket") as socket_gate:
            self.assertEqual(tool.main(arguments), 1)
        context_gate.assert_called_once_with()
        socket_gate.assert_not_called()

    def test_pg_environment_wrapper_rejects_other_relative_clients(self):
        tool = load_tool(PG_ENV_EXEC, "pg_env_relative_client")
        with self.assertRaises(tool.ConfigurationError):
            tool.postgres_client_command(["./psql"])
        with self.assertRaises(tool.ConfigurationError):
            tool.postgres_client_command(["pg_dump"])


    def test_pg_environment_wrapper_checks_context_before_private_environment(self):
        tool = load_tool(PG_ENV_EXEC, "pg_env_context_gate")
        with mock.patch.object(
            tool,
            "require_production_context",
            side_effect=tool.ConfigurationError("blocked"),
        ) as context_gate, mock.patch.object(
            tool, "private_libpq_environment"
        ) as private_environment:
            self.assertEqual(
                tool.main(
                    [
                        "--target-private-env-file",
                        "/tmp/never-opened.env",
                        "psql",
                        "--version",
                    ]
                ),
                1,
            )
        context_gate.assert_called_once_with()
        private_environment.assert_not_called()
    def test_pg_environment_root_context_uses_the_trusted_release_gate(self):
        tool = load_tool(PG_ENV_EXEC, "pg_env_root_context")
        source_path = pathlib.Path(tool.__file__).resolve()
        with mock.patch.object(tool.os, "geteuid", return_value=0), \
             mock.patch.object(tool, "REPO_DIR", tool.TRUSTED_RELEASE_ROOT), \
             mock.patch.object(tool, "TRUSTED_CONTROLLER", source_path), \
             mock.patch.object(tool, "require_trusted_release_path") as path_gate:
            tool.require_production_context()
        self.assertEqual(path_gate.call_count, 6)
        self.assertIn(
            mock.call(
                tool.TRUSTED_RELEASE_ROOT / "deploy" / "private_env.py",
                expects_directory=False,
            ),
            path_gate.call_args_list,
        )

    def test_source_postgres_root_context_checks_transitive_helpers(self):
        tool = load_tool(SOURCE_EXEC, "source_postgres_root_context")
        source_path = pathlib.Path(tool.__file__).resolve()
        with mock.patch.object(tool.os, "geteuid", return_value=0), \
             mock.patch.object(tool, "REPO_DIR", tool.TRUSTED_RELEASE_ROOT), \
             mock.patch.object(tool, "TRUSTED_CONTROLLER", source_path), \
             mock.patch.object(tool, "require_trusted_release_path") as path_gate:
            tool.require_production_context()
        self.assertEqual(path_gate.call_count, 7)
        self.assertIn(
            mock.call(
                tool.TRUSTED_RELEASE_ROOT / "deploy" / "private_env.py",
                expects_directory=False,
            ),
            path_gate.call_args_list,
        )
        self.assertIn(
            mock.call(
                tool.TRUSTED_RELEASE_ROOT / "deploy" / "pg-env-exec.py",
                expects_directory=False,
            ),
            path_gate.call_args_list,
        )

    def test_pg_environment_wrapper_uses_a_clean_environment_and_absolute_exec(self):
        tool = load_tool(PG_ENV_EXEC, "pg_env_execution_boundary")
        observed_environment = {}
        exec_call = {}

        def fake_private_environment(environment, _path, _name):
            observed_environment.update(environment)
            return {
                **environment,
                "PGHOST": "127.0.0.1",
                "PGPORT": "15432",
                "PGUSER": "target-user",
                "PGPASSWORD": "test-password",
                "PGDATABASE": "sub2api",
                "PGSSLMODE": "disable",
            }

        def fake_exec(path, arguments, environment):
            exec_call.update(path=path, arguments=arguments, environment=environment)
            raise OSError("test stop")

        with mock.patch.dict(tool.os.environ, {"LD_PRELOAD": "/tmp/injected.so"}, clear=True), \
             mock.patch.object(tool, "require_production_context") as context_gate, \
             mock.patch.object(tool, "private_libpq_environment", fake_private_environment), \
             mock.patch.object(tool.os, "execve", fake_exec, create=True):
            self.assertEqual(
                tool.main(
                    [
                        "--target-private-env-file",
                        "/tmp/private.env",
                        "psql",
                        "--version",
                    ]
                ),
                1,
            )

        context_gate.assert_called_once_with()
        self.assertNotIn("LD_PRELOAD", observed_environment)
        self.assertEqual(observed_environment["PATH"], tool.SAFE_COMMAND_PATH)
        self.assertEqual(exec_call["path"], str(tool.PSQL_BINARY))
        self.assertEqual(exec_call["arguments"][0], str(tool.PSQL_BINARY))
        self.assertNotIn("LD_PRELOAD", exec_call["environment"])


if __name__ == "__main__":
    unittest.main()
