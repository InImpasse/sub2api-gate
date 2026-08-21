import base64
import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
PRIVATE_ENV = ROOT / "deploy" / "private_env.py"
ROLE_CASES = (
    {
        "name": "app",
        "script": ROOT / "deploy" / "prepare-app-role.sh",
        "password_key": "SUB2API_APP_DATABASE_PASSWORD",
        "password": "APP_ROLE_PRIVATE_PASSWORD_SENTINEL_123",
        "sql_files": (
            "000_prepare_app_role.sql",
            "005_app_least_privilege.sql",
            "006_allow_sub2api_schema_migrations.sql",
            "007_allow_sub2api_function_trigger_migrations.sql",
            "008_allow_sub2api_additive_alter_migrations.sql",
            "009_allow_sub2api_deny_list_ddl_guard.sql",
            "sub2api_gate_guard_app_ddl.sql",
        ),
        "error_code": "sub2api_app_role_prepare_failed",
    },
    {
        "name": "sync",
        "script": ROOT / "deploy" / "prepare-sync-role.sh",
        "password_key": "SUB2API_SYNC_DATABASE_PASSWORD",
        "password": "SYNC_ROLE_PRIVATE_PASSWORD_SENTINEL_123",
        "sql_files": ("000_prepare_sync_role.sql",),
        "error_code": "sub2api_sync_role_prepare_failed",
    },
)
AMBIENT_SENTINEL = "AMBIENT_ROLE_SECRET_MUST_NOT_BE_USED_123"
TARGET_URL_SENTINEL = "TARGET_URL_PASSWORD_SENTINEL_123"
TIMEOUT_SENTINEL = "TIMEOUT_DIAGNOSTIC_PRIVATE_SENTINEL"


def write_executable(path, source):
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o700)


class RolePreparationPrivateEnvironmentTests(unittest.TestCase):
    def make_harness(self, directory, case):
        root = pathlib.Path(directory) / "repo"
        deploy = root / "deploy"
        migrations = root / "migrations"
        private = root / "private"
        for path in (deploy, migrations, private):
            path.mkdir(parents=True, mode=0o700)

        shutil.copy2(case["script"], deploy / case["script"].name)
        shutil.copy2(PRIVATE_ENV, deploy / PRIVATE_ENV.name)
        for sql_name in case["sql_files"]:
            (migrations / sql_name).write_text("SELECT 1;\n", encoding="ascii")

        write_executable(
            deploy / "require-clean-worktree.sh",
            """
            #!/usr/bin/env bash
            set -eu
            [ "${1:-}" = "check" ]
            """,
        )

        encoded_password = base64.b64encode(case["password"].encode("ascii")).decode(
            "ascii"
        )
        write_executable(
            deploy / "pg-env-exec.py",
            f"""
            #!/usr/bin/env python3
            import os
            import pathlib
            import sys

            expected = [
                "--target-private-env-file",
                os.environ["FAKE_PRIVATE_ENV"],
                "psql",
                "--quiet",
                "--no-psqlrc",
                "-v",
                "ON_ERROR_STOP=1",
            ]
            if sys.argv[1:] != expected:
                raise SystemExit(91)
            forbidden = {{
                "SUB2API_DATABASE_URL",
                "SUB2API_SOURCE_DATABASE_URL",
                "SUB2API_TARGET_DATABASE_URL",
                "SUB2API_APP_DATABASE_PASSWORD",
                "SUB2API_SYNC_DATABASE_PASSWORD",
            }}
            if not forbidden.isdisjoint(os.environ):
                raise SystemExit(92)
            payload = sys.stdin.read()
            if {encoded_password!r} not in payload:
                raise SystemExit(93)
            if os.environ["FAKE_ROLE_WRAPPER_MODE"] == "fail":
                print({encoded_password!r})
                print(
                    "ALTER ROLE role PASSWORD " + {case["password"]!r},
                    file=sys.stderr,
                )
                raise SystemExit(23)
            pathlib.Path(os.environ["FAKE_ROLE_MARKER"]).touch()
            """,
        )

        env_file = private / "deployment.env"
        env_file.write_text(
            "\n".join(
                (
                    "SUB2API_SOURCE_DATABASE_URL="
                    "postgresql://source:source-password@172.19.0.2:5432/sub2api"
                    "?sslmode=disable",
                    "SUB2API_TARGET_DATABASE_URL="
                    f"postgresql://owner:{TARGET_URL_SENTINEL}"
                    "@127.0.0.1:15432/sub2api?sslmode=disable",
                    "SUB2API_DATABASE_URL="
                    "postgresql://app:app-password@127.0.0.1:15432/sub2api"
                    "?sslmode=disable",
                    "SUB2API_APP_DATABASE_PASSWORD="
                    + (
                        case["password"]
                        if case["password_key"] == "SUB2API_APP_DATABASE_PASSWORD"
                        else "OTHER_APP_ROLE_PASSWORD_SENTINEL_123"
                    ),
                    "SUB2API_SYNC_DATABASE_PASSWORD="
                    + (
                        case["password"]
                        if case["password_key"] == "SUB2API_SYNC_DATABASE_PASSWORD"
                        else "OTHER_SYNC_ROLE_PASSWORD_SENTINEL_123"
                    ),
                    "",
                )
            ),
            encoding="ascii",
        )
        env_file.chmod(0o600)
        marker = root / "role-prepared"
        environment = os.environ.copy()
        environment.update(
            {
                "FAKE_PRIVATE_ENV": str(env_file),
                "FAKE_ROLE_MARKER": str(marker),
                "FAKE_ROLE_WRAPPER_MODE": "success",
                "SUB2API_DATABASE_URL": "postgresql://" + AMBIENT_SENTINEL,
                "SUB2API_SOURCE_DATABASE_URL": "postgresql://" + AMBIENT_SENTINEL,
                "SUB2API_TARGET_DATABASE_URL": "postgresql://" + AMBIENT_SENTINEL,
                "SUB2API_APP_DATABASE_PASSWORD": AMBIENT_SENTINEL,
                "SUB2API_SYNC_DATABASE_PASSWORD": AMBIENT_SENTINEL,
            }
        )
        return deploy / case["script"].name, env_file, marker, environment

    def run_role(self, script, env_file, environment, *, xtrace=False):
        command = [script, "--apply", "--env-file", env_file]
        if xtrace:
            command = ["bash", "-x", *command]
        return subprocess.run(
            command,
            cwd=script.parents[1],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_no_secret(self, result, case):
        output = result.stdout + result.stderr
        self.assertNotIn(case["password"], output)
        self.assertNotIn(
            base64.b64encode(case["password"].encode("ascii")).decode("ascii"),
            output,
        )
        self.assertNotIn(AMBIENT_SENTINEL, output)
        self.assertNotIn(TARGET_URL_SENTINEL, output)

    def test_apply_reads_private_values_over_a_pipe_and_ignores_ambient_values(self):
        for case in ROLE_CASES:
            with self.subTest(role=case["name"]), tempfile.TemporaryDirectory() as directory:
                script, env_file, marker, environment = self.make_harness(
                    directory, case
                )
                result = self.run_role(script, env_file, environment)

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(marker.exists())
                self.assert_no_secret(result, case)

    def test_inherited_xtrace_is_disabled_before_private_values_are_read(self):
        for case in ROLE_CASES:
            with self.subTest(role=case["name"]), tempfile.TemporaryDirectory() as directory:
                script, env_file, marker, environment = self.make_harness(
                    directory, case
                )
                result = self.run_role(
                    script,
                    env_file,
                    environment,
                    xtrace=True,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(marker.exists())
                self.assertIn("+ set +x", result.stderr)
                self.assert_no_secret(result, case)

    def test_database_failure_diagnostics_are_replaced_by_a_stable_error_code(self):
        for case in ROLE_CASES:
            with self.subTest(role=case["name"]), tempfile.TemporaryDirectory() as directory:
                script, env_file, marker, environment = self.make_harness(
                    directory, case
                )
                environment["FAKE_ROLE_WRAPPER_MODE"] = "fail"
                result = self.run_role(script, env_file, environment)

                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertEqual(result.stderr.strip(), case["error_code"])
                self.assert_no_secret(result, case)

    def test_database_timeout_diagnostics_are_replaced_by_the_same_error_code(self):
        for case in ROLE_CASES:
            with self.subTest(role=case["name"]), tempfile.TemporaryDirectory() as directory:
                script, env_file, marker, environment = self.make_harness(
                    directory, case
                )
                fake_bin = pathlib.Path(directory) / "fake-bin"
                fake_bin.mkdir()
                write_executable(
                    fake_bin / "timeout",
                    f"""
                    #!/usr/bin/env python3
                    import os
                    import sys

                    arguments = sys.argv[1:]
                    if arguments[:6] not in (
                        ["--foreground", "-s", "TERM", "-k", "1", "5"],
                        ["--foreground", "-s", "TERM", "-k", "1", "30"],
                    ):
                        raise SystemExit(94)
                    if arguments[5] == "30":
                        print({TIMEOUT_SENTINEL!r})
                        print({case["password"]!r}, file=sys.stderr)
                        raise SystemExit(124)
                    os.execvp(arguments[6], arguments[6:])
                    """,
                )
                environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
                result = self.run_role(script, env_file, environment)

                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertEqual(result.stderr.strip(), case["error_code"])
                self.assertNotIn(TIMEOUT_SENTINEL, result.stdout + result.stderr)
                self.assert_no_secret(result, case)

    def test_private_parser_timeout_is_bounded_and_reports_only_a_stable_code(self):
        for case in ROLE_CASES:
            with self.subTest(role=case["name"]), tempfile.TemporaryDirectory() as directory:
                script, env_file, marker, environment = self.make_harness(
                    directory, case
                )
                fake_bin = pathlib.Path(directory) / "fake-bin"
                fake_bin.mkdir()
                write_executable(
                    fake_bin / "timeout",
                    f"""
                    #!/usr/bin/env python3
                    import sys

                    print({TIMEOUT_SENTINEL!r})
                    print({case["password"]!r}, file=sys.stderr)
                    raise SystemExit(124)
                    """,
                )
                environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
                result = self.run_role(script, env_file, environment)

                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(marker.exists())
                self.assertEqual(
                    result.stderr.strip(),
                    "sub2api_private_environment_load_failed",
                )
                self.assertNotIn(TIMEOUT_SENTINEL, result.stdout + result.stderr)
                self.assert_no_secret(result, case)


if __name__ == "__main__":
    unittest.main()
