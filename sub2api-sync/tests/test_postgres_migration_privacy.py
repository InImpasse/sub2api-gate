import os
import pathlib
import shutil
import subprocess
import tempfile
import textwrap
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "deploy" / "migrate-sanitized-postgres.sh"
PG_ENV_EXEC = ROOT / "deploy" / "pg-env-exec.py"
PRIVACY_GATE = ROOT / "migrations" / "verify_no_conversation_content.sql"
TARGET_GATE = ROOT / "deploy" / "verify-sanitized-target.sql"
RUNTIME_LOGGING_GATE = ROOT / "deploy" / "verify-postgres-runtime-logging.sql"
PORTABILITY_GATE = ROOT / "deploy" / "verify-postgres-portability.sql"

PRIVATE_SENTINEL = "PRIVATE_SENTINEL"
SOURCE_PASSWORD = "source-password-private-sentinel"
TARGET_PASSWORD = "target-password-private-sentinel"


def write_executable(path, source):
    path.write_text(textwrap.dedent(source).lstrip(), encoding="utf-8")
    path.chmod(0o700)


class SanitizedPostgresStreamPrivacyTests(unittest.TestCase):
    def make_harness(self, directory):
        root = pathlib.Path(directory) / "repo"
        deploy = root / "deploy"
        migrations = root / "migrations"
        fake_bin = root / "fake-bin"
        counters = root / "counters"
        for path in (deploy, migrations, fake_bin, counters):
            path.mkdir(parents=True, exist_ok=True)

        shutil.copy2(MIGRATION, deploy / MIGRATION.name)
        shutil.copy2(TARGET_GATE, deploy / TARGET_GATE.name)
        shutil.copy2(RUNTIME_LOGGING_GATE, deploy / RUNTIME_LOGGING_GATE.name)
        shutil.copy2(PORTABILITY_GATE, deploy / PORTABILITY_GATE.name)
        shutil.copy2(PRIVACY_GATE, migrations / PRIVACY_GATE.name)

        write_executable(
            deploy / "require-clean-worktree.sh",
            r"""
            #!/bin/sh
            set -eu
            [ "${1:-}" = "check" ]
            printf '%s\n' 'clean Git worktree verified'
            """,
        )
        write_executable(
            deploy / "locked-postgres-stream.py",
            r"""
            #!/usr/bin/env python3
            import os
            import pathlib
            import sys

            mode = os.environ["FAKE_STREAM_FAILURE"]
            counters = pathlib.Path(os.environ["FAKE_COUNTER_DIR"])
            if mode != "portability":
                for name in ("pg_dump", "psql_stream"):
                    counter = counters / name
                    count = int(counter.read_text() if counter.exists() else "0") + 1
                    counter.write_text(str(count))
            private = (
                "PRIVATE_SENTINEL SQL line COPY private_table invalid COPY data "
                "constraint failed postgresql:// password="
                + os.environ["FAKE_SOURCE_PASSWORD"]
                + os.environ["FAKE_TARGET_PASSWORD"]
            )
            print(private)
            print(private, file=sys.stderr)
            raise SystemExit(12 if mode == "portability" else 14)
            """,
        )
        write_executable(
            deploy / "source-postgres-exec.py",
            r"""
            #!/usr/bin/env python3
            import os
            import sys

            arguments = sys.argv[1:]
            expected = [
                "--env-file", os.environ["FAKE_PRIVATE_ENV"],
                "--source-app-container", "legacy-app",
                "--source-app-id", "a" * 64,
                "--source-postgres-container", "legacy-postgres",
                "--source-postgres-id", "b" * 64,
                "--source-app-state", "stopped",
            ]
            if arguments[:len(expected)] != expected:
                raise SystemExit(97)
            command = arguments[len(expected):]
            if command == ["identity"]:
                print("1000000000000000001|16384|736f757263652d6462")
                raise SystemExit(0)
            if not command or command[0] not in {"psql", "pg_dump"}:
                raise SystemExit(98)
            environment = os.environ.copy()
            environment.update({
                "PGHOST": "/var/run/postgresql",
                "PGPORT": "5432",
                "PGUSER": "source-user",
                "PGPASSWORD": os.environ["FAKE_SOURCE_PASSWORD"],
                "PGDATABASE": "source-db",
            })
            os.execvpe(command[0], command, environment)
            """,
        )
        write_executable(
            deploy / PG_ENV_EXEC.name,
            r"""
            #!/usr/bin/env python3
            import os
            import sys

            arguments = sys.argv[1:]
            if arguments[:2] != [
                "--target-private-env-file", os.environ["FAKE_PRIVATE_ENV"]
            ] or len(arguments) < 3:
                raise SystemExit(96)
            command = arguments[2:]
            environment = os.environ.copy()
            environment.update({
                "PGHOST": "127.0.0.1",
                "PGPORT": "15432",
                "PGUSER": "target-user",
                "PGPASSWORD": os.environ["FAKE_TARGET_PASSWORD"],
                "PGDATABASE": "target-db",
            })
            os.execvpe(command[0], command, environment)
            """,
        )
        write_executable(
            fake_bin / "docker",
            r"""
            #!/bin/sh
            exit 99
            """,
        )
        write_executable(
            fake_bin / "pg_dump",
            r"""
            #!/usr/bin/env python3
            import os
            import pathlib
            import sys

            if "--version" in sys.argv[1:]:
                print("pg_dump (PostgreSQL) 18.1")
                raise SystemExit(0)

            counter = pathlib.Path(os.environ["FAKE_COUNTER_DIR"]) / "pg_dump"
            count = int(counter.read_text() if counter.exists() else "0") + 1
            counter.write_text(str(count))
            mode = os.environ["FAKE_STREAM_FAILURE"]
            if mode == "pg_dump":
                sys.stdout.write("COPY private_table FROM stdin;\nPRIVATE_SENTINEL\n")
                sys.stdout.flush()
                sys.stderr.write(
                    "pg_dump: PRIVATE_SENTINEL at SQL line 41 for "
                    f"postgresql://{os.environ['PGUSER']}:{os.environ['PGPASSWORD']}@"
                    f"{os.environ['PGHOST']}/{os.environ['PGDATABASE']}\n"
                )
                raise SystemExit(23)
            sys.stdout.write("SELECT 1;\n")
            """,
        )
        write_executable(
            fake_bin / "psql",
            r"""
            #!/usr/bin/env python3
            import os
            import pathlib
            import sys
            import time

            arguments = sys.argv[1:]
            if "--version" in arguments:
                print("psql (PostgreSQL) 18.1")
                raise SystemExit(0)
            if "--single-transaction" in arguments:
                counter = pathlib.Path(os.environ["FAKE_COUNTER_DIR"]) / "psql_stream"
                count = int(counter.read_text() if counter.exists() else "0") + 1
                counter.write_text(str(count))
                sys.stdin.read()
                mode = os.environ["FAKE_STREAM_FAILURE"]
                if mode == "pg_dump":
                    raise SystemExit(0)
                if mode == "copy":
                    detail = (
                        "ERROR: invalid COPY data PRIVATE_SENTINEL; SQL line 52; "
                        f"postgresql://{os.environ['PGUSER']}:{os.environ['PGPASSWORD']}@"
                        f"{os.environ['PGHOST']}/{os.environ['PGDATABASE']}"
                    )
                elif mode == "constraint":
                    detail = (
                        "ERROR: constraint failed for (PRIVATE_SENTINEL); SQL line 63; "
                        f"password={os.environ['PGPASSWORD']}"
                    )
                elif mode == "timeout":
                    detail = (
                        "ERROR: stalled COPY PRIVATE_SENTINEL; SQL line 74; "
                        f"password={os.environ['PGPASSWORD']}"
                    )
                else:
                    raise AssertionError(mode)
                # Exercise both inherited descriptors. Neither stream is an approved
                # diagnostic channel for data-bearing PostgreSQL client output.
                print(detail, flush=True)
                print(detail, file=sys.stderr, flush=True)
                if mode == "timeout":
                    time.sleep(30)
                raise SystemExit(1)

            if "--command" not in arguments:
                gate_sql = sys.stdin.read()
                if (
                    os.environ["FAKE_STREAM_FAILURE"] == "portability"
                    and "pg_foreign_server" in gate_sql
                    and os.environ["PGDATABASE"] == "source-db"
                ):
                    detail = (
                        "ERROR: foreign server option PRIVATE_SENTINEL; "
                        f"password={os.environ['PGPASSWORD']}"
                    )
                    print(detail)
                    print(detail, file=sys.stderr)
                    raise SystemExit(1)
                raise SystemExit(0)
            try:
                command = arguments[arguments.index("--command") + 1]
            except (ValueError, IndexError) as error:
                raise AssertionError(arguments) from error
            database = os.environ["PGDATABASE"]
            if "pg_largeobject_metadata" in command:
                print("0|0")
            elif "to_regclass" in command:
                print("f")
            elif "pg_control_system()" in command:
                print("2000000000000000002|16384|7461726765742d6462")
            elif "current_database()" in command:
                print(f"{database}:127.0.0.1:5432")
            elif "server_version_num" in command:
                print("180000")
            elif "WITH user_objects" in command:
                print("0")
            else:
                raise AssertionError(command)
            """,
        )
        write_executable(
            fake_bin / "timeout",
            r"""
            #!/usr/bin/env python3
            import os
            import pathlib
            import signal
            import subprocess
            import sys

            arguments = sys.argv[1:]
            index = 0
            while index < len(arguments):
                if arguments[index] == "--foreground":
                    index += 1
                    continue
                if arguments[index] in {"-s", "-k"}:
                    index += 2
                    continue
                break
            if index >= len(arguments):
                raise SystemExit(2)
            index += 1  # Ignore the production deadline in this controlled harness.
            command = arguments[index:]
            os.execvp(command[0], command)
            """,
        )
        return root, fake_bin, counters

    def run_failure(self, failure):
        with tempfile.TemporaryDirectory() as directory:
            root, fake_bin, counters = self.make_harness(directory)
            private_env = root / "private.env"
            private_env.write_text("TEST_ONLY=1\n", encoding="ascii")
            private_env.chmod(0o600)
            source_url = (
                f"postgresql://source-user:{SOURCE_PASSWORD}@172.19.0.2:5432/"
                "source-db?sslmode=disable"
            )
            target_url = (
                f"postgresql://target-user:{TARGET_PASSWORD}@127.0.0.1:15432/"
                "target-db?sslmode=disable"
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "FAKE_COUNTER_DIR": str(counters),
                    "FAKE_PRIVATE_ENV": str(private_env),
                    "FAKE_SOURCE_PASSWORD": SOURCE_PASSWORD,
                    "FAKE_TARGET_PASSWORD": TARGET_PASSWORD,
                    "FAKE_STREAM_FAILURE": failure,
                    "SUB2API_MIGRATION_WRITES_STOPPED": "YES",
                }
            )
            started = time.monotonic()
            result = subprocess.run(
                [
                    root / "deploy" / MIGRATION.name,
                    "--apply",
                    "--env-file", private_env,
                    "--source-app-container", "legacy-app",
                    "--source-app-id", "a" * 64,
                    "--source-postgres-container", "legacy-postgres",
                    "--source-postgres-id", "b" * 64,
                ],
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=5,
            )
            elapsed = time.monotonic() - started
            counts = {
                name: (
                    int((counters / name).read_text())
                    if (counters / name).exists()
                    else 0
                )
                for name in ("pg_dump", "psql_stream")
            }
            return result, elapsed, counts, source_url, target_url

    def assert_sanitized_failure(self, failure):
        result, elapsed, counts, source_url, target_url = self.run_failure(failure)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "sanitized_postgres_stream_failed\n")
        self.assertEqual(result.stderr.count("sanitized_postgres_stream_failed"), 1)
        combined_output = result.stdout + result.stderr
        for private_value in (
            PRIVATE_SENTINEL,
            "SQL line",
            "COPY private_table",
            "invalid COPY data",
            "constraint failed",
            "postgresql://",
            SOURCE_PASSWORD,
            TARGET_PASSWORD,
            source_url,
            target_url,
        ):
            with self.subTest(failure=failure, private_value=private_value):
                self.assertNotIn(private_value, combined_output)
        self.assertEqual(counts, {"pg_dump": 1, "psql_stream": 1})
        self.assertLess(elapsed, 3)

    def test_pg_dump_failure_is_pipefail_sanitized_and_not_retried(self):
        self.assert_sanitized_failure("pg_dump")

    def test_psql_copy_failure_is_sanitized_and_not_retried(self):
        self.assert_sanitized_failure("copy")

    def test_psql_constraint_failure_is_sanitized_and_not_retried(self):
        self.assert_sanitized_failure("constraint")

    def test_stream_timeout_is_sanitized_bounded_and_not_retried(self):
        self.assert_sanitized_failure("timeout")

    def test_portability_failure_is_sanitized_and_stops_before_pg_dump(self):
        result, elapsed, counts, source_url, target_url = self.run_failure(
            "portability"
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr, "sanitized_postgres_portability_gate_failed\n"
        )
        combined_output = result.stdout + result.stderr
        for private_value in (
            PRIVATE_SENTINEL,
            "foreign server option",
            "password=",
            SOURCE_PASSWORD,
            TARGET_PASSWORD,
            source_url,
            target_url,
        ):
            self.assertNotIn(private_value, combined_output)
        self.assertEqual(counts, {"pg_dump": 0, "psql_stream": 0})
        self.assertLess(elapsed, 3)


if __name__ == "__main__":
    unittest.main()
