import contextlib
import importlib.util
import io
import pathlib
import subprocess
import sys
import time
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "locked-postgres-stream.py"


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name, TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def options(deadline_seconds=5):
    return types.SimpleNamespace(
        deadline_seconds=deadline_seconds,
        env_file=pathlib.Path("/private/sub2api-gate.env"),
        source_app_container="legacy-app",
        source_app_id="a" * 64,
        source_postgres_container="legacy-postgres",
        source_postgres_id="b" * 64,
        source_system_id="1234567890123456789",
        source_database_oid="16384",
        source_database_name_hex="73756232617069",
        snapshot_id="",
    )


class LockedPostgresStreamTests(unittest.TestCase):
    def test_source_lock_precedes_inventory_and_rejects_every_unknown_client(self):
        tool = load_tool("locked_stream_lock_contract")
        sql = tool.LOCK_HOLDER_SQL
        fixed_lock = sql.index("LOCK TABLE\n    pg_catalog.pg_attribute")
        inventory = sql.index("FOR locked_relation IN")
        self.assertLess(fixed_lock, inventory)
        for catalog in (
            "pg_catalog.pg_class",
            "pg_catalog.pg_namespace",
            "pg_catalog.pg_attribute",
            "pg_catalog.pg_type",
            "pg_catalog.pg_proc",
        ):
            self.assertIn(catalog, sql)
        self.assertIn("relation.relkind IN ('r', 'p', 'm')", sql)
        self.assertIn("IN SHARE MODE", sql)
        self.assertNotIn("regdatabase", sql + tool.CLIENT_GUARD_SQL)
        self.assertGreaterEqual(
            (sql + tool.CLIENT_GUARD_SQL).count(
                "unexpected source client session rejected"
            ),
            3,
        )
        self.assertGreaterEqual(
            (sql + tool.CLIENT_GUARD_SQL).count("pg_terminate_backend"), 3
        )
        self.assertGreaterEqual(
            (sql + tool.CLIENT_GUARD_SQL).count("pg_stat_clear_snapshot"), 3
        )

    def test_read_write_lock_and_read_only_snapshot_are_separate_holders(self):
        source = TOOL_PATH.read_text()
        self.assertIn("default_transaction_read_only=off", source)
        self.assertIn("default_transaction_read_only=on", source)
        self.assertIn("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY", source)
        self.assertIn("pg_export_snapshot()", source)
        self.assertIn("SNAPSHOT_HOLDER|", source)
        self.assertIn("terminate_source_backend", source)
        self.assertIn("SET TRANSACTION SNAPSHOT", source)
        self.assertIn("--snapshot=", source)
        self.assertIn("stdout=self.target.stdin", source)
        self.assertNotIn("tempfile", source)
        execute = source.split("    def execute(self):", 1)[1].split(
            "\n\n\ndef parse_arguments", 1
        )[0]
        self.assertLess(
            execute.index("self.start_lock_holder()"),
            execute.index("self.start_snapshot_holder"),
        )
        self.assertLess(
            execute.index("self.clear_source_clients()"),
            execute.index("self.commit_target()"),
        )
        self.assertLess(
            execute.index("self.commit_target()"),
            execute.index("self.stop_holder(self.lock_holder"),
        )

    def test_holder_cleanup_uses_pid_database_and_backend_start_identity(self):
        tool = load_tool("locked_stream_backend_identity")
        source = TOOL_PATH.read_text()
        self.assertIn("LOCK_READY|", tool.LOCK_HOLDER_SQL)
        self.assertIn("backend_start", tool.LOCK_HOLDER_SQL)
        self.assertIn("SNAPSHOT_HOLDER|", source)
        self.assertIn(
            "floor(extract(epoch from backend_start) * 1000000)::bigint",
            source,
        )
        cleanup = source.split("    def terminate_source_backend", 1)[1].split(
            "\n    def clear_source_clients", 1
        )[0]
        self.assertIn("WHERE pid = {backend_pid}", cleanup)
        self.assertIn("AND datid = {database_oid}", cleanup)
        self.assertNotIn("application_name =", cleanup)

    def test_holder_failure_shares_one_cleanup_deadline(self):
        tool = load_tool("locked_stream_shared_cleanup_deadline")
        stream = tool.LockedStream(options())
        holder = object()
        stream.snapshot_holder = holder
        stream.snapshot_backend_identity = (1234, 16384, 1720000000000000)
        cleanup_deadline = time.monotonic() + 4
        stream.send = mock.Mock(side_effect=tool.StreamFailure(tool.EXIT_DEADLINE))
        stream.terminate_source_backend = mock.Mock()
        stream.abort = mock.Mock()

        with self.assertRaises(tool.StreamFailure):
            stream.stop_holder(
                holder,
                tool.EXIT_SOURCE_SNAPSHOT,
                cleanup_deadline=cleanup_deadline,
            )

        stream.terminate_source_backend.assert_called_once_with(
            (1234, 16384, 1720000000000000), cleanup_deadline
        )
        stream.abort.assert_called_once_with(holder, cleanup_deadline)

    def test_backend_termination_timeout_is_bounded_by_cleanup_deadline(self):
        tool = load_tool("locked_stream_bounded_backend_termination")
        stream = tool.LockedStream(options())

        class FakeProcess:
            def __init__(self):
                self.timeout = None
                self.sql = None

            def communicate(self, *, input, timeout):
                self.sql = input
                self.timeout = timeout

            def poll(self):
                return 0

        process = FakeProcess()
        cleanup_deadline = time.monotonic() + 0.25
        with mock.patch.object(tool.subprocess, "Popen", return_value=process):
            stream.terminate_source_backend(
                (1234, 16384, 1720000000000000), cleanup_deadline
            )

        self.assertLessEqual(process.timeout, 0.25)
        sql = process.sql.decode("ascii")
        self.assertIn("pid = 1234", sql)
        self.assertIn("datid = 16384", sql)
        self.assertIn("= 1720000000000000", sql)
        self.assertNotIn("application_name", sql)

    def test_target_output_over_cap_is_rejected_without_echoing_it(self):
        tool = load_tool("locked_stream_target_output_cap")
        stream = tool.LockedStream(options())
        sentinel = "TARGET_PRIVATE_SENTINEL"
        process = stream.spawn(
            [
                sys.executable,
                "-c",
                (
                    "import sys,time;"
                    f"sys.stdout.write({sentinel!r}*5000+'\\n');"
                    "sys.stdout.flush();time.sleep(30)"
                ),
            ]
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        started = time.monotonic()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with self.assertRaises(tool.StreamFailure) as raised:
                    stream.expect_marker(process, b"TARGET_VALIDATED", tool.EXIT_STREAM)
            self.assertEqual(raised.exception.exit_code, tool.EXIT_STREAM)
        finally:
            stream.abort(process)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(sentinel, stdout.getvalue() + stderr.getvalue())

    def test_restore_output_is_discarded_before_dump_and_reset_for_marker(self):
        tool = load_tool("locked_stream_restore_output_drain")
        stream = tool.LockedStream(options())
        child = (
            "import sys;"
            "first=sys.stdin.buffer.readline();"
            "bad=first!=b'\\\\o /dev/null\\n';"
            "data=sys.stdin.buffer.read();"
            "sys.stdout.buffer.write((b'X'*131072) if bad else b'');"
            "sys.stdout.buffer.write(b'TARGET_VALIDATED\\n' if "
            "b'\\\\o\\n\\\\echo TARGET_VALIDATED\\n' in data else b'BROKEN\\n');"
            "sys.stdout.buffer.flush()"
        )
        stream.target_base = [sys.executable, "-c", child]
        try:
            stream.start_target()
            stream.send(
                stream.target,
                b"SELECT pg_catalog.setval('example', 1);\n"
                b"\\o\n\\echo TARGET_VALIDATED\n",
                tool.EXIT_STREAM,
            )
            stream.close_input(stream.target, tool.EXIT_STREAM)
            marker = stream.expect_marker(
                stream.target, b"TARGET_VALIDATED", tool.EXIT_STREAM
            )
            self.assertEqual(marker, b"TARGET_VALIDATED")
            stream.wait(stream.target, tool.EXIT_STREAM)
        finally:
            stream.abort(stream.target)

    def test_control_read_timeout_is_bounded_and_child_is_reaped(self):
        tool = load_tool("locked_stream_control_timeout")
        stream = tool.LockedStream(options(deadline_seconds=1))
        process = stream.spawn(
            [sys.executable, "-c", "import time;time.sleep(30)"]
        )
        started = time.monotonic()
        try:
            with self.assertRaises(tool.StreamFailure) as raised:
                stream.read_line(process, tool.EXIT_STREAM)
            self.assertEqual(raised.exception.exit_code, tool.EXIT_DEADLINE)
        finally:
            stream.abort(process)
        self.assertLess(time.monotonic() - started, 4)
        self.assertIsNotNone(process.poll())

    def test_error_cleanup_sends_explicit_target_rollback_before_termination(self):
        tool = load_tool("locked_stream_explicit_target_rollback")
        stream = tool.LockedStream(options())
        marker = pathlib.Path("/tmp") / (
            "locked-stream-rollback-" + str(time.monotonic_ns())
        )
        child = (
            "import pathlib,sys;"
            "data=sys.stdin.buffer.read();"
            f"pathlib.Path({str(marker)!r}).write_text('rollback' if "
            "b'ROLLBACK;' in data else 'commit')"
        )
        stream.target = stream.spawn([sys.executable, "-c", child])
        try:
            stream.rollback_target(time.monotonic() + 3)
            self.assertEqual(marker.read_text(), "rollback")
        finally:
            stream.abort(stream.target)
            marker.unlink(missing_ok=True)

    def test_cli_rejects_abbreviated_or_unpinned_container_identity(self):
        common = [
            "--deadline-seconds",
            "10",
            "--env-file",
            "/private/sub2api-gate.env",
            "--source-app-container",
            "legacy-app",
            "--source-app-id",
            "a" * 64,
            "--source-postgres-container",
            "legacy-postgres",
            "--source-postgres-id",
            "b" * 64,
            "--source-system-id",
            "1234567890123456789",
            "--source-database-oid",
            "16384",
            "--source-database-name-hex",
            "73756232617069",
        ]
        cases = (
            ["--deadline-sec", *common[2:]],
            [*common[:7], "bad/name", *common[8:]],
            [*common[:11], "a" * 63, *common[12:]],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run(
                    [sys.executable, TOOL_PATH, *arguments],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertEqual(
                    result.stderr,
                    "sanitized PostgreSQL stream argument validation failed\n",
                )


if __name__ == "__main__":
    unittest.main()
