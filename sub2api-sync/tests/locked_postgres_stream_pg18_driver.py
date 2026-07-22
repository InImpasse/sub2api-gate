#!/usr/bin/env python3
"""Real PostgreSQL 18 integration driver for the locked logical stream."""

import importlib.util
import pathlib
import subprocess
import sys
import threading
import time
import types


PRIVATE_SENTINEL = "PG18_PRIVATE_SENTINEL_MUST_NOT_ESCAPE"


def load_tool(path):
    spec = importlib.util.spec_from_file_location("locked_stream_pg18", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def docker_psql(container, sql, *, capture=True, check=True, application=None):
    command = ["docker", "exec", "--interactive", "--user", "postgres"]
    if application:
        command.extend(("--env", f"PGAPPNAME={application}"))
    command.extend(
        (
            container,
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--username=postgres",
            "--dbname=postgres",
            "-v",
            "ON_ERROR_STOP=1",
        )
    )
    return subprocess.run(
        command,
        input=sql,
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        check=check,
        timeout=20,
    )


def scalar(container, sql):
    return docker_psql(container, sql).stdout.strip()


def reset_target(container):
    docker_psql(
        container,
        "DROP SCHEMA public CASCADE; CREATE SCHEMA public AUTHORIZATION postgres;",
        capture=False,
    )


def target_is_empty(container):
    return scalar(container, "SELECT to_regclass('public.users') IS NULL;") == "t"


def wait_for_application(container, application, *, locked=False):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        predicate = "AND wait_event_type = 'Lock'" if locked else ""
        value = scalar(
            container,
            "SELECT count(*) FROM pg_catalog.pg_stat_activity "
            f"WHERE application_name = '{application}' {predicate};",
        )
        if value == "1":
            return
        time.sleep(0.05)
    raise AssertionError("expected PostgreSQL test client state was not observed")


def terminate_application(container, application):
    docker_psql(
        container,
        "SELECT pg_catalog.pg_terminate_backend(pid, 5000) "
        "FROM pg_catalog.pg_stat_activity "
        f"WHERE application_name = '{application}';",
        capture=False,
    )


def source_identity(container):
    value = scalar(
        container,
        "SELECT system_identifier::text || '|' || d.oid::text || '|' || "
        "pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_database(), "
        "'UTF8'), 'hex') FROM pg_catalog.pg_control_system() "
        "CROSS JOIN pg_catalog.pg_database AS d "
        "WHERE d.datname = pg_catalog.current_database();",
    )
    parts = value.split("|")
    if len(parts) != 3:
        raise AssertionError("source identity fixture is invalid")
    return parts


def make_options(env_file, source_container, identity, deadline=30):
    return types.SimpleNamespace(
        deadline_seconds=deadline,
        env_file=env_file,
        source_app_container="stopped-test-app",
        source_app_id="a" * 64,
        source_postgres_container=source_container,
        source_postgres_id="b" * 64,
        source_system_id=identity[0],
        source_database_oid=identity[1],
        source_database_name_hex=identity[2],
        snapshot_id="",
    )


def execute_in_thread(stream, lock_ready=None, continue_after_lock=None):
    outcome = []
    original = stream.start_lock_holder

    if lock_ready is not None:
        def start_and_pause():
            original()
            lock_ready.set()
            if not continue_after_lock.wait(8):
                raise stream_failure(stream, 16)

        stream.start_lock_holder = start_and_pause

    def target():
        try:
            stream.execute()
        except stream_failure_type(stream) as error:
            outcome.append(error.exit_code)
        else:
            outcome.append(0)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, outcome


def stream_failure_type(stream):
    return sys.modules[stream.__class__.__module__].StreamFailure


def stream_failure(stream, code):
    return stream_failure_type(stream)(code)


def wait_thread(thread, outcome):
    thread.join(40)
    if thread.is_alive() or len(outcome) != 1:
        raise AssertionError("locked PostgreSQL stream did not terminate")
    return outcome[0]


def start_client(container, application, sql):
    return subprocess.Popen(
        [
            "docker",
            "exec",
            "--interactive",
            "--user",
            "postgres",
            "--env",
            f"PGAPPNAME={application}",
            container,
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--username=postgres",
            "--dbname=postgres",
            "-v",
            "ON_ERROR_STOP=1",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
        start_new_session=True,
    ), sql


def feed_client(process_and_sql):
    process, sql = process_and_sql
    process.stdin.write(sql)
    process.stdin.close()
    return process


def main():
    if len(sys.argv) != 5:
        return 2
    repo = pathlib.Path(sys.argv[1])
    env_file = pathlib.Path(sys.argv[2])
    source_container = sys.argv[3]
    target_container = sys.argv[4]
    tool = load_tool(repo / "deploy" / "locked-postgres-stream.py")
    identity = source_identity(source_container)

    docker_psql(
        source_container,
        """
        CREATE TABLE users (
            id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
            username text NOT NULL
        );
        CREATE TABLE usage_logs (
            id bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
            request_id text,
            input_tokens bigint NOT NULL DEFAULT 0,
            output_tokens bigint NOT NULL DEFAULT 0,
            total_cost numeric NOT NULL DEFAULT 0,
            actual_cost numeric NOT NULL DEFAULT 0
        );
        INSERT INTO users (username) VALUES ('metadata-user');
        INSERT INTO usage_logs (
            request_id, input_tokens, output_tokens, total_cost, actual_cost
        ) VALUES ('request-metadata', 11, 7, 0.12, 0.10);
        """,
        capture=False,
    )

    # Baseline proves the complete no-file stream can commit against PG18.
    reset_target(target_container)
    tool.LockedStream(
        make_options(env_file, source_container, identity)
    ).execute()
    if scalar(target_container, "SELECT count(*) FROM users;") != "1":
        raise AssertionError("baseline locked stream did not commit")

    # A writer arriving after SHARE locks must block. Once canceled, the
    # target receives the exact pre-writer snapshot and the stream succeeds.
    reset_target(target_container)
    stream = tool.LockedStream(make_options(env_file, source_container, identity))
    lock_ready = threading.Event()
    continue_after_lock = threading.Event()
    thread, outcome = execute_in_thread(stream, lock_ready, continue_after_lock)
    if not lock_ready.wait(8):
        raise AssertionError("source lock holder did not become ready")
    writer = feed_client(
        start_client(
            source_container,
            "locked_stream_concurrent_writer",
            "INSERT INTO users (username) VALUES ('must-not-commit');",
        )
    )
    wait_for_application(
        source_container, "locked_stream_concurrent_writer", locked=True
    )
    terminate_application(source_container, "locked_stream_concurrent_writer")
    writer.wait(timeout=8)
    continue_after_lock.set()
    if wait_thread(thread, outcome) != 0:
        raise AssertionError("stream failed after the blocked writer rolled back")
    if scalar(source_container, "SELECT count(*) FROM users;") != "1":
        raise AssertionError("blocked source writer unexpectedly committed")
    if scalar(target_container, "SELECT count(*) FROM users;") != "1":
        raise AssertionError("target row count did not use the exported snapshot")

    # A client present before the freeze is terminated and causes a hard
    # failure before any target object can be committed.
    reset_target(target_container)
    initial_client = feed_client(
        start_client(
            source_container,
            "locked_stream_initial_unknown",
            "SELECT pg_catalog.pg_sleep(30);",
        )
    )
    wait_for_application(source_container, "locked_stream_initial_unknown")
    try:
        tool.LockedStream(
            make_options(env_file, source_container, identity)
        ).execute()
    except tool.StreamFailure as error:
        if error.exit_code != tool.EXIT_SOURCE_LOCK:
            raise
    else:
        raise AssertionError("initial unknown source client was accepted")
    initial_client.wait(timeout=8)
    if not target_is_empty(target_container):
        raise AssertionError("initial client rejection modified the target")

    # A client arriving after the lock is also terminated and the still-open
    # target transaction must roll back before it can commit.
    reset_target(target_container)
    stream = tool.LockedStream(make_options(env_file, source_container, identity))
    lock_ready = threading.Event()
    continue_after_lock = threading.Event()
    thread, outcome = execute_in_thread(stream, lock_ready, continue_after_lock)
    if not lock_ready.wait(8):
        raise AssertionError("source lock holder did not become ready")
    final_client = feed_client(
        start_client(
            source_container,
            "locked_stream_final_unknown",
            "SELECT pg_catalog.pg_sleep(30);",
        )
    )
    wait_for_application(source_container, "locked_stream_final_unknown")
    continue_after_lock.set()
    final_status = wait_thread(thread, outcome)
    if final_status != tool.EXIT_SOURCE_CLIENT_GUARD:
        raise AssertionError(
            f"final unknown source client returned stable code {final_status}"
        )
    final_client.wait(timeout=8)
    if not target_is_empty(target_container):
        raise AssertionError("unknown-client failure did not roll back target")

    # A target validation error occurs before EOF/commit and leaves the fresh
    # target unchanged. Child diagnostics are never surfaced by the helper.
    reset_target(target_container)
    failing_target = repo / "deploy" / "failing-target.sql"
    failing_target.write_text(
        "DO $$ BEGIN RAISE EXCEPTION '" + PRIVATE_SENTINEL + "'; END $$;\n",
        encoding="ascii",
    )
    original_target_gate = tool.TARGET_GATE
    tool.TARGET_GATE = failing_target
    try:
        tool.LockedStream(
            make_options(env_file, source_container, identity)
        ).execute()
    except tool.StreamFailure as error:
        if error.exit_code != tool.EXIT_STREAM:
            raise
    else:
        raise AssertionError("target validator failure unexpectedly committed")
    finally:
        tool.TARGET_GATE = original_target_gate
    if not target_is_empty(target_container):
        raise AssertionError("target validator failure left restored objects")

    # Multi-megabyte SELECT output from the target validator is discarded
    # before the marker, so it neither deadlocks nor reaches caller output.
    reset_target(target_container)
    large_target = repo / "deploy" / "large-target.sql"
    large_target.write_bytes(
        original_target_gate.read_bytes()
        + b"\nSELECT repeat('TARGET_OUTPUT_SENTINEL', 150000);\n"
    )
    tool.TARGET_GATE = large_target
    started = time.monotonic()
    try:
        tool.LockedStream(
            make_options(env_file, source_container, identity)
        ).execute()
    finally:
        tool.TARGET_GATE = original_target_gate
    if time.monotonic() - started > 30:
        raise AssertionError("large target output stalled the stream")
    if scalar(target_container, "SELECT count(*) FROM users;") != "1":
        raise AssertionError("large target output run did not commit")

    # A source gate timeout is bounded and releases both source holders.
    reset_target(target_container)
    sleeping_privacy = repo / "migrations" / "sleeping-privacy.sql"
    sleeping_privacy.write_text(
        "SELECT pg_catalog.pg_sleep(30);\n", encoding="ascii"
    )
    original_privacy_gate = tool.PRIVACY_GATE
    tool.PRIVACY_GATE = sleeping_privacy
    started = time.monotonic()
    try:
        tool.LockedStream(
            make_options(env_file, source_container, identity, deadline=3)
        ).execute()
    except tool.StreamFailure as error:
        if error.exit_code != tool.EXIT_DEADLINE:
            raise
    else:
        raise AssertionError("source gate timeout unexpectedly succeeded")
    finally:
        tool.PRIVACY_GATE = original_privacy_gate
    if time.monotonic() - started > 9:
        raise AssertionError("source timeout cleanup exceeded its bound")
    if not target_is_empty(target_container):
        raise AssertionError("source timeout modified the target")
    lingering_clients = scalar(
        source_container,
        "SELECT COALESCE(string_agg(application_name || ':' || state, ',' "
        "ORDER BY application_name), '') FROM pg_catalog.pg_stat_activity "
        "WHERE datid = (SELECT oid FROM pg_catalog.pg_database "
        "WHERE datname = pg_catalog.current_database()) "
        "AND pid <> pg_catalog.pg_backend_pid() "
        "AND backend_type = 'client backend';",
    )
    if lingering_clients:
        raise AssertionError(
            "source timeout left PostgreSQL clients: " + lingering_clients
        )

    # Execute a real failing gate through the public CLI and prove PostgreSQL
    # diagnostics and the sentinel are completely suppressed.
    failing_privacy = repo / "migrations" / "verify_no_conversation_content.sql"
    safe_privacy = failing_privacy.read_bytes()
    failing_privacy.write_text(
        "DO $$ BEGIN RAISE EXCEPTION '" + PRIVATE_SENTINEL + "'; END $$;\n",
        encoding="ascii",
    )
    try:
        result = subprocess.run(
            [
                sys.executable,
                repo / "deploy" / "locked-postgres-stream.py",
                "--deadline-seconds",
                "20",
                "--env-file",
                env_file,
                "--source-app-container",
                "stopped-test-app",
                "--source-app-id",
                "a" * 64,
                "--source-postgres-container",
                source_container,
                "--source-postgres-id",
                "b" * 64,
                "--source-system-id",
                identity[0],
                "--source-database-oid",
                identity[1],
                "--source-database-name-hex",
                identity[2],
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=25,
            check=False,
        )
    finally:
        failing_privacy.write_bytes(safe_privacy)
    if result.returncode != tool.EXIT_SOURCE_PRIVACY:
        raise AssertionError(
            f"real privacy failure returned stable code {result.returncode}"
        )
    if result.stdout or result.stderr or PRIVATE_SENTINEL in result.stdout + result.stderr:
        raise AssertionError("PostgreSQL failure detail escaped the helper")

    print("PostgreSQL 18 locked snapshot stream passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
