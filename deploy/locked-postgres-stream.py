#!/usr/bin/env python3
"""Stream one locked, sanitized source snapshot into a fresh target database."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import select
import signal
import subprocess
import sys
import time


REPO_DIR = pathlib.Path(__file__).resolve().parents[1]
SOURCE_EXEC = REPO_DIR / "deploy" / "source-postgres-exec.py"
TARGET_EXEC = REPO_DIR / "deploy" / "pg-env-exec.py"
PRIVACY_GATE = REPO_DIR / "migrations" / "verify_no_conversation_content.sql"
PORTABILITY_GATE = REPO_DIR / "deploy" / "verify-postgres-portability.sql"
TARGET_GATE = REPO_DIR / "deploy" / "verify-sanitized-target.sql"

EXIT_SOURCE_LOCK = 10
EXIT_SOURCE_PRIVACY = 11
EXIT_SOURCE_PORTABILITY = 12
EXIT_SOURCE_SNAPSHOT = 13
EXIT_STREAM = 14
EXIT_SOURCE_CLIENT_GUARD = 15
EXIT_DEADLINE = 16
MAX_CONTROL_OUTPUT_BYTES = 64 * 1024
MAX_GATE_BYTES = 1024 * 1024
SNAPSHOT_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{8}-[0-9]+\Z")
SYSTEM_ID_RE = re.compile(r"[0-9]{10,24}\Z")
OID_RE = re.compile(r"[0-9]{1,10}\Z")
NAME_HEX_RE = re.compile(r"(?:[0-9a-f]{2}){1,63}\Z")
NUMBER_RE = re.compile(r"-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")
CONTAINER_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
CONTAINER_ID_RE = re.compile(r"[0-9a-f]{64}\Z")


LOCK_HOLDER_SQL = r"""
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '150s';
DO $sub2api_gate_lock$
DECLARE
    victim record;
    victim_count integer;
BEGIN
    PERFORM pg_catalog.pg_stat_clear_snapshot();
    SELECT count(*) INTO victim_count
    FROM pg_catalog.pg_stat_activity
    WHERE datid = (
        SELECT oid FROM pg_catalog.pg_database
        WHERE datname = pg_catalog.current_database()
    )
      AND pid <> pg_catalog.pg_backend_pid()
      AND backend_type = 'client backend';
    IF victim_count > 64 THEN
        RAISE EXCEPTION 'source client boundary exceeded';
    END IF;
    FOR victim IN
        SELECT pid
        FROM pg_catalog.pg_stat_activity
        WHERE datid = (
            SELECT oid FROM pg_catalog.pg_database
            WHERE datname = pg_catalog.current_database()
        )
          AND pid <> pg_catalog.pg_backend_pid()
          AND backend_type = 'client backend'
        ORDER BY pid
    LOOP
        IF NOT pg_catalog.pg_terminate_backend(victim.pid, 5000) THEN
            RAISE EXCEPTION 'source client termination failed';
        END IF;
    END LOOP;
    IF victim_count > 0 THEN
        RAISE EXCEPTION 'unexpected source client session rejected';
    END IF;
END
$sub2api_gate_lock$;

LOCK TABLE
    pg_catalog.pg_attribute,
    pg_catalog.pg_class,
    pg_catalog.pg_namespace,
    pg_catalog.pg_proc,
    pg_catalog.pg_type
IN SHARE MODE;

DO $sub2api_gate_lock_inventory$
DECLARE
    victim record;
    locked_relation record;
    victim_count integer;
BEGIN
    FOR locked_relation IN
        SELECT namespace.nspname AS schema_name,
               relation.relname AS relation_name
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE (
            namespace.nspname = 'public'
            AND relation.relkind IN ('r', 'p', 'm')
        ) OR (
            namespace.nspname = 'pg_catalog'
            AND relation.relkind IN ('r', 'p')
            AND relation.relname = ANY (ARRAY[
                'pg_aggregate', 'pg_am', 'pg_amop', 'pg_amproc',
                'pg_attrdef', 'pg_attribute', 'pg_cast', 'pg_class',
                'pg_collation', 'pg_constraint', 'pg_conversion',
                'pg_database', 'pg_default_acl', 'pg_depend',
                'pg_description', 'pg_enum', 'pg_event_trigger',
                'pg_extension', 'pg_foreign_data_wrapper',
                'pg_foreign_server', 'pg_foreign_table', 'pg_index',
                'pg_inherits', 'pg_init_privs', 'pg_language',
                'pg_largeobject_metadata', 'pg_namespace', 'pg_opclass',
                'pg_operator', 'pg_opfamily', 'pg_partitioned_table',
                'pg_policy', 'pg_proc', 'pg_range', 'pg_rewrite',
                'pg_seclabel', 'pg_sequence', 'pg_shdepend',
                'pg_shdescription', 'pg_tablespace', 'pg_trigger',
                'pg_type', 'pg_user_mapping'
            ]::name[])
        )
        ORDER BY namespace.nspname, relation.relname
    LOOP
        EXECUTE pg_catalog.format(
            'LOCK TABLE %I.%I IN SHARE MODE',
            locked_relation.schema_name,
            locked_relation.relation_name
        );
    END LOOP;

    PERFORM pg_catalog.pg_stat_clear_snapshot();
    SELECT count(*) INTO victim_count
    FROM pg_catalog.pg_stat_activity
    WHERE datid = (
        SELECT oid FROM pg_catalog.pg_database
        WHERE datname = pg_catalog.current_database()
    )
      AND pid <> pg_catalog.pg_backend_pid()
      AND backend_type = 'client backend';
    FOR victim IN
        SELECT pid
        FROM pg_catalog.pg_stat_activity
        WHERE datid = (
            SELECT oid FROM pg_catalog.pg_database
            WHERE datname = pg_catalog.current_database()
        )
          AND pid <> pg_catalog.pg_backend_pid()
          AND backend_type = 'client backend'
        ORDER BY pid
    LOOP
        IF NOT pg_catalog.pg_terminate_backend(victim.pid, 5000) THEN
            RAISE EXCEPTION 'source client termination failed';
        END IF;
    END LOOP;
    IF victim_count > 0 THEN
        RAISE EXCEPTION 'unexpected source client session rejected';
    END IF;
END
$sub2api_gate_lock_inventory$;
SELECT 'LOCK_READY|' || pid::text || '|' || datid::text || '|' ||
       floor(extract(epoch from backend_start) * 1000000)::bigint::text
FROM pg_catalog.pg_stat_activity
WHERE pid = pg_catalog.pg_backend_pid();
""".lstrip()

CLIENT_GUARD_SQL = r"""
DO $sub2api_gate_clients$
DECLARE
    victim record;
    victim_count integer;
BEGIN
    PERFORM pg_catalog.pg_stat_clear_snapshot();
    SELECT count(*) INTO victim_count
    FROM pg_catalog.pg_stat_activity
    WHERE datid = (
        SELECT oid FROM pg_catalog.pg_database
        WHERE datname = pg_catalog.current_database()
    )
      AND pid <> pg_catalog.pg_backend_pid()
      AND backend_type = 'client backend';
    IF victim_count > 64 THEN
        RAISE EXCEPTION 'source client boundary exceeded';
    END IF;
    FOR victim IN
        SELECT pid
        FROM pg_catalog.pg_stat_activity
        WHERE datid = (
            SELECT oid FROM pg_catalog.pg_database
            WHERE datname = pg_catalog.current_database()
        )
          AND pid <> pg_catalog.pg_backend_pid()
          AND backend_type = 'client backend'
        ORDER BY pid
    LOOP
        IF NOT pg_catalog.pg_terminate_backend(victim.pid, 5000) THEN
            RAISE EXCEPTION 'source client termination failed';
        END IF;
    END LOOP;
    IF victim_count > 0 THEN
        RAISE EXCEPTION 'unexpected source client session rejected';
    END IF;
END
$sub2api_gate_clients$;
SELECT 'CLIENTS_CLEARED|' || pg_catalog.pg_backend_pid()::text;
""".lstrip()


class StreamFailure(RuntimeError):
    def __init__(self, exit_code: int):
        super().__init__("sanitized PostgreSQL stream failed")
        self.exit_code = exit_code


class RedactedArgumentParser(argparse.ArgumentParser):
    def error(self, _message):
        self.exit(2, "sanitized PostgreSQL stream argument validation failed\n")


def safe_environment(pgoptions: str = "") -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in ("PATH", "LANG", "LC_ALL", "TZ")
        if os.environ.get(name)
    }
    environment.setdefault(
        "PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )
    if pgoptions:
        environment["SUB2API_PGOPTIONS"] = pgoptions
    return environment


def read_gate(path: pathlib.Path) -> bytes:
    try:
        metadata = path.stat(follow_symlinks=False)
        if path.is_symlink() or not path.is_file() or metadata.st_size > MAX_GATE_BYTES:
            raise OSError
        value = path.read_bytes()
    except OSError as error:
        raise StreamFailure(EXIT_STREAM) from error
    if not value or b"\x00" in value:
        raise StreamFailure(EXIT_STREAM)
    return value


class LockedStream:
    def __init__(self, options):
        self.options = options
        self.deadline = time.monotonic() + options.deadline_seconds
        self.processes: set[subprocess.Popen] = set()
        self.buffers: dict[int, bytearray] = {}
        self.lock_holder = None
        self.snapshot_holder = None
        self.lock_backend_identity = None
        self.snapshot_backend_identity = None
        self.target = None
        self.target_committed = False
        common = [
            "--env-file",
            str(options.env_file),
            "--source-app-container",
            options.source_app_container,
            "--source-app-id",
            options.source_app_id,
            "--source-postgres-container",
            options.source_postgres_container,
            "--source-postgres-id",
            options.source_postgres_id,
            "--source-app-state",
            "stopped",
        ]
        self.source_base = [sys.executable, str(SOURCE_EXEC), *common]
        self.target_base = [
            sys.executable,
            str(TARGET_EXEC),
            "--target-private-env-file",
            str(options.env_file),
        ]

    def remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise StreamFailure(EXIT_DEADLINE)
        return remaining

    def spawn(
        self,
        argv,
        *,
        pgoptions="",
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    ):
        self.remaining()
        try:
            process = subprocess.Popen(
                argv,
                stdin=stdin,
                stdout=stdout,
                stderr=subprocess.DEVNULL,
                env=safe_environment(pgoptions),
                start_new_session=True,
                close_fds=True,
                bufsize=0,
            )
        except OSError as error:
            raise StreamFailure(EXIT_STREAM) from error
        self.processes.add(process)
        return process

    def abort(self, process, cleanup_deadline=None):
        if process is None:
            return
        if cleanup_deadline is None:
            cleanup_deadline = time.monotonic() + 4
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass
            remaining = cleanup_deadline - time.monotonic()
            try:
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(process.args, 0)
                process.wait(timeout=min(2, remaining))
            except (subprocess.TimeoutExpired, ValueError, AttributeError):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
                remaining = cleanup_deadline - time.monotonic()
                try:
                    if remaining > 0:
                        process.wait(timeout=min(2, remaining))
                except (subprocess.TimeoutExpired, ValueError, AttributeError):
                    pass
        self.processes.discard(process)
        self.buffers.pop(process.pid, None)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def wait(self, process, error_code):
        try:
            return_code = process.wait(timeout=self.remaining())
        except subprocess.TimeoutExpired as error:
            self.abort(process)
            raise StreamFailure(EXIT_DEADLINE) from error
        self.processes.discard(process)
        if return_code != 0:
            raise StreamFailure(error_code)

    def send(self, process, value: bytes, error_code: int):
        self.remaining()
        try:
            process.stdin.write(value)
            process.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as error:
            raise StreamFailure(error_code) from error

    def close_input(self, process, error_code):
        try:
            process.stdin.close()
        except (BrokenPipeError, OSError, ValueError) as error:
            raise StreamFailure(error_code) from error

    def read_line(self, process, error_code):
        buffer = self.buffers.setdefault(process.pid, bytearray())
        while True:
            newline = buffer.find(b"\n")
            if newline >= 0:
                line = bytes(buffer[:newline])
                del buffer[: newline + 1]
                return line.rstrip(b"\r")
            if len(buffer) > MAX_CONTROL_OUTPUT_BYTES:
                raise StreamFailure(error_code)
            timeout = self.remaining()
            try:
                readable, _, _ = select.select([process.stdout], [], [], timeout)
            except (OSError, ValueError) as error:
                raise StreamFailure(error_code) from error
            if not readable:
                raise StreamFailure(EXIT_DEADLINE)
            try:
                chunk = os.read(process.stdout.fileno(), 4096)
            except OSError as error:
                raise StreamFailure(error_code) from error
            if not chunk:
                raise StreamFailure(error_code)
            buffer.extend(chunk)

    def expect_marker(self, process, marker: bytes, error_code):
        consumed = 0
        while consumed <= MAX_CONTROL_OUTPUT_BYTES:
            line = self.read_line(process, error_code)
            consumed += len(line) + 1
            if line.startswith(marker):
                return line
        raise StreamFailure(error_code)

    def run_capture(self, argv, sql: bytes, pgoptions: str, error_code: int):
        process = self.spawn(argv, pgoptions=pgoptions)
        try:
            self.send(process, sql, error_code)
            self.close_input(process, error_code)
            output = bytearray()
            while True:
                timeout = self.remaining()
                readable, _, _ = select.select([process.stdout], [], [], timeout)
                if not readable:
                    raise StreamFailure(EXIT_DEADLINE)
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_CONTROL_OUTPUT_BYTES:
                    raise StreamFailure(error_code)
            self.wait(process, error_code)
            try:
                return bytes(output).decode("ascii", errors="strict").strip()
            except UnicodeError as error:
                raise StreamFailure(error_code) from error
        except Exception:
            self.abort(process)
            raise

    def source_psql(self):
        return [
            *self.source_base,
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "-v",
            "ON_ERROR_STOP=1",
        ]

    def snapshot_query(self, query: str, error_code=EXIT_SOURCE_SNAPSHOT):
        snapshot = self.options.snapshot_id
        sql = (
            "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
            f"SET TRANSACTION SNAPSHOT '{snapshot}';\n"
            f"{query.rstrip(';')};\n"
            "COMMIT;\n"
        ).encode("ascii")
        return self.run_capture(
            self.source_psql(),
            sql,
            "-c default_transaction_read_only=on -c lock_timeout=5000 "
            "-c statement_timeout=120000 -c idle_in_transaction_session_timeout=180000 "
            "-c application_name=sub2api_gate_snapshot_reader",
            error_code,
        )

    def start_lock_holder(self):
        self.lock_holder = self.spawn(
            self.source_psql(),
            pgoptions=(
                "-c default_transaction_read_only=off -c lock_timeout=5000 "
                "-c statement_timeout=150000 "
                "-c idle_in_transaction_session_timeout=180000 "
                "-c application_name=sub2api_gate_lock_holder"
            ),
        )
        self.send(self.lock_holder, LOCK_HOLDER_SQL.encode("ascii"), EXIT_SOURCE_LOCK)
        line = self.expect_marker(self.lock_holder, b"LOCK_READY|", EXIT_SOURCE_LOCK)
        self.lock_backend_identity = self.parse_backend_identity(
            line, b"LOCK_READY", EXIT_SOURCE_LOCK
        )

    def start_snapshot_holder(self, privacy_gate: bytes, portability_gate: bytes):
        self.snapshot_holder = self.spawn(
            self.source_psql(),
            pgoptions=(
                "-c default_transaction_read_only=on -c lock_timeout=5000 "
                "-c statement_timeout=150000 "
                "-c idle_in_transaction_session_timeout=180000 "
                "-c application_name=sub2api_gate_snapshot_holder"
            ),
        )
        self.send(
            self.snapshot_holder,
            b"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;\n"
            b"SELECT 'SNAPSHOT_HOLDER|' || pid::text || '|' || datid::text || '|' || "
            b"floor(extract(epoch from backend_start) * 1000000)::bigint::text "
            b"FROM pg_catalog.pg_stat_activity "
            b"WHERE pid = pg_catalog.pg_backend_pid();\n",
            EXIT_SOURCE_SNAPSHOT,
        )
        holder_line = self.expect_marker(
            self.snapshot_holder, b"SNAPSHOT_HOLDER|", EXIT_SOURCE_SNAPSHOT
        )
        self.snapshot_backend_identity = self.parse_backend_identity(
            holder_line, b"SNAPSHOT_HOLDER", EXIT_SOURCE_SNAPSHOT
        )
        self.send(self.snapshot_holder, privacy_gate, EXIT_SOURCE_PRIVACY)
        self.send(
            self.snapshot_holder,
            b"\nSELECT 'PRIVACY_OK|' || pg_catalog.pg_backend_pid()::text;\n",
            EXIT_SOURCE_PRIVACY,
        )
        self.expect_marker(
            self.snapshot_holder, b"PRIVACY_OK|", EXIT_SOURCE_PRIVACY
        )

        self.send(self.snapshot_holder, b"\n" + portability_gate, EXIT_SOURCE_PORTABILITY)
        self.send(
            self.snapshot_holder,
            b"\nSELECT 'PORTABILITY_OK|' || pg_catalog.pg_backend_pid()::text;\n",
            EXIT_SOURCE_PORTABILITY,
        )
        self.expect_marker(
            self.snapshot_holder, b"PORTABILITY_OK|", EXIT_SOURCE_PORTABILITY
        )

        identity_sql = (
            "SELECT 'SNAPSHOT_READY|' || pg_catalog.pg_backend_pid()::text || '|' || "
            "pg_catalog.pg_export_snapshot() || '|' || system_identifier::text || '|' || "
            "d.oid::text || '|' || pg_catalog.encode(pg_catalog.convert_to("
            "pg_catalog.current_database(), 'UTF8'), 'hex') "
            "FROM pg_catalog.pg_control_system() CROSS JOIN pg_catalog.pg_database AS d "
            "WHERE d.datname = pg_catalog.current_database();\n"
        ).encode("ascii")
        self.send(self.snapshot_holder, identity_sql, EXIT_SOURCE_SNAPSHOT)
        line = self.expect_marker(
            self.snapshot_holder, b"SNAPSHOT_READY|", EXIT_SOURCE_SNAPSHOT
        )
        try:
            _, pid, snapshot_id, system_id, database_oid, database_name_hex = (
                line.decode("ascii", errors="strict").split("|")
            )
        except (UnicodeError, ValueError) as error:
            raise StreamFailure(EXIT_SOURCE_SNAPSHOT) from error
        if (
            not pid.isdigit()
            or int(pid) != self.snapshot_backend_identity[0]
            or not SNAPSHOT_RE.fullmatch(snapshot_id)
            or system_id != self.options.source_system_id
            or database_oid != self.options.source_database_oid
            or database_name_hex != self.options.source_database_name_hex
        ):
            raise StreamFailure(EXIT_SOURCE_SNAPSHOT)
        self.options.snapshot_id = snapshot_id

    def parse_backend_identity(self, line, marker, error_code):
        parts = line.split(b"|")
        if (
            len(parts) != 4
            or parts[0] != marker
            or not all(value.isdigit() for value in parts[1:])
        ):
            raise StreamFailure(error_code)
        backend_pid, database_oid, backend_start_us = (
            int(value) for value in parts[1:]
        )
        if (
            backend_pid <= 0
            or database_oid <= 0
            or database_oid > 4_294_967_295
            or str(database_oid) != self.options.source_database_oid
            or backend_start_us <= 0
            or backend_start_us > 9_223_372_036_854_775_807
        ):
            raise StreamFailure(error_code)
        return backend_pid, database_oid, backend_start_us

    def capture_manifest(self):
        identity_and_shape = self.snapshot_query(
            "SELECT system_identifier::text || '|' || d.oid::text || '|' || "
            "pg_catalog.encode(pg_catalog.convert_to(pg_catalog.current_database(), "
            "'UTF8'), 'hex') || '|' || "
            "(SELECT count(*) FROM pg_catalog.pg_namespace WHERE nspname NOT LIKE "
            "'pg_%' AND nspname NOT IN ('information_schema','public'))::text || '|' || "
            "(SELECT count(*) FROM pg_catalog.pg_largeobject_metadata)::text "
            "FROM pg_catalog.pg_control_system() CROSS JOIN pg_catalog.pg_database AS d "
            "WHERE d.datname = pg_catalog.current_database()"
        )
        expected_prefix = "|".join(
            (
                self.options.source_system_id,
                self.options.source_database_oid,
                self.options.source_database_name_hex,
            )
        )
        if identity_and_shape != expected_prefix + "|0|0":
            raise StreamFailure(EXIT_SOURCE_SNAPSHOT)

        counts = {}
        for table_name in (
            "users",
            "api_keys",
            "groups",
            "user_allowed_groups",
            "user_subscriptions",
            "usage_logs",
        ):
            exists = self.snapshot_query(
                f"SELECT pg_catalog.to_regclass('public.{table_name}') IS NOT NULL"
            )
            if exists == "f":
                counts[table_name] = None
                continue
            if exists != "t":
                raise StreamFailure(EXIT_SOURCE_SNAPSHOT)
            count = self.snapshot_query(
                f"SELECT count(*) FROM public.{table_name}"
            )
            if not count.isdigit():
                raise StreamFailure(EXIT_SOURCE_SNAPSHOT)
            counts[table_name] = int(count)

        if counts["usage_logs"] is None:
            usage = None
        else:
            raw_usage = self.snapshot_query(
                "SELECT jsonb_build_object("
                "'rows', count(*)::text, "
                "'request_ids', count(request_id)::text, "
                "'input_tokens', COALESCE(sum(input_tokens), 0)::text, "
                "'output_tokens', COALESCE(sum(output_tokens), 0)::text, "
                "'total_cost', COALESCE(sum(total_cost), 0)::text, "
                "'actual_cost', COALESCE(sum(actual_cost), 0)::text"
                ")::text FROM public.usage_logs"
            )
            try:
                usage = json.loads(raw_usage)
            except (json.JSONDecodeError, TypeError) as error:
                raise StreamFailure(EXIT_SOURCE_SNAPSHOT) from error
            if not isinstance(usage, dict) or set(usage) != {
                "rows",
                "request_ids",
                "input_tokens",
                "output_tokens",
                "total_cost",
                "actual_cost",
            }:
                raise StreamFailure(EXIT_SOURCE_SNAPSHOT)
            for key, value in usage.items():
                if not isinstance(value, str) or not NUMBER_RE.fullmatch(value):
                    raise StreamFailure(EXIT_SOURCE_SNAPSHOT)
                if key not in {"total_cost", "actual_cost"} and not value.isdigit():
                    raise StreamFailure(EXIT_SOURCE_SNAPSHOT)
        return counts, usage

    def stop_holder(self, process, error_code, cleanup_deadline=None):
        if process is None:
            return
        if cleanup_deadline is None:
            cleanup_deadline = min(self.deadline, time.monotonic() + 4)
        if process is self.snapshot_holder:
            backend_identity = self.snapshot_backend_identity
        else:
            backend_identity = self.lock_backend_identity
        try:
            self.send(process, b"ROLLBACK;\n\\q\n", error_code)
            self.close_input(process, error_code)
            remaining = min(self.remaining(), cleanup_deadline - time.monotonic())
            if remaining <= 0:
                raise StreamFailure(EXIT_DEADLINE)
            try:
                return_code = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired as error:
                raise StreamFailure(EXIT_DEADLINE) from error
            self.processes.discard(process)
            if return_code != 0:
                raise StreamFailure(error_code)
        except Exception:
            self.terminate_source_backend(backend_identity, cleanup_deadline)
            self.abort(process, cleanup_deadline)
            raise
        finally:
            if process is self.snapshot_holder:
                self.snapshot_holder = None
                self.snapshot_backend_identity = None
            if process is self.lock_holder:
                self.lock_holder = None
                self.lock_backend_identity = None

    def terminate_source_backend(self, backend_identity, cleanup_deadline):
        if (
            not isinstance(backend_identity, tuple)
            or len(backend_identity) != 3
            or not all(isinstance(value, int) for value in backend_identity)
        ):
            return
        backend_pid, database_oid, backend_start_us = backend_identity
        if (
            backend_pid <= 0
            or database_oid <= 0
            or database_oid > 4_294_967_295
            or backend_start_us <= 0
            or backend_start_us > 9_223_372_036_854_775_807
            or cleanup_deadline <= time.monotonic()
        ):
            return
        sql = (
            "SELECT pg_catalog.pg_terminate_backend(pid, 1000) "
            "FROM pg_catalog.pg_stat_activity "
            f"WHERE pid = {backend_pid} "
            f"AND datid = {database_oid} "
            "AND floor(extract(epoch from backend_start) * 1000000)::bigint "
            f"= {backend_start_us};\n"
        ).encode("ascii")
        process = None
        try:
            process = subprocess.Popen(
                self.source_psql(),
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=safe_environment(
                    "-c default_transaction_read_only=off "
                    "-c lock_timeout=1000 -c statement_timeout=1500 "
                    "-c application_name=sub2api_gate_cleanup"
                ),
                start_new_session=True,
                close_fds=True,
            )
            remaining = cleanup_deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(self.source_psql(), 0)
            process.communicate(input=sql, timeout=min(2, remaining))
        except (OSError, subprocess.SubprocessError):
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (OSError, ProcessLookupError):
                    pass
                remaining = cleanup_deadline - time.monotonic()
                try:
                    if remaining > 0:
                        process.wait(timeout=min(0.5, remaining))
                except (subprocess.SubprocessError, ValueError):
                    pass

    def clear_source_clients(self):
        self.send(
            self.lock_holder,
            CLIENT_GUARD_SQL.encode("ascii"),
            EXIT_SOURCE_CLIENT_GUARD,
        )
        line = self.expect_marker(
            self.lock_holder,
            b"CLIENTS_CLEARED|",
            EXIT_SOURCE_CLIENT_GUARD,
        )
        parts = line.split(b"|")
        if len(parts) != 2 or not parts[1].isdigit():
            raise StreamFailure(EXIT_SOURCE_CLIENT_GUARD)

    def start_target(self):
        self.target = self.spawn(
            [
                *self.target_base,
                "psql",
                "--no-psqlrc",
                "--quiet",
                "--single-transaction",
                "-v",
                "ON_ERROR_STOP=1",
            ],
            pgoptions=(
                "-c lock_timeout=5000 -c statement_timeout=120000 "
                "-c idle_in_transaction_session_timeout=180000 "
                "-c application_name=sub2api_gate_target_restore"
            ),
        )
        # pg_dump emits SELECT results for sequence setval statements. Discard
        # all restore query output before connecting the dump pipe so an
        # unread target stdout pipe cannot deadlock the source and target.
        self.send(self.target, b"\\o /dev/null\n", EXIT_STREAM)

    def stream_dump(self, counts, usage, privacy_gate, target_gate):
        dump = self.spawn(
            [
                *self.source_base,
                "pg_dump",
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
                f"--snapshot={self.options.snapshot_id}",
            ],
            pgoptions=(
                "-c default_transaction_read_only=on -c lock_timeout=5000 "
                "-c statement_timeout=120000 "
                "-c idle_in_transaction_session_timeout=180000 "
                "-c application_name=sub2api_gate_snapshot_dump"
            ),
            stdin=subprocess.DEVNULL,
            stdout=self.target.stdin,
        )
        try:
            self.wait(dump, EXIT_STREAM)
        except Exception:
            self.abort(dump)
            raise
        if self.target.poll() is not None:
            raise StreamFailure(EXIT_STREAM)

        row_counts = json.dumps(counts, separators=(",", ":"), sort_keys=True)
        usage_aggregate = (
            "null"
            if usage is None
            else json.dumps(usage, separators=(",", ":"), sort_keys=True)
        )
        verification = bytearray(b"\n")
        verification.extend(privacy_gate)
        verification.extend(
            (
                "\nSET LOCAL sub2api_gate.expected_row_counts = '"
                + row_counts
                + "';\nSET LOCAL sub2api_gate.expected_usage_aggregate = '"
                + usage_aggregate
                + "';\n"
            ).encode("ascii")
        )
        verification.extend(target_gate)
        verification.extend(b"\n\\o\n\\echo TARGET_VALIDATED\n")
        self.send(self.target, bytes(verification), EXIT_STREAM)
        self.expect_marker(self.target, b"TARGET_VALIDATED", EXIT_STREAM)

    def commit_target(self):
        self.close_input(self.target, EXIT_STREAM)
        self.wait(self.target, EXIT_STREAM)
        self.target_committed = True
        self.target = None

    def rollback_target(self, cleanup_deadline):
        process = self.target
        if process is None:
            return
        rollback_sent = False
        if process.poll() is None:
            try:
                process.stdin.write(b"\nROLLBACK;\n\\q\n")
                process.stdin.flush()
                process.stdin.close()
                rollback_sent = True
            except (BrokenPipeError, OSError, ValueError):
                pass
        if rollback_sent:
            try:
                process.wait(
                    timeout=max(
                        0.05,
                        min(3, cleanup_deadline - time.monotonic()),
                    )
                )
            except (subprocess.TimeoutExpired, ValueError):
                pass
        self.abort(process, cleanup_deadline)
        self.target = None

    def execute(self):
        privacy_gate = read_gate(PRIVACY_GATE)
        portability_gate = read_gate(PORTABILITY_GATE)
        target_gate = read_gate(TARGET_GATE)
        try:
            self.start_lock_holder()
            self.start_snapshot_holder(privacy_gate, portability_gate)
            counts, usage = self.capture_manifest()
            self.start_target()
            self.stream_dump(counts, usage, privacy_gate, target_gate)

            self.stop_holder(self.snapshot_holder, EXIT_SOURCE_SNAPSHOT)
            self.clear_source_clients()
            self.commit_target()
            self.stop_holder(self.lock_holder, EXIT_SOURCE_LOCK)
        finally:
            cleanup_deadline = time.monotonic() + 4
            if self.target is not None and not self.target_committed:
                self.rollback_target(cleanup_deadline)
            if self.snapshot_holder is not None:
                try:
                    self.stop_holder(
                        self.snapshot_holder,
                        EXIT_SOURCE_SNAPSHOT,
                        cleanup_deadline=cleanup_deadline,
                    )
                except Exception:
                    self.abort(self.snapshot_holder, cleanup_deadline)
                    self.snapshot_holder = None
            if self.lock_holder is not None:
                try:
                    self.stop_holder(
                        self.lock_holder,
                        EXIT_SOURCE_LOCK,
                        cleanup_deadline=cleanup_deadline,
                    )
                except Exception:
                    self.abort(self.lock_holder, cleanup_deadline)
                    self.lock_holder = None
            for process in tuple(self.processes):
                self.abort(process, cleanup_deadline)


def parse_arguments(argv):
    parser = RedactedArgumentParser(allow_abbrev=False)
    parser.add_argument("--deadline-seconds", type=int, required=True)
    parser.add_argument("--env-file", type=pathlib.Path, required=True)
    parser.add_argument("--source-app-container", required=True)
    parser.add_argument("--source-app-id", required=True)
    parser.add_argument("--source-postgres-container", required=True)
    parser.add_argument("--source-postgres-id", required=True)
    parser.add_argument("--source-system-id", required=True)
    parser.add_argument("--source-database-oid", required=True)
    parser.add_argument("--source-database-name-hex", required=True)
    options = parser.parse_args(argv)
    if (
        options.deadline_seconds < 1
        or options.deadline_seconds > 180
        or not options.env_file.is_absolute()
        or not CONTAINER_NAME_RE.fullmatch(options.source_app_container)
        or not CONTAINER_NAME_RE.fullmatch(options.source_postgres_container)
        or not CONTAINER_ID_RE.fullmatch(options.source_app_id)
        or not CONTAINER_ID_RE.fullmatch(options.source_postgres_id)
        or not SYSTEM_ID_RE.fullmatch(options.source_system_id)
        or not OID_RE.fullmatch(options.source_database_oid)
        or int(options.source_database_oid) > 4_294_967_295
        or not NAME_HEX_RE.fullmatch(options.source_database_name_hex)
    ):
        parser.error("invalid sanitized PostgreSQL stream arguments")
    options.snapshot_id = ""
    return options


def main(argv=None):
    options = parse_arguments(sys.argv[1:] if argv is None else argv)
    stream = LockedStream(options)

    def interrupted(_signum, _frame):
        raise StreamFailure(EXIT_DEADLINE)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    try:
        stream.execute()
    except StreamFailure as error:
        return error.exit_code
    except (OSError, subprocess.SubprocessError, ValueError):
        return EXIT_STREAM
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
