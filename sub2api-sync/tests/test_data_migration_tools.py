import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import time
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
POSTGRES_MIGRATION = ROOT / "deploy" / "migrate-sanitized-postgres.sh"
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
        self.assertIn("SUB2API_MIGRATION_WRITES_STOPPED=YES", script)
        self.assertIn("verify_no_conversation_content.sql", script)
        self.assertIn("pg_dump", script)
        self.assertIn("| PGDATABASE=", script)
        self.assertIn("--single-transaction", script)
        self.assertIn("180", script)
        self.assertIn("checkpoint:", script)
        self.assertIn("SUB2API_EXPECTED_ROW_COUNTS", script)
        self.assertIn("SUB2API_EXPECTED_USAGE_AGGREGATE", script)
        self.assertIn("verify-sanitized-target.sql", script)
        self.assertIn("verify-postgres-portability.sql", script)
        self.assertIn("pg_control_system()", script)
        self.assertIn("different physical PostgreSQL clusters", script)
        self.assertIn("sanitized_postgres_portability_gate_failed", script)
        self.assertGreaterEqual(script.count("2>/dev/null"), 2)
        self.assertIn("sanitized_postgres_stream_failed", script)
        self.assertNotIn("cat $stream_stderr", script)
        for forbidden in (
            "pg_basebackup",
            "pg_waldump",
            "/var/lib/postgresql/data",
            "--format=custom",
        ):
            self.assertNotIn(forbidden, script)

    def test_postgres_url_wrapper_keeps_credentials_out_of_argv(self):
        wrapper = load_python_script(PG_ENV_EXEC, "pg_env_exec")
        original = {
            "SUB2API_SOURCE_DATABASE_URL": (
                "postgresql://user%40name:password%2Fvalue@db.example:5544/app%2Ddb"
                "?sslmode=verify-full&sslrootcert=system&connect_timeout=7"
            ),
            "PGHOST": "must-be-replaced",
        }
        result = wrapper.libpq_environment(
            original, "SUB2API_SOURCE_DATABASE_URL"
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

        script = POSTGRES_MIGRATION.read_text()
        self.assertNotIn('--dbname="$SUB2API_SOURCE_DATABASE_URL"', script)
        self.assertNotIn('--dbname="$SUB2API_TARGET_DATABASE_URL"', script)
        self.assertTrue(TARGET_VALIDATOR.exists())

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
            self.assertEqual((info.st_uid, info.st_gid), (1000, 1000))
            self.assertEqual(info.st_mode & 0o777, 0o600)
            marker_info = (target / ".installed").stat()
            self.assertEqual((marker_info.st_uid, marker_info.st_gid), (1000, 1000))
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
        self.assertIn("source_postgres_system_identifier", script)
        self.assertIn("policy_files", script)
        self.assertIn("HEAD^{commit}", script)
        self.assertIn('require_private_directory "$data_root" "0:0:700"', script)
        self.assertIn('require_private_directory "$backup_root" "0:0:700"', script)
        self.assertLess(
            script.index('require_private_directory "$data_root" "0:0:700"'),
            script.index("coproc SNAPSHOT_HOLDER"),
        )

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
