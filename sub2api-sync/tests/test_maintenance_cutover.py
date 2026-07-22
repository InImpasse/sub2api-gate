import importlib.util
import io
import hashlib
import os
import pathlib
import json
import signal
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "maintenance-cutover.py"
TRAFFIC_PATH = ROOT / "deploy" / "traffic-canary.py"
REDIS_MIGRATION_COMPOSE = ROOT / "docker-compose.redis-migration.yml"
POSTGRES_MIGRATION_COMPOSE = ROOT / "docker-compose.postgres-migration.yml"


def load_tool(path, name):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


class NeverRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), kwargs))
        raise AssertionError("offline check attempted a command")


class StubNginx:
    def __init__(self, events):
        self.events = events

    def require_stage(self, stage):
        self.events.append(f"nginx-require:{stage}")

    def verify_live_direct_v1(self, hostname):
        self.events.append(f"nginx-direct:{hostname}")

    def switch(self, stage, *, timeout):
        self.events.append(f"nginx:{stage}")


class RollbackRunner:
    def __init__(self, tool, services, events):
        self.tool = tool
        self.services = services
        self.events = events
        self.running = {
            services.app.name: False,
            services.postgres.name: False,
            services.redis.name: False,
        }
        self.identities = {item.name: item.identity for item in services.containers()}
        self.health = {item.name: "healthy" for item in services.containers()}
        self.health_sequences = {}
        self.sync_active = False
        self.traffic_targets = set(tool.TARGET_NAMES)
        self.nonce_targets = {tool.TARGET_NONCE_REDIS}

    def __call__(
        self,
        argv,
        *,
        timeout,
        environment=None,
        allow_failure=False,
        interactive=False,
    ):
        argv = [str(value) for value in argv]
        if argv[:2] == ["docker", "inspect"]:
            name = argv[-1]
            template = argv[3]
            if name in self.identities:
                identity = self.identities[name]
                running = "true" if self.running[name] else "false"
                sequence = self.health_sequences.get(name)
                if sequence:
                    health = sequence.pop(0) if len(sequence) > 1 else sequence[0]
                else:
                    health = self.health[name]
                self.events.append(f"inspect:{name}:{running}:{health}")
                output = (
                    f"{identity}|{running}|{health}"
                    if "State.Health" in template
                    else identity
                )
                return self.tool.CommandResult(0, output.encode())
            exists = name in self.traffic_targets or name in self.nonce_targets
            return self.tool.CommandResult(0 if exists else 1, b"target-id" if exists else b"")
        if argv[:2] == ["docker", "start"]:
            name = argv[-1]
            self.events.append(f"start:{name}")
            self.running[name] = True
            return self.tool.CommandResult(0)
        if argv[:3] == ["/usr/bin/systemctl", "show", self.tool.SYNC_UNIT]:
            return self.tool.CommandResult(
                0,
                (
                    "Id=sub2api-sync.service\n"
                    "LoadState=loaded\n"
                    "FragmentPath=/etc/systemd/system/sub2api-sync.service\n"
                ).encode(),
            )
        if argv[:3] == ["/usr/bin/systemctl", "is-active", "--quiet"]:
            return self.tool.CommandResult(0 if self.sync_active else 3)
        if argv[:3] == ["/usr/bin/systemctl", "start", self.tool.SYNC_UNIT]:
            self.events.append("start:sync")
            self.sync_active = True
            return self.tool.CommandResult(0)
        if "down" in argv and str(self.tool.COMPOSE_FILE) in argv:
            self.events.append("down:traffic")
            self.traffic_targets.clear()
            return self.tool.CommandResult(0)
        if "down" in argv and str(self.tool.SYNC_COMPOSE_FILE) in argv:
            self.events.append("down:nonce")
            self.nonce_targets.clear()
            return self.tool.CommandResult(0)
        if argv[-2:] == ["configure-redis-migration-acl.py", "--remove"]:
            self.events.append("remove:migration-acl")
            return self.tool.CommandResult(0)
        if "configure-redis-migration-acl.py" in " ".join(argv) and "--remove" in argv:
            self.events.append("remove:migration-acl")
            return self.tool.CommandResult(0)
        raise AssertionError(f"unexpected command: {argv}")


class MaintenanceCutoverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool(TOOL_PATH, "maintenance_cutover_tests")

    def services(self):
        return self.tool.LegacyServices(
            self.tool.LegacyService("legacy-app", "a" * 64),
            self.tool.LegacyService("legacy-postgres", "b" * 64),
            self.tool.LegacyService("legacy-redis", "c" * 64),
        )

    def options(self):
        return types.SimpleNamespace(env_file=pathlib.Path("/private/env"))

    def test_default_check_is_offline_and_side_effect_free(self):
        runner = NeverRunner()
        stdout = io.StringIO()
        result = self.tool.main(["check"], runner=runner, stdout=stdout)
        self.assertEqual(result, 0)
        self.assertFalse(runner.calls)
        self.assertIn("no private file was read", stdout.getvalue())
        self.assertIn("no service or data changed", stdout.getvalue())

    def test_runtime_images_are_attested_before_writer_stop_and_never_pulled(self):
        source = TOOL_PATH.read_text(encoding="utf-8")
        image_gate = source.index("traffic_canary.require_local_runtime_images")
        writer_stop = source.index("    def stop_writers(self):")
        self.assertLess(image_gate, writer_stop)
        self.assertGreaterEqual(source.count('"--pull",\n'), 5)
        self.assertGreaterEqual(source.count('"never",\n'), 5)
        self.assertNotIn('"--pull",\n                "always",', source)

    def test_writer_stop_has_an_independent_60_second_deadline(self):
        clock = mock.Mock(return_value=45.0)
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return self.tool.CommandResult(0)

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={},
            runner=runner,
            nginx=StubNginx([]),
            clock=clock,
        )
        controller.deadline = 225.0
        controller.writer_stop_deadline = 50.0
        controller.run(["true"], timeout=20)
        self.assertEqual(calls[0][1]["timeout"], 5)

        clock.return_value = 50.0
        with self.assertRaisesRegex(
            self.tool.WindowExpired, "60-second writer-stop deadline exceeded"
        ):
            controller.run(["true"], timeout=20)

    def test_apply_requires_full_legacy_identities_and_explicit_paths(self):
        base = [
            "--apply",
            "--env-file", "/private/env",
            "--wrangler-config", "/private/wrangler.jsonc",
            "--safe-export-dir", "/mnt/data/sub2api-gate/safe-backup/export-20260722T000000Z",
            "--legacy-sub2api-container", "legacy-app",
            "--legacy-sub2api-id", "a" * 64,
            "--legacy-postgres-container", "legacy-postgres",
            "--legacy-postgres-id", "b" * 64,
            "--legacy-redis-container", "legacy-redis",
            "--legacy-redis-id", "c" * 64,
            "--verify-url", "https://gateway.example.test/v1/responses",
            "--model", "model-test",
            "--approved-hostname", "gateway.example.test",
        ]
        with self.assertRaisesRegex(self.tool.UsageError, "exact legacy identity"):
            self.tool.parse_arguments(base)
        complete = base + [
            "--legacy-app-path", "/legacy/app",
            "--legacy-postgres-path", "/legacy/postgres",
            "--legacy-redis-path", "/legacy/redis",
            "--legacy-nginx-log-path", "/var/log/nginx",
        ]
        mode, _options, services = self.tool.parse_arguments(complete)
        self.assertEqual(mode, "--apply")
        self.assertEqual(services.app.identity, "a" * 64)

        recover = [
            "--recover",
            "--env-file", "/private/env",
            "--legacy-sub2api-container", "legacy-app",
            "--legacy-sub2api-id", "a" * 64,
            "--legacy-postgres-container", "legacy-postgres",
            "--legacy-postgres-id", "b" * 64,
            "--legacy-redis-container", "legacy-redis",
            "--legacy-redis-id", "c" * 64,
        ]
        mode, _options, recovered_services = self.tool.parse_arguments(recover)
        self.assertEqual(mode, "--recover")
        self.assertEqual(recovered_services.redis.identity, "c" * 64)
        with self.assertRaisesRegex(self.tool.UsageError, "requires only"):
            self.tool.parse_arguments(recover + ["--model", "ambiguous"])

    def test_persistent_recovery_state_is_private_atomic_and_contains_no_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve() / "safe-backup"
            root.mkdir(mode=0o700)
            state_path = root / "maintenance-cutover-state.json"
            document = {
                "version": 1,
                "phase": "migrating",
                "git_head": "a" * 40,
                "env_file": "/private/runtime.env",
                "sync_fragment": "/etc/systemd/system/sub2api-sync.service",
                "legacy": {
                    "app": {"name": "legacy-app", "identity": "a" * 64},
                    "postgres": {"name": "legacy-postgres", "identity": "b" * 64},
                    "redis": {"name": "legacy-redis", "identity": "c" * 64},
                },
                "target_started": True,
                "nonce_target_started": True,
                "nonce_runtime_active": False,
                "writers_stopped": True,
                "canary_active": False,
            }
            with mock.patch.object(self.tool, "SAFE_BACKUP_ROOT", root), mock.patch.object(
                self.tool, "CUTOVER_STATE_PATH", state_path
            ):
                self.tool.write_cutover_state(
                    state_path, document, expected_uid=os.geteuid()
                )
                self.assertEqual(
                    stat.S_IMODE(state_path.stat().st_mode),
                    0o600,
                )
                payload = state_path.read_text(encoding="ascii")
                self.assertNotIn("password", payload.lower())
                self.assertNotIn("postgresql://", payload)
                self.assertEqual(
                    self.tool.load_cutover_state(
                        state_path, expected_uid=os.geteuid()
                    ),
                    document,
                )
                self.tool.clear_cutover_state(
                    state_path, expected_uid=os.geteuid()
                )
                self.assertFalse(state_path.exists())

    def test_safe_export_manifest_binds_artifacts_policy_git_and_source_cluster(self):
        with tempfile.TemporaryDirectory() as directory:
            backup_root = pathlib.Path(directory).resolve() / "safe-backup"
            export = backup_root / "export-20260722T000000Z"
            backup_root.mkdir(mode=0o700)
            export.mkdir(mode=0o700)
            artifacts = {}
            for name in self.tool.SAFE_EXPORT_ARTIFACTS:
                payload = f"metadata:{name}\n".encode()
                path = export / name
                path.write_bytes(payload)
                path.chmod(0o600)
                artifacts[name] = hashlib.sha256(payload).hexdigest()
            policy = {
                name: self.tool._sha256_repository_file(name)
                for name in self.tool.SAFE_EXPORT_POLICY_FILES
            }
            completed_at = "2026-07-22T00:00:00Z"
            manifest = {
                "version": 1,
                "completed_at": completed_at,
                "git_head": "a" * 40,
                "source_postgres_system_identifier": "1234567890123456789",
                "artifacts": artifacts,
                "policy_files": policy,
            }
            control_files = {
                "manifest.json": (json.dumps(manifest, sort_keys=True) + "\n").encode(),
                "SHA256SUMS": "".join(
                    f"{artifacts[name]}  {name}\n"
                    for name in self.tool.SAFE_EXPORT_ARTIFACTS
                ).encode(),
                "COMPLETE": f"completed_at={completed_at}\n".encode(),
            }
            for name, payload in control_files.items():
                path = export / name
                path.write_bytes(payload)
                path.chmod(0o600)

            with mock.patch.object(self.tool, "SAFE_BACKUP_ROOT", backup_root):
                identity = self.tool.validate_safe_export(
                    export,
                    "a" * 40,
                    expected_uid=os.geteuid(),
                )
                self.assertEqual(identity, "1234567890123456789")
                (export / "usage_metadata.csv").write_bytes(b"tampered\n")
                (export / "usage_metadata.csv").chmod(0o600)
                with self.assertRaisesRegex(self.tool.CutoverError, "artifact hash"):
                    self.tool.validate_safe_export(
                        export,
                        "a" * 40,
                        expected_uid=os.geteuid(),
                    )

    def test_safe_export_rejects_wrong_git_policy_and_unexpected_files(self):
        with tempfile.TemporaryDirectory() as directory:
            backup_root = pathlib.Path(directory).resolve() / "safe-backup"
            export = backup_root / "export-20260722T000000Z"
            backup_root.mkdir(mode=0o700)
            export.mkdir(mode=0o700)
            (export / "unexpected").write_bytes(b"")
            (export / "unexpected").chmod(0o600)
            with mock.patch.object(self.tool, "SAFE_BACKUP_ROOT", backup_root), \
                 self.assertRaisesRegex(self.tool.CutoverError, "file set"):
                self.tool.validate_safe_export(
                    export,
                    "a" * 40,
                    expected_uid=os.geteuid(),
                )

    def test_minimal_child_environment_does_not_propagate_ambient_secrets(self):
        with mock.patch.dict(
            os.environ,
            {
                "CLOUDFLARE_API_TOKEN": "ambient-secret",
                "SSH_AUTH_SOCK": "/private/agent.sock",
                "SUB2API_SOURCE_DATABASE_URL": "ambient-database-secret",
            },
            clear=False,
        ):
            environment = self.tool.minimal_environment()
        self.assertNotIn("CLOUDFLARE_API_TOKEN", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertNotIn("SUB2API_SOURCE_DATABASE_URL", environment)
        self.assertEqual(environment["DOCKER_HOST"], "unix:///var/run/docker.sock")

    def test_private_values_are_added_only_to_the_step_that_requests_them(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((list(argv), dict(kwargs["environment"])))
            return self.tool.CommandResult(0)

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={
                "SUB2API_SOURCE_DATABASE_URL": "postgresql://source-secret",
                "SUB2API_TARGET_DATABASE_URL": "postgresql://target-secret",
                "CLOUDFLARE_API_TOKEN": "must-not-be-forwarded",
            },
            runner=runner,
            nginx=StubNginx([]),
        )
        controller.run(["docker", "inspect", "legacy-app"], timeout=5)
        controller.run(
            ["psql"],
            timeout=5,
            private_keys=("SUB2API_SOURCE_DATABASE_URL",),
        )
        self.assertNotIn("SUB2API_SOURCE_DATABASE_URL", calls[0][1])
        self.assertNotIn("CLOUDFLARE_API_TOKEN", calls[0][1])
        self.assertEqual(
            calls[1][1]["SUB2API_SOURCE_DATABASE_URL"],
            "postgresql://source-secret",
        )
        self.assertNotIn("SUB2API_TARGET_DATABASE_URL", calls[1][1])
        self.assertNotIn("CLOUDFLARE_API_TOKEN", calls[1][1])

    def test_source_redis_preflight_authenticates_and_binds_run_id_to_exact_container(self):
        recorded = {}
        runner_calls = []
        run_id = "f" * 40

        class Endpoint:
            scheme = "redis"
            host = "127.0.0.1"
            port = 16378
            database = 0

        class Connection:
            def __init__(self, endpoint, password, deadline, username):
                recorded.update(
                    endpoint=endpoint,
                    password=password,
                    username=username,
                    deadline=deadline,
                )

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def execute(self, *command):
                recorded.setdefault("commands", []).append(command)
                if command == ("PING",):
                    return b"PONG"
                return f"redis_version:8.8.0\r\nrun_id:{run_id}\r\n".encode()

        migration = types.SimpleNamespace(
            parse_redis_url=lambda value, label: Endpoint(),
            RedisConnection=Connection,
            parse_info=lambda raw: {
                line.split(b":", 1)[0].decode(): line.split(b":", 1)[1].decode()
                for line in raw.splitlines()
                if b":" in line
            },
        )

        def runner(argv, **kwargs):
            runner_calls.append(list(argv))
            if "NetworkSettings" in argv[3]:
                return self.tool.CommandResult(
                    0,
                    json.dumps({
                        "Networks": {"legacy": {"IPAddress": "172.18.0.4"}},
                        "Ports": {
                            "6379/tcp": [
                                {"HostIp": "127.0.0.1", "HostPort": "16378"}
                            ]
                        },
                    }).encode(),
                )
            raise AssertionError(argv)

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={
                "SUB2API_SOURCE_REDIS_URL": "redis://127.0.0.1:16378/0",
                "SUB2API_SOURCE_REDIS_USERNAME": "default",
                "SUB2API_SOURCE_REDIS_PASSWORD": "source-secret",
            },
            runner=runner,
            nginx=StubNginx([]),
        )
        with mock.patch.object(self.tool, "load_module", return_value=migration):
            controller.verify_legacy_redis_source()
        self.assertEqual(recorded["password"], "source-secret")
        self.assertEqual(recorded["username"], "default")
        self.assertEqual(recorded["commands"], [("PING",), ("INFO", "server")])
        self.assertTrue(runner_calls)
        self.assertTrue(all(call[:2] == ["docker", "inspect"] for call in runner_calls))

    def test_source_redis_loopback_preflight_rejects_wrong_exact_port_binding(self):
        endpoint = types.SimpleNamespace(
            scheme="redis", host="127.0.0.1", port=16378, database=0
        )
        migration = types.SimpleNamespace(
            parse_redis_url=lambda _value, _label: endpoint,
            RedisConnection=lambda *_args: (_ for _ in ()).throw(
                AssertionError("wrong binding must fail before authentication")
            ),
        )

        def runner(argv, **_kwargs):
            return self.tool.CommandResult(
                0,
                json.dumps({
                    "Networks": {"legacy": {"IPAddress": "172.18.0.4"}},
                    "Ports": {
                        "6379/tcp": [
                            {"HostIp": "127.0.0.1", "HostPort": "6379"}
                        ]
                    },
                }).encode(),
            )

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={
                "SUB2API_SOURCE_REDIS_URL": "redis://127.0.0.1:16378/0",
                "SUB2API_SOURCE_REDIS_PASSWORD": "source-secret",
            },
            runner=runner,
            nginx=StubNginx([]),
        )
        with mock.patch.object(self.tool, "load_module", return_value=migration), \
             self.assertRaisesRegex(self.tool.CutoverError, "exact container port binding"):
            controller.verify_legacy_redis_source()

    def test_source_redis_bridge_preflight_accepts_only_exact_container_ip(self):
        run_id = "e" * 40
        endpoint = types.SimpleNamespace(
            scheme="redis", host="172.18.0.4", port=6379, database=0
        )

        class Connection:
            def __init__(self, *_args):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                pass

            def execute(self, command, *args):
                return b"PONG" if command == "PING" else (
                    f"redis_version:8.8.0\r\nrun_id:{run_id}\r\n".encode()
                )

        migration = types.SimpleNamespace(
            parse_redis_url=lambda _value, _label: endpoint,
            RedisConnection=Connection,
            parse_info=lambda _raw: {"redis_version": "8.8.0", "run_id": run_id},
        )

        def settings(address):
            return self.tool.CommandResult(
                0,
                json.dumps({
                    "Networks": {"legacy": {"IPAddress": address}},
                    "Ports": {},
                }).encode(),
            )

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={
                "SUB2API_SOURCE_REDIS_URL": "redis://172.18.0.4:6379/0",
                "SUB2API_SOURCE_REDIS_PASSWORD": "source-secret",
            },
            runner=lambda *_args, **_kwargs: settings("172.18.0.4"),
            nginx=StubNginx([]),
        )
        with mock.patch.object(self.tool, "load_module", return_value=migration):
            controller.verify_legacy_redis_source()
        controller.runner = lambda *_args, **_kwargs: settings("172.18.0.5")
        with mock.patch.object(self.tool, "load_module", return_value=migration), \
             self.assertRaisesRegex(self.tool.CutoverError, "exact local container endpoint"):
            controller.verify_legacy_redis_source()

    def test_postgres_preflight_binds_source_and_target_urls_to_exact_ports(self):
        calls = []
        pg_helper = types.SimpleNamespace(
            libpq_environment=lambda environment, name: {
                "PGHOST": "127.0.0.1",
                "PGPORT": "15431" if name == "SUB2API_SOURCE_DATABASE_URL" else "15432",
            }
        )

        def runner(argv, **kwargs):
            calls.append((list(argv), dict(kwargs["environment"])))
            if argv[:2] == ["docker", "inspect"]:
                port = "15431" if argv[-1] == "legacy-postgres" else "15432"
                return self.tool.CommandResult(
                    0,
                    json.dumps({
                        "Networks": {"data": {"IPAddress": "172.18.0.3"}},
                        "Ports": {
                            "5432/tcp": [
                                {"HostIp": "127.0.0.1", "HostPort": port}
                            ]
                        },
                    }).encode(),
                )
            return self.tool.CommandResult(0, b"1234567890123456789\n")

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={
                "SUB2API_SOURCE_DATABASE_URL": "source-secret-url",
                "SUB2API_TARGET_DATABASE_URL": "target-secret-url",
            },
            runner=runner,
            nginx=StubNginx([]),
        )
        with mock.patch.object(self.tool, "load_module", return_value=pg_helper):
            identities = controller.verify_database_connections()
        self.assertEqual(
            identities["SUB2API_SOURCE_DATABASE_URL"],
            "1234567890123456789",
        )
        psql_calls = [call for call in calls if call[0][0] == "python3"]
        self.assertEqual(len(psql_calls), 2)
        self.assertIn("SUB2API_SOURCE_DATABASE_URL", psql_calls[0][1])
        self.assertNotIn("SUB2API_TARGET_DATABASE_URL", psql_calls[0][1])
        self.assertIn("SUB2API_TARGET_DATABASE_URL", psql_calls[1][1])

    def test_safe_export_source_cluster_must_match_live_source_before_cutover(self):
        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={},
            runner=NeverRunner(),
            nginx=StubNginx([]),
        )
        controller.export_source_system_identifier = "1234567890123456789"
        controller.require_export_source_identity({
            "SUB2API_SOURCE_DATABASE_URL": "1234567890123456789"
        })
        with self.assertRaisesRegex(self.tool.CutoverError, "different source"):
            controller.require_export_source_identity({
                "SUB2API_SOURCE_DATABASE_URL": "9876543210987654321"
            })

    def test_safe_export_or_live_nginx_failure_cannot_stop_writers(self):
        tool = self.tool
        for failed_gate in (
            "safe-export",
            "live-nginx",
            "runtime-images",
            "source-cluster",
        ):
            with self.subTest(failed_gate=failed_gate):
                events = []

                class Phases:
                    target_started = False
                    writers_stopped = False
                    clock = staticmethod(lambda: 100.0)

                    def preflight(self):
                        events.append(failed_gate)
                        raise tool.CutoverError(f"{failed_gate} rejected")

                    def stop_writers(self):
                        events.append("stop-writers")

                    def rollback(self):
                        events.append("rollback")
                        return []

                    def log(self, _message):
                        pass

                with self.assertRaisesRegex(tool.CutoverError, "cutover_phase_failed"):
                    tool.MaintenanceController.execute(Phases())
                self.assertEqual(events, [failed_gate])

    def test_nginx_switch_is_atomic_only_inside_a_temporary_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            snippets = root / "snippets"
            state = root / "sub2api-gate"
            snippets.mkdir()
            snippets.chmod(0o755)
            active = snippets / "sub2api-upstream-active.conf"
            active.write_bytes(b"server 127.0.0.1:8080;\n")
            active.chmod(0o644)
            paths = self.tool.NginxPaths(root=root, active=active, state=state)
            calls = []

            def runner(argv, **kwargs):
                calls.append(list(argv))
                return self.tool.CommandResult(0)

            with self.tool.NginxUpstream(paths, runner, production=False) as nginx:
                nginx.switch("canary", timeout=10)
                self.assertEqual(active.read_bytes(), b"server 127.0.0.1:8081;\n")
                nginx.switch("stable", timeout=10)
            self.assertEqual(active.read_bytes(), b"server 127.0.0.1:8080;\n")
            self.assertEqual(sum(call == ["/usr/sbin/nginx", "-t"] for call in calls), 2)

    def test_live_nginx_gate_requires_capture_free_named_direct_upstream(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve() / "nginx"
            snippets = root / "snippets"
            sites = root / "sites-enabled"
            state = root / "sub2api-gate"
            snippets.mkdir(parents=True)
            sites.mkdir()
            for path in (root, snippets, sites):
                path.chmod(0o755)
            active = snippets / "sub2api-upstream-active.conf"
            active.write_bytes(b"server 127.0.0.1:8080;\n")
            active.chmod(0o644)
            site = sites / "sub2api.conf"
            site.write_text((ROOT / "nginx/sub2api.conf").read_text(), encoding="utf-8")
            site.chmod(0o644)
            paths = self.tool.NginxPaths(
                root=root,
                active=active,
                state=state,
                site=site,
            )
            nginx = self.tool.NginxUpstream(
                paths,
                lambda *_args, **_kwargs: self.tool.CommandResult(0),
                production=False,
            )
            nginx.verify_live_direct_v1("api.example.com")
            site.write_text(
                site.read_text().replace(
                    "proxy_request_buffering off;",
                    "mirror /capture;\n        proxy_request_buffering off;",
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(self.tool.CutoverError, "capture-free"):
                nginx.verify_live_direct_v1("api.example.com")

    def test_rollback_starts_and_health_checks_legacy_before_stable_then_isolates_targets(self):
        events = []
        services = self.services()
        runner = RollbackRunner(self.tool, services, events)
        runner.health_sequences[services.postgres.name] = [
            "healthy",
            "starting",
            "healthy",
        ]
        runner.health_sequences[services.redis.name] = [
            "healthy",
            "starting",
            "healthy",
        ]

        def health(port, path):
            events.append(f"health:{port}{path}")

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=services,
            private_values={},
            runner=runner,
            nginx=StubNginx(events),
            health_probe=health,
            sleeper=lambda _seconds: None,
            target_resetter=lambda: events.append("reset:target"),
        )
        controller.sync_fragment = "/etc/systemd/system/sub2api-sync.service"
        controller.target_started = True
        controller.nonce_target_started = True
        errors = controller.rollback()

        self.assertEqual(errors, [])
        stable = events.index("nginx:stable")
        self.assertLess(events.index("health:8080/health"), stable)
        self.assertLess(events.index("health:3021/healthz"), stable)
        self.assertLess(
            events.index(f"inspect:{services.postgres.name}:true:healthy"),
            events.index(f"start:{services.redis.name}"),
        )
        self.assertLess(
            events.index(f"inspect:{services.redis.name}:true:healthy"),
            events.index(f"start:{services.app.name}"),
        )
        self.assertLess(stable, events.index("down:traffic"))
        self.assertLess(stable, events.index("down:nonce"))
        self.assertLess(events.index("down:nonce"), events.index("reset:target"))

    def test_rollback_never_starts_a_rebound_legacy_name(self):
        events = []
        services = self.services()
        runner = RollbackRunner(self.tool, services, events)
        runner.identities[services.app.name] = "d" * 64
        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=services,
            private_values={},
            runner=runner,
            nginx=StubNginx(events),
            health_probe=lambda *_args: None,
            sleeper=lambda _seconds: None,
            target_resetter=lambda: events.append("reset:target"),
        )
        controller.sync_fragment = "/etc/systemd/system/sub2api-sync.service"
        controller.target_started = True
        controller.nonce_target_started = True
        errors = controller.rollback()
        self.assertIn("legacy_app_start", errors)
        self.assertNotIn("nginx:stable", events)
        self.assertNotIn("down:traffic", events)
        self.assertNotIn("reset:target", events)

    def test_rollback_fails_closed_when_legacy_data_container_has_no_healthcheck(self):
        events = []
        services = self.services()
        runner = RollbackRunner(self.tool, services, events)
        runner.health[services.postgres.name] = "none"
        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=services,
            private_values={},
            runner=runner,
            nginx=StubNginx(events),
            health_probe=lambda *_args: None,
            sleeper=lambda _seconds: None,
            target_resetter=lambda: events.append("reset:target"),
        )
        controller.sync_fragment = "/etc/systemd/system/sub2api-sync.service"
        controller.target_started = True
        controller.nonce_target_started = True

        errors = controller.rollback()

        self.assertIn("legacy_postgres_start", errors)
        self.assertIn("stable_upstream_not_restored_without_healthy_legacy", errors)
        self.assertNotIn("nginx:stable", events)
        self.assertNotIn("down:traffic", events)

    def test_deadline_or_term_after_writer_stop_runs_rollback_and_reports_both_states(self):
        tool = self.tool

        class Phases:
            def __init__(self, error):
                self.error = error
                self.target_started = False
                self.writers_stopped = False
                self.clock = lambda: 100.0
                self.events = []

            def preflight(self):
                self.target_started = True

            def stop_writers(self):
                self.writers_stopped = True

            def migrate(self):
                raise self.error

            def start_target(self):
                raise AssertionError

            def switch_and_canary(self):
                raise AssertionError

            def rollback(self):
                self.events.append("rollback")
                return []

            def log(self, _message):
                pass

            def remaining(self):
                return 1

        for error, expected in (
            (tool.WindowExpired("expired"), "cutover_deadline_exceeded; rollback_verified"),
            (tool.TerminationRequested("term"), "cutover_interrupted; rollback_verified"),
        ):
            with self.subTest(expected=expected):
                phases = Phases(error)
                with self.assertRaisesRegex(tool.CutoverError, expected):
                    tool.MaintenanceController.execute(phases)
                self.assertEqual(phases.events, ["rollback"])

    def test_signal_handler_converts_term_and_restores_previous_handler(self):
        previous = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(self.tool.TerminationRequested):
            with self.tool.controlled_termination_signals():
                os.kill(os.getpid(), signal.SIGTERM)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)

    def test_real_sigterm_after_writer_stop_enters_execute_rollback(self):
        tool = self.tool

        class Phases:
            target_started = False
            writers_stopped = False
            clock = staticmethod(lambda: 100.0)

            def __init__(self):
                self.events = []

            def preflight(self):
                self.target_started = True

            def stop_writers(self):
                self.writers_stopped = True

            def migrate(self):
                os.kill(os.getpid(), signal.SIGTERM)

            def start_target(self):
                raise AssertionError

            def switch_and_canary(self):
                raise AssertionError

            def rollback(self):
                self.events.append("rollback")
                os.kill(os.getpid(), signal.SIGTERM)
                if hasattr(signal, "SIGHUP"):
                    os.kill(os.getpid(), signal.SIGHUP)
                self.events.append("rollback-complete")
                return []

            def log(self, _message):
                pass

            def remaining(self):
                return 1

        phases = Phases()
        with self.assertRaisesRegex(tool.CutoverError, "cutover_interrupted; rollback_verified"):
            with tool.controlled_termination_signals():
                tool.MaintenanceController.execute(phases)
        self.assertEqual(phases.events, ["rollback", "rollback-complete"])

    def test_second_sigint_is_deferred_until_rollback_finishes(self):
        events = []
        with self.tool.deferred_termination_signals() as received:
            os.kill(os.getpid(), signal.SIGINT)
            os.kill(os.getpid(), signal.SIGINT)
            events.append("rollback-complete")
        self.assertEqual(events, ["rollback-complete"])
        self.assertEqual(received, {signal.SIGINT})

    def test_target_reset_rejects_symlinks_and_clears_only_explicit_temporary_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pathlib.Path(directory).resolve() / "target"
            target.mkdir(mode=0o700)
            (target / "nested").mkdir()
            (target / "nested/data.aof").write_bytes(b"nonce")
            self.tool.clear_private_directory(
                target,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                exact_path=target,
            )
            self.assertEqual(list(target.iterdir()), [])
            (target / "second-attempt.aof").write_bytes(b"nonce")
            self.tool.clear_private_directory(
                target,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
                exact_path=target,
            )
            self.assertEqual(list(target.iterdir()), [])

            external = pathlib.Path(directory).resolve() / "external"
            external.mkdir()
            (target / "link").symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(self.tool.CutoverError, "unsafe entry"):
                self.tool.clear_private_directory(
                    target,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                    exact_path=target,
                )
            self.assertTrue(external.exists())

    def test_nonce_migration_override_has_only_fixed_loopback_port_and_acl(self):
        source = REDIS_MIGRATION_COMPOSE.read_text()
        self.assertIn('"127.0.0.1:16379:6379"', source)
        self.assertIn("source: /run/sub2api-gate/redis-migration.acl", source)
        self.assertIn("target: /etc/redis/users.acl", source)
        self.assertIn("create_host_path: false", source)
        self.assertNotIn("0.0.0.0", source)

    def test_merged_nonce_migration_compose_has_one_loopback_port_and_one_acl_mount(self):
        result = __import__("subprocess").run(
            [
                "docker", "compose",
                "--env-file", str(ROOT / ".env.example"),
                "-f", str(ROOT / "docker-compose.sync-canary.yml"),
                "-f", str(REDIS_MIGRATION_COMPOSE),
                "--profile", "sync-canary",
                "config", "--format", "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        document = json.loads(result.stdout)
        service = document["services"]["sync-canary-redis-nonce"]
        self.assertEqual(
            service["ports"],
            [{
                "mode": "ingress",
                "host_ip": "127.0.0.1",
                "target": 6379,
                "published": "16379",
                "protocol": "tcp",
            }],
        )
        acl_mounts = [
            item for item in service["volumes"]
            if item["target"] == "/etc/redis/users.acl"
        ]
        self.assertEqual(len(acl_mounts), 1)
        self.assertEqual(
            acl_mounts[0]["source"],
            "/run/sub2api-gate/redis-migration.acl",
        )

    def test_merged_postgres_migration_compose_has_only_fixed_loopback_port(self):
        result = __import__("subprocess").run(
            [
                "docker", "compose",
                "--env-file", str(ROOT / ".env.example"),
                "-f", str(ROOT / "docker-compose.traffic-canary.yml"),
                "-f", str(POSTGRES_MIGRATION_COMPOSE),
                "--profile", "traffic-canary",
                "config", "--format", "json",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        document = json.loads(result.stdout)
        postgres = document["services"]["traffic-canary-postgres"]
        self.assertEqual(
            postgres["ports"],
            [{
                "mode": "ingress",
                "host_ip": "127.0.0.1",
                "target": 5432,
                "published": "15432",
                "protocol": "tcp",
            }],
        )


class StoppedLegacyTrafficVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool(TRAFFIC_PATH, "traffic_stopped_legacy_tests")

    def test_verify_stopped_uses_exact_ids_and_live_pg_redis_machine_identities(self):
        names = self.tool.LegacyNames("legacy-app", "legacy-pg", "legacy-redis")
        identities = self.tool.LegacyContainerIds("a" * 64, "b" * 64, "c" * 64)

        def runner(argv, **_kwargs):
            name = argv[-1]
            state = "false" if name == "legacy-app" else "true"
            expected = {
                "legacy-app": "a" * 64,
                "legacy-pg": "b" * 64,
                "legacy-redis": "c" * 64,
            }[name]
            return types.SimpleNamespace(returncode=0, stdout=f"{expected}|{state}\n".encode())

        target = {"app": "d" * 64, "postgres": "22", "redis": "e" * 40}
        with mock.patch.object(self.tool, "mount_sources", return_value=[]), \
             mock.patch.object(self.tool, "pg_system_identifier", return_value="11"), \
             mock.patch.object(self.tool, "redis_run_identifier", return_value="f" * 40), \
             mock.patch.object(self.tool, "validate_target_runtime", return_value=target), \
             mock.patch.object(
                 self.tool,
                 "container_id",
                 side_effect=("d" * 64, "e" * 64, "f" * 64),
             ):
            legacy, actual_target = self.tool.verify_stopped_legacy(
                names, identities, runner=runner
            )
        self.assertEqual(legacy["postgres"], "11")
        self.assertEqual(actual_target, target)

    def test_verify_stopped_rejects_rebound_name_before_target_validation(self):
        names = self.tool.LegacyNames("legacy-app", "legacy-pg", "legacy-redis")
        identities = self.tool.LegacyContainerIds("a" * 64, "b" * 64, "c" * 64)

        def runner(argv, **_kwargs):
            return types.SimpleNamespace(
                returncode=0,
                stdout=("d" * 64 + "|false\n").encode(),
            )

        with self.assertRaisesRegex(self.tool.CanaryError, "identity or runtime state changed"):
            self.tool.verify_stopped_legacy(names, identities, runner=runner)


if __name__ == "__main__":
    unittest.main()
