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
import time
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

    def switch(self, stage, *, timeout, deadline=None, clock=None):
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
        self.traffic_targets = {
            name: f"{index:x}" * 64
            for index, name in enumerate(tool.TARGET_NAMES, start=1)
        }
        self.nonce_targets = {tool.TARGET_NONCE_REDIS: "f" * 64}

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
            reference = argv[-1]
            template = argv[3]
            identity_to_name = {
                identity: name for name, identity in self.identities.items()
            }
            name = identity_to_name.get(reference, reference)
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
                    f"{identity}|/{name}|{running}|{health}"
                    if "State.Health" in template
                    else identity
                )
                return self.tool.CommandResult(0, output.encode())
            all_targets = {**self.traffic_targets, **self.nonce_targets}
            target_identity_to_name = {
                identity: target_name for target_name, identity in all_targets.items()
            }
            target_name = target_identity_to_name.get(reference, reference)
            identity = all_targets.get(target_name)
            if identity is None:
                return self.tool.CommandResult(1)
            output = (
                f"{identity}|/{target_name}|true|healthy".encode()
                if "State.Health" in template
                else identity.encode()
            )
            return self.tool.CommandResult(0, output)
        if argv[:2] == ["docker", "start"]:
            reference = argv[-1]
            name = {
                identity: name for name, identity in self.identities.items()
            }[reference]
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
        if "down" in argv and str(self.tool.NONCE_COMPOSE_FILE) in argv:
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
        return types.SimpleNamespace(
            env_file=pathlib.Path("/private/env"),
            verify_url="https://gateway.example.test/v1/responses",
            model="model-test",
            approved_hostname="gateway.example.test",
        )

    def migration_private_values(self):
        return {
            "SUB2API_SOURCE_DATABASE_URL": "postgresql://source-secret",
            "SUB2API_TARGET_DATABASE_URL": "postgresql://target-secret",
            "SUB2API_DATABASE_URL": "postgresql://target-secret",
            "SUB2API_APP_DATABASE_PASSWORD": "app-role-secret",
            "SUB2API_SYNC_DATABASE_PASSWORD": "sync-role-secret",
            "SUB2API_DATA_ROOT": "/mnt/data/sub2api-gate",
            "SUB2API_SOURCE_REDIS_URL": "redis://source",
            "SUB2API_SOURCE_REDIS_PASSWORD": "source-redis-secret",
            "SUB2API_TARGET_REDIS_URL": "redis://target",
            "SUB2API_TARGET_REDIS_PASSWORD": "target-redis-secret",
            "SUB2API_TARGET_REDIS_USERNAME": "sub2api_migration",
        }

    def test_default_check_is_offline_and_side_effect_free(self):
        runner = NeverRunner()
        stdout = io.StringIO()
        result = self.tool.main(["check"], runner=runner, stdout=stdout)
        self.assertEqual(result, 0)
        self.assertFalse(runner.calls)
        self.assertIn("no private file was read", stdout.getvalue())
        self.assertIn("no service or data changed", stdout.getvalue())

    def test_timed_out_command_kills_its_entire_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            child_pid_path = pathlib.Path(directory) / "child.pid"
            child_program = (
                "import signal,time;"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
                "time.sleep(60)"
            )
            parent_program = (
                "import pathlib,subprocess,sys,time;"
                "child=subprocess.Popen([sys.executable,'-c',sys.argv[2]]);"
                "pathlib.Path(sys.argv[1]).write_text(str(child.pid),encoding='ascii');"
                "time.sleep(60)"
            )
            runner = self.tool.CommandRunner()
            with self.assertRaisesRegex(
                self.tool.WindowExpired,
                "command deadline exceeded",
            ):
                runner(
                    [
                        sys.executable,
                        "-c",
                        parent_program,
                        str(child_pid_path),
                        child_program,
                    ],
                    timeout=1,
                )
            child_pid = int(child_pid_path.read_text(encoding="ascii"))

            def child_is_running():
                try:
                    state = pathlib.Path(f"/proc/{child_pid}/stat").read_text(
                        encoding="ascii"
                    ).split()[2]
                except (FileNotFoundError, ProcessLookupError):
                    return False
                return state != "Z"

            for _attempt in range(40):
                if not child_is_running():
                    break
                time.sleep(0.05)
            self.assertFalse(child_is_running())

    def test_interactive_command_inherits_tty_in_a_foreground_process_group(self):
        process = mock.Mock()
        process.communicate.return_value = (None, None)
        process.returncode = 0
        process.pid = 12345
        runner = self.tool.CommandRunner()
        with mock.patch.object(
            self.tool.subprocess,
            "Popen",
            return_value=process,
        ) as popen, mock.patch.object(
            runner,
            "_interactive_foreground",
            return_value=self.tool.contextlib.nullcontext(),
        ), mock.patch.object(
            runner,
            "_process_group_exists",
            return_value=False,
        ):
            result = runner(
                ["private-interactive-helper"],
                timeout=5,
                interactive=True,
            )
        self.assertEqual(result.returncode, 0)
        arguments = popen.call_args.kwargs
        self.assertIsNone(arguments["stdin"])
        self.assertIsNone(arguments["stdout"])
        self.assertIsNone(arguments["stderr"])
        self.assertFalse(arguments["start_new_session"])
        self.assertIs(arguments["preexec_fn"], os.setpgrp)

    def test_interrupted_command_reaps_its_process_group_before_propagating(self):
        process = mock.Mock()
        process.communicate.side_effect = self.tool.TerminationRequested("stop")
        process.pid = 12345
        with mock.patch.object(
            self.tool.subprocess,
            "Popen",
            return_value=process,
        ), mock.patch.object(
            self.tool.CommandRunner,
            "_terminate_process_group",
        ) as terminate:
            with self.assertRaises(self.tool.TerminationRequested):
                self.tool.CommandRunner()(["long-migration"], timeout=30)
        terminate.assert_called_once_with(process)

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

    def test_writer_stop_deadline_ends_only_after_canary_traffic_is_healthy(self):
        clock = mock.Mock(return_value=100.0)
        canary_deadlines = []
        canary_timeouts = []
        health_deadlines = []
        health_timeouts = []
        nginx_deadlines = []

        class DeadlineNginx:
            def switch(_self, stage, *, timeout, deadline=None, clock=None):
                self.assertEqual(stage, "canary")
                self.assertGreater(timeout, 0)
                self.assertEqual(deadline, controller.writer_stop_deadline)
                self.assertIs(clock, controller.clock)
                nginx_deadlines.append(controller.writer_stop_deadline)

        def runner(argv, **kwargs):
            if "run-v1-responses-canary.py" in " ".join(str(value) for value in argv):
                canary_deadlines.append(controller.writer_stop_deadline)
                canary_timeouts.append(kwargs["timeout"])
            return self.tool.CommandResult(0)

        def health(_port, _path, **kwargs):
            health_deadlines.append(controller.writer_stop_deadline)
            health_timeouts.append(kwargs["timeout"])

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={},
            runner=runner,
            nginx=DeadlineNginx(),
            health_probe=health,
            clock=clock,
        )
        controller.deadline = 280.0
        controller.sync_fragment = "/etc/systemd/system/sub2api-sync.service"
        controller.unit_active = lambda: False
        controller.unit_metadata = lambda: controller.sync_fragment
        controller.require_legacy = lambda *_args, **_kwargs: None
        controller.require_all_targets = lambda **_kwargs: None

        controller.stop_writers()
        self.assertEqual(controller.writer_stop_deadline, 160.0)
        controller.switch_and_canary()
        self.assertEqual(health_deadlines, [160.0, 160.0])
        self.assertEqual(nginx_deadlines, [160.0])
        self.assertEqual(canary_deadlines, [160.0])
        self.assertEqual(canary_timeouts, [60])
        self.assertEqual(health_timeouts, [5, 5])
        self.assertIsNone(controller.writer_stop_deadline)

        unbounded = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={},
            runner=NeverRunner(),
            nginx=StubNginx([]),
            health_probe=lambda *_args, **_kwargs: None,
            clock=clock,
        )
        unbounded.deadline = 280.0
        with self.assertRaisesRegex(self.tool.CutoverError, "writer-stop deadline"):
            unbounded.switch_and_canary()

        near_deadline_timeouts = []
        near_deadline = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={},
            runner=NeverRunner(),
            nginx=StubNginx([]),
            health_probe=lambda _port, _path, **kwargs: near_deadline_timeouts.append(
                kwargs["timeout"]
            ),
            clock=lambda: 158.0,
        )
        near_deadline.deadline = 280.0
        near_deadline.writer_stop_deadline = 160.0
        near_deadline.probe_health(8081, "/health")
        self.assertEqual(near_deadline_timeouts, [2])

    def test_legacy_stop_and_start_commands_use_full_immutable_ids(self):
        services = self.services()
        calls = []
        running = {service.identity: True for service in services.containers()}

        def runner(argv, **_kwargs):
            command = [str(value) for value in argv]
            calls.append(command)
            if command[:3] == ["/usr/bin/systemctl", "stop", self.tool.SYNC_UNIT]:
                return self.tool.CommandResult(0)
            if command[:3] == ["/usr/bin/systemctl", "is-active", "--quiet"]:
                return self.tool.CommandResult(3)
            if command[:3] == ["/usr/bin/systemctl", "show", self.tool.SYNC_UNIT]:
                return self.tool.CommandResult(
                    0,
                    (
                        "Id=sub2api-sync.service\n"
                        "LoadState=loaded\n"
                        "FragmentPath=/etc/systemd/system/sub2api-sync.service\n"
                    ).encode(),
                )
            if command[:2] == ["docker", "stop"]:
                self.assertEqual(command[-1], services.app.identity)
                running[services.app.identity] = False
                return self.tool.CommandResult(0)
            if command[:2] == ["docker", "start"]:
                self.assertEqual(command[-1], services.app.identity)
                running[services.app.identity] = True
                return self.tool.CommandResult(0)
            if command[:2] == ["docker", "inspect"]:
                identity = command[-1]
                service = next(
                    item for item in services.containers() if item.identity == identity
                )
                state = "true" if running[identity] else "false"
                return self.tool.CommandResult(
                    0,
                    f"{identity}|/{service.name}|{state}|healthy\n".encode(),
                )
            raise AssertionError(command)

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=services,
            private_values={},
            runner=runner,
            nginx=StubNginx([]),
            clock=lambda: 100.0,
        )
        controller.deadline = 280.0
        controller.sync_fragment = "/etc/systemd/system/sub2api-sync.service"
        controller.stop_writers()
        controller.ensure_legacy_running(services.app)

        self.assertNotIn(
            ["docker", "stop", "--time", "10", services.app.name],
            calls,
        )
        self.assertNotIn(["docker", "start", services.app.name], calls)

    def test_target_ids_are_rechecked_before_and_after_nginx_switch(self):
        target_ids = {
            name: f"{index:x}" * 64
            for index, name in enumerate(self.tool.TARGET_NAMES, start=4)
        }
        names_by_id = {identity: name for name, identity in target_ids.items()}
        canary_calls = []
        rebound = {"active": False}

        def runner(argv, **_kwargs):
            command = [str(value) for value in argv]
            if command[:2] == ["docker", "inspect"]:
                identity = command[-1]
                name = names_by_id[identity]
                actual_name = (
                    "unexpected-replacement"
                    if rebound["active"] and name == self.tool.TARGET_APP
                    else name
                )
                return self.tool.CommandResult(
                    0,
                    f"{identity}|/{actual_name}|true|healthy\n".encode(),
                )
            if "run-v1-responses-canary.py" in " ".join(command):
                canary_calls.append(command)
                return self.tool.CommandResult(0)
            raise AssertionError(command)

        class RebindingNginx:
            def switch(_self, stage, **_kwargs):
                self.assertEqual(stage, "canary")
                rebound["active"] = True

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={},
            runner=runner,
            nginx=RebindingNginx(),
            health_probe=lambda *_args, **_kwargs: None,
            clock=lambda: 100.0,
        )
        controller.deadline = 280.0
        controller.writer_stop_deadline = 160.0
        controller.target_identities.update(target_ids)

        with self.assertRaisesRegex(
            self.tool.CutoverError,
            "container identity or runtime state changed",
        ):
            controller.switch_and_canary()
        self.assertEqual(canary_calls, [])
        self.assertEqual(controller.writer_stop_deadline, 160.0)

    def test_preflight_rollback_readiness_requires_healthy_data_services(self):
        events = []
        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={},
            runner=NeverRunner(),
            nginx=StubNginx(events),
            health_probe=lambda port, path, **_kwargs: events.append(
                f"health:{port}{path}"
            ),
        )
        controller.sync_fragment = "/etc/systemd/system/sub2api-sync.service"
        controller.sync_fragment_sha256 = "d" * 64
        controller.unit_metadata = lambda: controller.sync_fragment
        controller.unit_active = lambda: True
        controller.require_legacy = lambda service, **kwargs: events.append(
            (service.name, kwargs)
        )
        with mock.patch.object(
            self.tool,
            "stable_unit_sha256",
            return_value=controller.sync_fragment_sha256,
        ):
            controller.verify_rollback_ready()

        self.assertIn(
            (self.services().postgres.name, {"running": True, "healthy": True}),
            events,
        )
        self.assertIn(
            (self.services().redis.name, {"running": True, "healthy": True}),
            events,
        )
        self.assertLess(events.index("health:8080/health"), events.index("nginx-require:stable"))
        source = TOOL_PATH.read_text(encoding="utf-8")
        preflight = source[source.index("    def preflight(self):"):source.index(
            "    def stop_writers(self):"
        )]
        self.assertLess(
            preflight.index("self.wait_target_healthy(TARGET_NONCE_REDIS)"),
            preflight.index("self.verify_rollback_ready()"),
        )

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

    def test_private_configuration_paths_must_be_absolute(self):
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
            "--legacy-app-path", "/legacy/app",
            "--legacy-postgres-path", "/legacy/postgres",
            "--legacy-redis-path", "/legacy/redis",
            "--legacy-nginx-log-path", "/var/log/nginx",
            "--verify-url", "https://gateway.example.test/v1/responses",
            "--model", "model-test",
            "--approved-hostname", "gateway.example.test",
        ]
        for option in ("--env-file", "--wrangler-config"):
            arguments = list(base)
            arguments[arguments.index(option) + 1] = "relative/private-config"
            with self.subTest(option=option), self.assertRaisesRegex(
                self.tool.UsageError,
                "absolute",
            ):
                self.tool.parse_arguments(arguments)

        recovery = [
            "--recover",
            "--env-file", "relative/private.env",
            "--legacy-sub2api-container", "legacy-app",
            "--legacy-sub2api-id", "a" * 64,
            "--legacy-postgres-container", "legacy-postgres",
            "--legacy-postgres-id", "b" * 64,
            "--legacy-redis-container", "legacy-redis",
            "--legacy-redis-id", "c" * 64,
        ]
        with self.assertRaisesRegex(self.tool.UsageError, "absolute"):
            self.tool.parse_arguments(recovery)

    def test_apply_rejects_unsafe_canary_arguments_offline(self):
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
            "--legacy-app-path", "/legacy/app",
            "--legacy-postgres-path", "/legacy/postgres",
            "--legacy-redis-path", "/legacy/redis",
            "--legacy-nginx-log-path", "/var/log/nginx",
            "--verify-url", "https://gateway.example.test/v1/responses",
            "--model", "model-test",
            "--approved-hostname", "gateway.example.test",
        ]
        invalid_values = (
            ("--verify-url", "http://127.0.0.1:8081/v1/responses"),
            ("--verify-url", "https://other.example.test/v1/responses"),
            ("--verify-url", "https://gateway.example.test/v1/chat/completions"),
            ("--model", "<invalid-model>"),
            ("--approved-hostname", "Gateway.example.test"),
        )
        for option, value in invalid_values:
            arguments = list(base)
            arguments[arguments.index(option) + 1] = value
            with self.subTest(option=option, value=value), self.assertRaisesRegex(
                self.tool.UsageError,
                "canary",
            ):
                self.tool.parse_arguments(arguments)

    def test_controller_preflight_revalidates_canary_before_local_commands(self):
        options = self.options()
        options.verify_url = "https://other.example.test/v1/responses"
        runner = NeverRunner()
        controller = self.tool.MaintenanceController(
            options=options,
            services=self.services(),
            private_values={},
            runner=runner,
            nginx=StubNginx([]),
        )
        with self.assertRaisesRegex(self.tool.UsageError, "canary"):
            controller.preflight()
        self.assertEqual(runner.calls, [])

    def test_persistent_recovery_state_is_private_atomic_and_contains_no_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve() / "safe-backup"
            root.mkdir(mode=0o700)
            state_path = root / "maintenance-cutover-state.json"
            document = {
            "version": 3,
                "phase": "migrating",
                "git_head": "a" * 40,
                "env_file": "/private/runtime.env",
                "env_file_identity": {
                    "device": 1,
                    "inode": 2,
                    "mode": stat.S_IFREG | 0o600,
                    "links": 1,
                    "uid": os.geteuid(),
                    "gid": os.getegid(),
                    "size": 4096,
                    "modified_ns": 3,
                    "changed_ns": 4,
                },
                "sync_fragment": "/etc/systemd/system/sub2api-sync.service",
                "sync_fragment_sha256": "d" * 64,
                "legacy": {
                    "app": {"name": "legacy-app", "identity": "a" * 64},
                    "postgres": {"name": "legacy-postgres", "identity": "b" * 64},
                    "redis": {"name": "legacy-redis", "identity": "c" * 64},
                },
                "targets": {
                    "sub2api-traffic-canary": "1" * 64,
                    "sub2api-traffic-canary-postgres": "2" * 64,
                    "sub2api-traffic-canary-redis": "3" * 64,
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
                invalid_documents = []
                legacy_version = dict(document, version=2)
                invalid_documents.append(legacy_version)
                invalid_documents.append(
                    dict(document, sync_fragment_sha256=123)
                )
                boolean_identity = dict(document["env_file_identity"], device=True)
                invalid_documents.append(
                    dict(document, env_file_identity=boolean_identity)
                )
                aliased_targets = dict(document["targets"])
                aliased_targets["sub2api-traffic-canary"] = "a" * 64
                invalid_documents.append(dict(document, targets=aliased_targets))
                for invalid in invalid_documents:
                    with self.subTest(invalid=invalid), self.assertRaises(
                        self.tool.CutoverError
                    ):
                        self.tool.write_cutover_state(
                            state_path,
                            invalid,
                            expected_uid=os.geteuid(),
                        )

    def test_safe_export_manifest_binds_artifacts_policy_git_and_source_cluster(self):
        with tempfile.TemporaryDirectory() as directory:
            backup_root = pathlib.Path(directory).resolve() / "safe-backup"
            export = backup_root / "export-20260722T000000Z"
            backup_root.mkdir(mode=0o700)
            export.mkdir(mode=0o700)
            artifacts = {}
            self.assertIn("schema_fingerprint.sha256", self.tool.SAFE_EXPORT_ARTIFACTS)
            self.assertNotIn("schema.sql", self.tool.SAFE_EXPORT_ARTIFACTS)
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
                "version": 3,
                "completed_at": completed_at,
                "git_head": "a" * 40,
                "source_postgres_identity": {
                    "system_identifier": "1234567890123456789",
                    "database_oid": "16384",
                    "database_name_hex": "73756232617069",
                },
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
                self.assertEqual(
                    identity,
                    ("1234567890123456789", "16384", "73756232617069"),
                )
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
                "HOME": "/tmp/attacker-home",
                "LANG": "attacker-locale",
                "LC_ALL": "attacker-locale",
                "TZ": "attacker-timezone",
                "GIT_CONFIG_GLOBAL": "/tmp/attacker-gitconfig",
            },
            clear=False,
        ):
            environment = self.tool.minimal_environment()
        self.assertNotIn("CLOUDFLARE_API_TOKEN", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertNotIn("SUB2API_SOURCE_DATABASE_URL", environment)
        self.assertEqual(environment["DOCKER_HOST"], "unix:///var/run/docker.sock")
        self.assertEqual(environment["HOME"], "/root")
        self.assertEqual(environment["LANG"], "C.UTF-8")
        self.assertEqual(environment["LC_ALL"], "C.UTF-8")
        self.assertEqual(environment["TZ"], "UTC")
        self.assertEqual(environment["PYTHONNOUSERSITE"], "1")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(environment["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(environment["GIT_CONFIG_SYSTEM"], "/dev/null")
        self.assertEqual(environment["GIT_CONFIG_COUNT"], "0")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")

    def test_operator_authentication_precedes_private_environment_read(self):
        source = TOOL_PATH.read_text(encoding="utf-8")
        main_start = source.index("def main(\n")
        main_source = source[main_start:]
        self.assertLess(
            main_source.index("        authenticate()"),
            main_source.index(
                "private_env.read_private_environment_with_identity(options.env_file)"
            ),
        )
        self.assertNotIn(
            "env_file_identity = private_environment_identity(\n                options.env_file",
            main_source,
        )

    def test_privileged_python_helpers_use_the_fixed_isolated_interpreter(self):
        source = TOOL_PATH.read_text(encoding="utf-8")
        self.assertTrue(source.startswith("#!/usr/bin/python3 -I\n"))
        self.assertEqual(
            self.tool.privileged_python_command("/tmp/helper.py", "--apply"),
            ["/usr/bin/python3", "-I", "/tmp/helper.py", "--apply"],
        )
        self.assertNotIn("[str(PYTHON_BINARY)", source)

    def test_apply_context_gate_precedes_argument_parsing(self):
        with mock.patch.object(
            self.tool,
            "require_production_apply_context",
            side_effect=self.tool.CutoverError("blocked"),
        ) as context_gate, mock.patch.object(
            self.tool,
            "parse_arguments",
            side_effect=AssertionError("arguments must not be parsed first"),
        ):
            self.assertEqual(
                self.tool.main(["--apply"], stderr=io.StringIO()),
                1,
            )
        context_gate.assert_called_once()

    def test_trusted_release_tree_includes_filesystem_root(self):
        with mock.patch.object(
            self.tool, "TRUSTED_RELEASE_ROOT", ROOT
        ), mock.patch.object(self.tool, "_require_trusted_release_path") as path_gate:
            self.tool.require_trusted_release_tree(ROOT, source_path=TOOL_PATH)
        self.assertIn(
            mock.call(self.tool.TRUSTED_FILESYSTEM_ROOT, expects_directory=True),
            path_gate.call_args_list,
        )

    def test_safe_export_policy_binds_totp_and_role_migration_controls(self):
        policy = set(self.tool.SAFE_EXPORT_POLICY_FILES)
        self.assertTrue(
            {
                "deploy/locked-postgres-stream.py",
                "deploy/verify-migration-totp.py",
                "deploy/prepare-app-role.sh",
                "deploy/prepare-sync-role.sh",
                "deploy/run-database-migration.sh",
                "migrations/000_prepare_app_role.sql",
                "migrations/000_prepare_sync_role.sql",
                "migrations/003_sync_least_privilege.sql",
                "migrations/005_app_least_privilege.sql",
            }.issubset(policy)
        )

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

    def test_migration_prepares_sync_boundary_before_app_role(self):
        calls = []

        def runner(argv, **kwargs):
            command = [str(value) for value in argv]
            calls.append((command, dict(kwargs["environment"])))
            if command[:3] == ["docker", "inspect", "--format"]:
                return self.tool.CommandResult(0, b"true|healthy\n")
            return self.tool.CommandResult(0)

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values=self.migration_private_values(),
            runner=runner,
            nginx=StubNginx([]),
        )
        controller.target_identities[self.tool.TARGET_POSTGRES] = "d" * 64
        controller.target_identities[self.tool.TARGET_REDIS] = "e" * 64
        controller.require_target = lambda *_args, **_kwargs: None
        controller.inspect_container_runtime = lambda *_args, **_kwargs: None
        controller.persist_recovery_state = lambda _phase: None

        def wait_target(name):
            if name == self.tool.TARGET_POSTGRES:
                controller.target_identities[name] = "f" * 64

        controller.wait_target_healthy = wait_target

        controller.migrate()

        commands = [command for command, _environment in calls]
        postgres_migration = next(
            index
            for index, command in enumerate(commands)
            if command[:2] == [
                str(ROOT / "deploy" / "migrate-sanitized-postgres.sh"),
                "--apply",
            ]
        )
        self.assertEqual(
            commands[postgres_migration][2:],
            [
                "--env-file", "/private/env",
                "--source-app-container", "legacy-app",
                "--source-app-id", "a" * 64,
                "--source-postgres-container", "legacy-postgres",
                "--source-postgres-id", "b" * 64,
            ],
        )
        postgres_environment = calls[postgres_migration][1]
        self.assertNotIn("SUB2API_SOURCE_DATABASE_URL", postgres_environment)
        self.assertNotIn("SUB2API_TARGET_DATABASE_URL", postgres_environment)
        prepare_sync = next(
            index
            for index, command in enumerate(commands)
            if command[:2] == [
                str(ROOT / "deploy" / "prepare-sync-role.sh"),
                "--apply",
            ]
        )
        apply_sync_schema = next(
            index
            for index, command in enumerate(commands)
            if command[:3] == [
                str(ROOT / "deploy" / "run-database-migration.sh"),
                "sync-role",
                "--apply",
            ]
        )
        prepare_app = next(
            index
            for index, command in enumerate(commands)
            if command[:2] == [
                str(ROOT / "deploy" / "prepare-app-role.sh"),
                "--apply",
            ]
        )
        self.assertLess(prepare_sync, apply_sync_schema)
        self.assertLess(apply_sync_schema, prepare_app)

        sync_environment = calls[prepare_sync][1]
        self.assertEqual(
            commands[prepare_sync][2:],
            ["--env-file", "/private/env"],
        )
        self.assertNotIn("SUB2API_SYNC_DATABASE_PASSWORD", sync_environment)
        self.assertNotIn("SUB2API_DATABASE_URL", sync_environment)
        self.assertNotIn("SUB2API_APP_DATABASE_PASSWORD", sync_environment)

        schema_environment = calls[apply_sync_schema][1]
        self.assertEqual(
            commands[apply_sync_schema][3:],
            ["--env-file", "/private/env"],
        )
        self.assertNotIn("SUB2API_DATABASE_URL", schema_environment)
        self.assertNotIn("SUB2API_SYNC_DATABASE_PASSWORD", schema_environment)
        self.assertEqual(
            commands[prepare_app][2:],
            ["--env-file", "/private/env"],
        )
        self.assertNotIn("SUB2API_DATABASE_URL", calls[prepare_app][1])
        self.assertNotIn("SUB2API_APP_DATABASE_PASSWORD", calls[prepare_app][1])

    def test_sync_role_failure_after_writer_stop_uses_verified_rollback(self):
        events = []

        def runner(argv, **_kwargs):
            command = [str(value) for value in argv]
            events.append(pathlib.Path(command[0]).name)
            if command[:2] == [
                str(ROOT / "deploy" / "prepare-sync-role.sh"),
                "--apply",
            ]:
                raise self.tool.CutoverError("sync role preparation failed")
            return self.tool.CommandResult(0)

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values=self.migration_private_values(),
            runner=runner,
            nginx=StubNginx(events),
            clock=lambda: 100.0,
        )

        controller.preflight = lambda: events.append("preflight")

        def stop_writers():
            events.append("writers-stopped")
            controller.writers_stopped = True

        controller.stop_writers = stop_writers
        controller.start_target = lambda: events.append("unexpected-target-start")
        controller.switch_and_canary = lambda: events.append("unexpected-nginx-switch")
        controller.rollback = lambda: events.append("rollback") or []

        with self.assertRaisesRegex(
            self.tool.CutoverError,
            "cutover_phase_failed; rollback_verified",
        ):
            controller.execute()

        self.assertIn("prepare-sync-role.sh", events)
        self.assertIn("rollback", events)
        self.assertNotIn("unexpected-target-start", events)
        self.assertNotIn("unexpected-nginx-switch", events)

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
                "PGPORT": "15432",
                "PGDATABASE": "sub2api",
            }
        )

        def runner(argv, **kwargs):
            calls.append((list(argv), dict(kwargs["environment"])))
            if argv[:3] == [
                str(self.tool.PYTHON_BINARY),
                "-I",
                str(ROOT / "deploy" / "source-postgres-exec.py"),
            ]:
                return self.tool.CommandResult(
                    0,
                    b"1234567890123456789|16384|73756232617069\n",
                )
            if argv[:2] == ["docker", "inspect"]:
                return self.tool.CommandResult(
                    0,
                    json.dumps({
                        "Networks": {"data": {"IPAddress": "172.18.0.3"}},
                        "Ports": {
                            "5432/tcp": [
                                {"HostIp": "127.0.0.1", "HostPort": "15432"}
                            ]
                        },
                    }).encode(),
                )
            return self.tool.CommandResult(
                0,
                b"1234567890123456789|16384|73756232617069\n",
            )

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={
                "SUB2API_SOURCE_DATABASE_URL": "must-not-enter-child-environment",
                "SUB2API_TARGET_DATABASE_URL": "target-secret-url",
            },
            runner=runner,
            nginx=StubNginx([]),
        )
        with mock.patch.object(self.tool, "load_module", return_value=pg_helper):
            identities = controller.verify_database_connections()
        self.assertEqual(
            identities["SUB2API_SOURCE_DATABASE_URL"],
            ("1234567890123456789", "16384", "73756232617069"),
        )
        source_calls = [
            call for call in calls
            if call[0][:3] == [
                str(self.tool.PYTHON_BINARY),
                "-I",
                str(ROOT / "deploy" / "source-postgres-exec.py"),
            ]
        ]
        self.assertEqual(len(source_calls), 1)
        self.assertEqual(
            source_calls[0][0][3:],
            [
                "--env-file", "/private/env",
                "--source-app-container", "legacy-app",
                "--source-app-id", "a" * 64,
                "--source-postgres-container", "legacy-postgres",
                "--source-postgres-id", "b" * 64,
                "--source-app-state", "running",
                "identity",
            ],
        )
        self.assertNotIn("SUB2API_SOURCE_DATABASE_URL", source_calls[0][1])
        target_calls = [
            call for call in calls
            if call[0][:3] == [
                str(self.tool.PYTHON_BINARY),
                "-I",
                str(ROOT / "deploy" / "pg-env-exec.py"),
            ]
        ]
        self.assertEqual(len(target_calls), 1)
        self.assertIn("SUB2API_TARGET_DATABASE_URL", target_calls[0][1])

    def test_target_postgres_network_metadata_fails_closed(self):
        pg_helper = types.SimpleNamespace(
            libpq_environment=lambda _environment, _name: {
                "PGHOST": "127.0.0.1",
                "PGPORT": "15432",
                "PGDATABASE": "sub2api",
            }
        )

        def runner(argv, **_kwargs):
            if argv[:3] == [
                str(self.tool.PYTHON_BINARY),
                "-I",
                str(ROOT / "deploy" / "source-postgres-exec.py"),
            ]:
                return self.tool.CommandResult(
                    0,
                    b"1234567890123456789|16384|73756232617069\n",
                )
            if argv[:2] == ["docker", "inspect"]:
                return self.tool.CommandResult(0, b"[]\n")
            raise AssertionError(argv)

        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={"SUB2API_TARGET_DATABASE_URL": "target-secret-url"},
            runner=runner,
            nginx=StubNginx([]),
        )
        with mock.patch.object(self.tool, "load_module", return_value=pg_helper), \
             self.assertRaisesRegex(self.tool.CutoverError, "network metadata"):
            controller.verify_database_connections()

    def test_safe_export_source_cluster_must_match_live_source_before_cutover(self):
        controller = self.tool.MaintenanceController(
            options=self.options(),
            services=self.services(),
            private_values={},
            runner=NeverRunner(),
            nginx=StubNginx([]),
        )
        controller.export_source_database_identity = (
            "1234567890123456789",
            "16384",
            "73756232617069",
        )
        controller.require_export_source_identity({
            "SUB2API_SOURCE_DATABASE_URL": (
                "1234567890123456789",
                "16384",
                "73756232617069",
            )
        })
        for mismatched_identity in (
            ("9876543210987654321", "16384", "73756232617069"),
            ("1234567890123456789", "16385", "73756232617069"),
            ("1234567890123456789", "16384", "6f74686572"),
        ):
            with self.subTest(identity=mismatched_identity), self.assertRaisesRegex(
                self.tool.CutoverError, "different source PostgreSQL database"
            ):
                controller.require_export_source_identity({
                    "SUB2API_SOURCE_DATABASE_URL": mismatched_identity
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

    def test_nginx_switch_recomputes_absolute_deadline_before_reload(self):
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
            times = iter((0.0, 0.0, 6.0))

            def runner(argv, **_kwargs):
                calls.append(list(argv))
                return self.tool.CommandResult(0)

            nginx = self.tool.NginxUpstream(
                paths,
                runner,
                production=False,
                initial_stage=None,
            )
            with self.assertRaisesRegex(
                self.tool.WindowExpired,
                "writer-stop deadline",
            ):
                nginx.switch(
                    "canary",
                    timeout=10,
                    deadline=5.0,
                    clock=lambda: next(times),
                )
            self.assertEqual(calls, [["/usr/sbin/nginx", "-t"]])

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
            for name, source in (
                ("cloudflare-real-ip.conf", ROOT / "nginx/snippets/cloudflare-real-ip.conf"),
                ("cloudflare-only.conf", ROOT / "nginx/snippets/cloudflare-only.conf"),
                ("sub2api-sync-location.conf", ROOT / "nginx/sub2api-sync-location.conf"),
            ):
                target = snippets / name
                target.write_bytes(source.read_bytes())
                target.chmod(0o644)
            aop = snippets / "sub2api-aop-active.conf"
            aop.write_text("# test fixture\n", encoding="ascii")
            aop.chmod(0o644)
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

        def health(port, path, **_kwargs):
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
        controller.target_identities.update(runner.traffic_targets)
        controller.writer_stop_deadline = controller.clock() - 1
        errors = controller.rollback()

        self.assertEqual(errors, [])
        self.assertIsNone(controller.writer_stop_deadline)
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

    def test_rollback_restores_legacy_before_enforcing_cleanup_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            private = root / "private"
            private.mkdir(mode=0o700)
            env_file = private / "sub2api.env"
            env_file.write_text("VALUE=first\n", encoding="ascii")
            env_file.chmod(0o600)
            unit = root / self.tool.SYNC_UNIT
            unit.write_text("[Service]\nExecStart=/bin/true\n", encoding="ascii")
            unit.chmod(0o644)
            expected_uid = os.geteuid()
            expected_gid = os.getegid()

            def controller():
                events = []
                services = self.services()
                runner = RollbackRunner(self.tool, services, events)
                instance = self.tool.MaintenanceController(
                    options=types.SimpleNamespace(env_file=env_file),
                    services=services,
                    private_values={},
                    runner=runner,
                    nginx=StubNginx(events),
                    health_probe=lambda port, path, **_kwargs: events.append(
                        f"health:{port}{path}"
                    ),
                    sleeper=lambda _seconds: None,
                    target_resetter=lambda: events.append("reset:target"),
                    private_env_identity=self.tool.private_environment_identity(
                        env_file,
                        expected_uid=expected_uid,
                        expected_gid=expected_gid,
                    ),
                    recovery_state_expected_uid=expected_uid,
                    recovery_state_expected_gid=expected_gid,
                )
                instance.sync_fragment = str(unit)
                instance.sync_fragment_sha256 = self.tool.stable_unit_sha256(
                    unit,
                    expected_uid=expected_uid,
                )
                instance.unit_metadata = lambda: str(unit)
                instance.target_started = True
                instance.nonce_target_started = True
                instance.target_identities.update(runner.traffic_targets)
                return instance, events

            changed_env, env_events = controller()
            env_file.write_text("VALUE=changed-value\n", encoding="ascii")
            self.assertEqual(changed_env.rollback(), ["recovery_identity"])
            self.assertIn("nginx:stable", env_events)
            self.assertNotIn("down:traffic", env_events)
            self.assertNotIn("reset:target", env_events)

            changed_unit, unit_events = controller()
            unit.write_text("[Service]\nExecStart=/bin/false\n", encoding="ascii")
            self.assertEqual(
                changed_unit.rollback(),
                ["legacy_sync_health", "recovery_identity"],
            )
            self.assertIn("nginx:stable", unit_events)
            self.assertNotIn("down:traffic", unit_events)
            self.assertNotIn("reset:target", unit_events)

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
            health_probe=lambda *_args, **_kwargs: None,
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
            health_probe=lambda *_args, **_kwargs: None,
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

    def test_target_reset_rejects_mountinfo_boundaries_and_rechecks_before_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            target = root / "target"
            nested = target / "nested"
            target.mkdir(mode=0o700)
            nested.mkdir(mode=0o700)
            payload = nested / "data"
            payload.write_bytes(b"preserve")
            mountinfo = root / "mountinfo"
            mountinfo.write_text(
                f"36 25 0:32 / {nested} rw,relatime - ext4 /dev/root rw\n",
                encoding="ascii",
            )
            reader = lambda: self.tool.read_mountpoints(mountinfo)
            with self.assertRaisesRegex(self.tool.CutoverError, "mount boundary"):
                self.tool.clear_private_directory(
                    target,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                    exact_path=target,
                    mountpoints_reader=reader,
                )
            self.assertEqual(payload.read_bytes(), b"preserve")

            calls = 0

            def changed_mount_table():
                nonlocal calls
                calls += 1
                return () if calls == 1 else (nested,)

            with self.assertRaisesRegex(self.tool.CutoverError, "mount boundary"):
                self.tool.clear_private_directory(
                    target,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                    exact_path=target,
                    mountpoints_reader=changed_mount_table,
                )
            self.assertEqual(calls, 2)
            self.assertEqual(payload.read_bytes(), b"preserve")

    @unittest.skipUnless(os.geteuid() == 0, "real bind-mount test requires root")
    def test_target_reset_rejects_a_real_same_device_bind_mount(self):
        subprocess = __import__("subprocess")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory).resolve()
            source = root / "source"
            target = root / "target"
            nested = target / "nested"
            source.mkdir(mode=0o700)
            target.mkdir(mode=0o700)
            nested.mkdir(mode=0o700)
            payload = source / "data"
            payload.write_bytes(b"preserve")
            result = subprocess.run(
                ["mount", "--bind", str(source), str(nested)],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if result.returncode:
                self.skipTest("root test environment cannot create bind mounts")
            try:
                self.assertEqual(source.stat().st_dev, nested.stat().st_dev)
                with self.assertRaisesRegex(
                    self.tool.CutoverError,
                    "mount boundary",
                ):
                    self.tool.clear_private_directory(
                        target,
                        expected_uid=0,
                        expected_gid=0,
                        exact_path=target,
                    )
                self.assertEqual(payload.read_bytes(), b"preserve")
            finally:
                subprocess.run(
                    ["umount", str(nested)],
                    check=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

    def test_nonce_migration_override_has_only_fixed_loopback_port_and_acl(self):
        source = REDIS_MIGRATION_COMPOSE.read_text()
        self.assertIn('"127.0.0.1:16379:6379"', source)
        self.assertIn("source: /run/sub2api-gate/redis-migration.acl", source)
        self.assertIn("target: /etc/redis/users.acl", source)
        self.assertIn("create_host_path: false", source)
        self.assertNotIn("0.0.0.0", source)

    def test_nonce_canary_is_isolated_from_the_live_sync_release(self):
        source = (ROOT / "docker-compose.nonce-canary.yml").read_text()
        self.assertIn("name: sub2api-gate-nonce-canary", source)
        self.assertIn(
            "name: sub2api-gate-traffic-canary_traffic-canary-data", source
        )
        self.assertIn("pull_policy: never", source)
        self.assertNotIn("ports:", source)
        self.assertNotIn("sub2api-gate-release_sub2api-data", source)
        self.assertNotIn("network_mode: host", source)
        self.assertNotIn("privileged: true", source)

    def test_merged_nonce_migration_compose_has_one_loopback_port_and_one_acl_mount(self):
        result = __import__("subprocess").run(
            [
                "docker", "compose",
                "--env-file", str(ROOT / ".env.example"),
                "-f", str(ROOT / "docker-compose.nonce-canary.yml"),
                "-f", str(REDIS_MIGRATION_COMPOSE),
                "--profile", "nonce-canary",
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
