import importlib.util
import io
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE_PATH = ROOT / "docker-compose.traffic-canary.yml"
TOOL_PATH = ROOT / "deploy" / "traffic-canary.py"
SWITCH_PATH = ROOT / "deploy" / "switch-nginx-upstream.sh"


def load_tool():
    spec = importlib.util.spec_from_file_location("traffic_canary", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TtyBuffer(io.StringIO):
    def isatty(self):
        return True


class TrafficCanaryComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = COMPOSE_PATH.read_text(encoding="utf-8")
        cls.tool = TOOL_PATH.read_text(encoding="utf-8")

    def service(self, name, next_name=None):
        body = self.compose.split(f"  {name}:\n", 1)[1]
        if next_name:
            body = body.split(f"\n  {next_name}:\n", 1)[0]
        else:
            body = body.split("\nnetworks:\n", 1)[0]
        return body

    def test_stack_is_separate_from_the_empty_18081_preflight(self):
        self.assertIn("name: sub2api-gate-traffic-canary", self.compose)
        self.assertEqual(self.compose.count('profiles: ["traffic-canary"]'), 3)
        self.assertNotIn('"127.0.0.1:18081:8080"', self.compose)
        self.assertIn('"127.0.0.1:8081:8080"', self.compose)
        self.assertIn(
            "sub2api-gate.canary-purpose: migrated-target-traffic-only",
            self.compose,
        )
        self.assertNotIn("sub2api-sync:", self.compose)
        self.assertNotIn("3021:3021", self.compose)
        self.assertNotIn("3022:3021", self.compose)
        self.assertNotIn("external: true", self.compose)
        self.assertIn("internal: true", self.compose)

    def test_target_data_services_are_unpublished_pinned_and_logless(self):
        postgres = self.service("traffic-canary-postgres", "traffic-canary-redis")
        redis = self.service("traffic-canary-redis", "sub2api-traffic-canary")
        self.assertNotIn("ports:", postgres)
        self.assertNotIn("ports:", redis)
        self.assertIn(
            "postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15",
            postgres,
        )
        self.assertIn(
            "redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005",
            redis,
        )
        for body in (postgres, redis):
            self.assertIn("pull_policy: never", body)
            self.assertIn('driver: "none"', body)
            self.assertIn("read_only: true", body)
            self.assertIn("ulimits:\n      core:\n        soft: 0\n        hard: 0", body)
            self.assertIn("cap_drop:\n      - ALL", body)
            self.assertIn("no-new-privileges:true", body)
        self.assertIn("source: /mnt/data/sub2api-gate/postgres", postgres)
        self.assertIn("target: /var/lib/postgresql", postgres)
        self.assertIn("PGDATA: /var/lib/postgresql/18/docker", postgres)
        self.assertNotIn("/var/lib/postgresql/data", postgres)
        self.assertIn("create_host_path: false", postgres)
        self.assertIn("source: /mnt/data/sub2api-gate/redis/users.acl", redis)
        self.assertIn("/data:rw,noexec,nosuid,nodev", redis)
        self.assertIn("--appendonly\n      - \"no\"", redis)
        self.assertIn("--save\n      - \"\"", redis)
        self.assertIn("mem_limit: 256m", redis)
        self.assertIn("--maxmemory\n      - 128mb", redis)
        self.assertIn("--maxmemory-policy\n      - noeviction", redis)

    def test_sub2api_uses_sanitized_target_and_least_privilege_runtime(self):
        app = self.service("sub2api-traffic-canary")
        self.assertIn(
            "weishaw/sub2api@sha256:8469b859dbc0fb299ffa01d4cc8890dfce671b1ae9fa9cb54651bd258a3577d2",
            app,
        )
        self.assertIn("pull_policy: never", app)
        self.assertIn('user: "1000:1000"', app)
        self.assertIn("read_only: true", app)
        self.assertIn('driver: "none"', app)
        self.assertIn("ulimits:\n      core:\n        soft: 0\n        hard: 0", app)
        self.assertIn("source: /mnt/data/sub2api-gate/app", app)
        self.assertIn("create_host_path: false", app)
        self.assertIn('AUTO_SETUP: "false"', app)
        self.assertNotIn('AUTO_SETUP: "true"', app)
        self.assertIn("DATABASE_USER: sub2api_app", app)
        self.assertIn("DATABASE_HOST: traffic-canary-postgres", app)
        self.assertIn("REDIS_HOST: traffic-canary-redis", app)
        self.assertIn('LOG_OUTPUT_TO_FILE: "false"', app)
        self.assertIn('GATEWAY_LOG_UPSTREAM_ERROR_BODY: "false"', app)
        self.assertIn('RISK_CONTROL_ENABLED: "false"', app)
        self.assertIn('IMAGE_STORAGE_ENABLED: "false"', app)
        self.assertNotIn("ADMIN_PASSWORD", app)
        self.assertNotIn("ADMIN_EMAIL", app)

    def test_sub2api_runtime_mode_cannot_be_overridden(self):
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("docker CLI is unavailable")

        env = os.environ.copy()
        env.update({"SERVER_MODE": "debug", "RUN_MODE": "development"})
        result = subprocess.run(
            [
                docker,
                "compose",
                "--env-file",
                ROOT / ".env.example",
                "-f",
                COMPOSE_PATH,
                "--profile",
                "traffic-canary",
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        app = json.loads(result.stdout)["services"]["sub2api-traffic-canary"]
        self.assertEqual(app["environment"]["SERVER_MODE"], "release")
        self.assertEqual(app["environment"]["RUN_MODE"], "standard")

    def test_controller_fails_closed_on_storage_identity_and_privacy(self):
        for contract in (
            'DATA_ROOT = pathlib.Path("/mnt/data/sub2api-gate")',
            'marker_value != b"installed_by=sub2api-gate\\n"',
            'version_value != "18"',
            'cluster = postgres / "18" / "docker"',
            'require_path(cluster, kind="directory", uid=70, gid=70, mode=0o700)',
            '"/var/lib/postgresql"',
            "pg_controldata",
            "INFO server",
            "legacy PostgreSQL already uses the migrated target path",
            "legacy Sub2API already uses the migrated target app path",
            "runtime_dependency_hosts",
            "require_legacy_dependency",
            "verify_conversation_guards.sql",
            "verify_no_conversation_content.sql",
            "target volatile Redis was not empty before app startup",
            "require-clean-worktree.sh",
            "security-preflight.sh",
            'pathlib.Path("/proc/swaps")',
            'pathlib.Path("/var/run/docker.sock")',
            'compose_command(env_file, "config", "--quiet")',
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, self.tool)
        self.assertNotIn("docker logs", self.tool)
        self.assertNotIn("Config.Env", self.tool)
        self.assertIn("stderr=subprocess.DEVNULL", self.tool)

    def test_switcher_attests_target_before_health_or_nginx_change(self):
        switcher = SWITCH_PATH.read_text(encoding="utf-8")
        verifier = '"$traffic_canary_verifier" verify'
        health = '"http://127.0.0.1:$target_port/health"'
        mutation = 'install -m 0644 "$source_file"'
        self.assertIn(verifier, switcher)
        self.assertLess(switcher.index(verifier), switcher.index(health))
        self.assertLess(switcher.index(verifier), switcher.index(mutation))
        self.assertIn("canary --apply requires all three legacy container identities", switcher)

    def test_compose_config_parses_without_runtime_values(self):
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("docker CLI is unavailable")
        result = subprocess.run(
            [
                docker,
                "compose",
                "-f",
                COMPOSE_PATH,
                "--profile",
                "traffic-canary",
                "config",
                "--no-interpolate",
                "--quiet",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class TrafficCanaryToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_check_is_offline_and_ignores_environment_file_inputs(self):
        calls = []

        def forbidden(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("check mode ran a command")

        with mock.patch.dict(
            os.environ,
            {
                "SUB2API_DATA_ROOT": "/untrusted",
                "POSTGRES_PASSWORD": "must-not-be-read",
                "REDIS_PASSWORD": "must-not-be-read",
            },
        ):
            stdout = io.StringIO()
            result = self.tool.main(
                ["check"],
                runner=forbidden,
                stdin=io.StringIO(),
                stderr=io.StringIO(),
                stdout=stdout,
            )
        self.assertEqual(result, 0)
        self.assertEqual(calls, [])
        self.assertIn("no environment file was read", stdout.getvalue())
        self.assertIn("no Docker command ran", stdout.getvalue())

    def test_apply_requires_private_tty_before_release_or_secret_file_reads(self):
        calls = []

        def forbidden(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("non-TTY apply ran a command")

        argv = [
            "--apply",
            "--env-file",
            "/private/deployment.env",
            "--wrangler-config",
            "/private/wrangler.jsonc",
            "--legacy-sub2api-container",
            "legacy-app",
            "--legacy-postgres-container",
            "legacy-postgres",
            "--legacy-redis-container",
            "legacy-redis",
        ]
        with mock.patch.object(self.tool.os, "geteuid", return_value=0):
            result = self.tool.main(
                argv,
                runner=forbidden,
                stdin=io.StringIO(),
                stderr=io.StringIO(),
                stdout=io.StringIO(),
            )
        self.assertEqual(result, 1)
        self.assertEqual(calls, [])

    def test_verify_and_apply_require_all_legacy_identities(self):
        for argv in (
            ["verify"],
            ["--apply", "--env-file", "/private/deployment.env"],
        ):
            with self.subTest(argv=argv):
                stderr = io.StringIO()
                result = self.tool.main(
                    argv,
                    runner=lambda *_args, **_kwargs: None,
                    stdin=TtyBuffer(),
                    stderr=stderr,
                    stdout=io.StringIO(),
                )
                self.assertEqual(result, 2)
                self.assertIn("all three legacy container names", stderr.getvalue())

    def test_apply_requires_both_explicit_private_configuration_paths(self):
        base = [
            "--apply",
            "--legacy-sub2api-container",
            "legacy-app",
            "--legacy-postgres-container",
            "legacy-postgres",
            "--legacy-redis-container",
            "legacy-redis",
        ]
        cases = (
            (base, "--env-file"),
            (base + ["--env-file", "/private/deployment.env"], "--wrangler-config"),
        )
        for argv, missing in cases:
            with self.subTest(missing=missing):
                stderr = io.StringIO()
                result = self.tool.main(
                    argv,
                    runner=lambda *_args, **_kwargs: None,
                    stdin=TtyBuffer(),
                    stderr=stderr,
                    stdout=io.StringIO(),
                )
                self.assertEqual(result, 2)
                self.assertIn(f"requires {missing}", stderr.getvalue())

    def test_compose_environment_cannot_override_private_file_or_project(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = pathlib.Path(directory) / "deployment.env"
            env_file.write_text(
                "SUB2API_DATA_ROOT=/mnt/data/sub2api-gate\n"
                "POSTGRES_PASSWORD=private-file-test-value\n",
                encoding="utf-8",
            )
            env_file.chmod(0o600)
            with mock.patch.dict(
                os.environ,
                {
                    "POSTGRES_PASSWORD": "exported-override-must-be-removed",
                    "COMPOSE_PROJECT_NAME": "unreviewed-project",
                    "COMPOSE_FILE": "/unreviewed/compose.yml",
                    "UNRELATED_SAFE_VARIABLE": "preserved",
                },
            ):
                resolved, keys = self.tool.parse_private_env(env_file)
                environment = self.tool.compose_environment(keys)
        self.assertEqual(resolved, env_file.resolve())
        self.assertNotIn("POSTGRES_PASSWORD", environment)
        self.assertNotIn("COMPOSE_PROJECT_NAME", environment)
        self.assertNotIn("COMPOSE_FILE", environment)
        self.assertEqual(environment["DOCKER_HOST"], "unix:///var/run/docker.sock")
        self.assertEqual(environment["UNRELATED_SAFE_VARIABLE"], "preserved")
        command = self.tool.compose_command(resolved, "config", "--quiet")
        self.assertIn("--project-name", command)
        self.assertEqual(command[command.index("--project-name") + 1], self.tool.PROJECT)

    def test_private_env_cannot_redirect_docker_or_compose(self):
        for key in ("DOCKER_HOST", "DOCKER_CONTEXT", "COMPOSE_FILE"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                env_file = pathlib.Path(directory) / "deployment.env"
                env_file.write_text(
                    "SUB2API_DATA_ROOT=/mnt/data/sub2api-gate\n"
                    f"{key}=unreviewed-value\n",
                    encoding="utf-8",
                )
                env_file.chmod(0o600)
                with self.assertRaisesRegex(self.tool.CanaryError, "environment file is invalid"):
                    self.tool.parse_private_env(env_file)

    def test_identity_parsers_accept_only_bounded_machine_identifiers(self):
        def result(stdout):
            return subprocess.CompletedProcess([], 0, stdout.encode("ascii"), b"")

        pg_runner = lambda *_args, **_kwargs: result(
            "pg_control version number: 1800\n"
            "Database system identifier: 7612345678901234567\n"
        )
        redis_runner = lambda *_args, **_kwargs: result(
            "# Server\r\nrun_id:0123456789abcdef0123456789abcdef01234567\r\n"
        )
        self.assertEqual(
            self.tool.pg_system_identifier("pg", runner=pg_runner),
            "7612345678901234567",
        )
        self.assertEqual(
            self.tool.redis_run_identifier("redis", runner=redis_runner),
            "0123456789abcdef0123456789abcdef01234567",
        )
        with self.assertRaises(self.tool.CanaryError):
            self.tool.pg_system_identifier(
                "pg", runner=lambda *_args, **_kwargs: result("not-an-identity\n")
            )
        with self.assertRaises(self.tool.CanaryError):
                self.tool.redis_run_identifier(
                    "redis", runner=lambda *_args, **_kwargs: result("run_id:short\n")
                )

    def test_local_runtime_images_require_exact_repo_digest_and_platform(self):
        seen = []

        def runner(command, **_kwargs):
            reference = command[-1]
            seen.append(reference)
            image_id = "sha256:" + format(len(seen), "064x")
            payload = f'{image_id}|linux|amd64|["{reference}"]\n'.encode("ascii")
            return subprocess.CompletedProcess(command, 0, payload, b"")

        identities = self.tool.require_local_runtime_images(runner=runner)
        self.assertEqual(set(seen), set(self.tool.RUNTIME_IMAGES))
        self.assertEqual(set(identities), set(self.tool.RUNTIME_IMAGES))

        def wrong_digest(command, **_kwargs):
            reference = command[-1]
            payload = (
                "sha256:" + "a" * 64 + "|linux|amd64|"
                f'["unreviewed/image@sha256:{"b" * 64}"]\n'
            ).encode("ascii")
            return subprocess.CompletedProcess(command, 0, payload, b"")

        with self.assertRaisesRegex(self.tool.CanaryError, "reviewed digest"):
            self.tool.require_local_runtime_images(runner=wrong_digest)

    def test_canary_start_never_builds_or_pulls_inside_the_release_window(self):
        commands = []

        def runner(command, **_kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        names = self.tool.LegacyNames("legacy-app", "legacy-pg", "legacy-redis")
        target = {"app": "target-app", "postgres": "target-pg", "redis": "target-redis"}
        with mock.patch.object(self.tool, "container_exists", return_value=False), \
             mock.patch.object(self.tool, "project_members", return_value=[]), \
             mock.patch.object(self.tool, "legacy_identity", return_value={"app": "legacy-app", "postgres": "legacy-pg", "redis": "legacy-redis"}), \
             mock.patch.object(self.tool, "wait_healthy"), \
             mock.patch.object(self.tool, "pg_system_identifier", return_value="target-pg"), \
             mock.patch.object(self.tool, "redis_run_identifier", return_value="target-redis"), \
             mock.patch.object(self.tool, "require_redis_volatile"), \
             mock.patch.object(self.tool, "run_postgres_gate"), \
             mock.patch.object(self.tool, "require_app_role"), \
             mock.patch.object(self.tool, "validate_target_runtime", return_value=target), \
             mock.patch.object(self.tool, "require_distinct"):
            self.tool.start_canary(
                pathlib.Path("/private/deployment.env"),
                {},
                names,
                runner=runner,
            )

        up_commands = [command for command in commands if "up" in command]
        self.assertEqual(len(up_commands), 2)
        for command in up_commands:
            self.assertIn("--no-build", command)
            self.assertIn("--pull", command)
            self.assertEqual(command[command.index("--pull") + 1], "never")

    def test_runtime_dependency_hosts_reads_only_reviewed_host_fields(self):
        calls = []

        def runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(
                command,
                0,
                b"database=postgres\nredis=redis\n",
                b"",
            )

        self.assertEqual(
            self.tool.runtime_dependency_hosts("legacy-app", runner=runner),
            {"database": "postgres", "redis": "redis"},
        )
        self.assertEqual(calls[0][:4], ["docker", "exec", "legacy-app", "sh"])
        self.assertNotIn("PASSWORD", " ".join(calls[0]))
        self.assertNotIn("Config.Env", " ".join(calls[0]))

        for output in (
            b"database=\nredis=redis\n",
            b"database=postgres\n",
            b"database=postgres\nredis=redis\nunreviewed=value\n",
        ):
            with self.subTest(output=output):
                with self.assertRaisesRegex(
                    self.tool.CanaryError,
                    "dependency hosts could not be verified",
                ):
                    self.tool.runtime_dependency_hosts(
                        "legacy-app",
                        runner=lambda *_args, **_kwargs: subprocess.CompletedProcess(
                            [], 0, output, b""
                        ),
                    )

    def test_legacy_dependency_requires_a_shared_network_and_matching_alias(self):
        network_id = "a" * 64
        app_networks = {
            "legacy": {"NetworkID": network_id, "Aliases": ["sub2api"]},
        }
        postgres_networks = {
            "legacy": {
                "NetworkID": network_id,
                "Aliases": ["postgres"],
                "DNSNames": ["legacy-postgres"],
                "IPAddress": "172.20.0.3",
            },
        }
        with mock.patch.object(
            self.tool,
            "network_attachments",
            side_effect=[app_networks, postgres_networks],
        ):
            self.tool.require_legacy_dependency(
                "legacy-app",
                "legacy-postgres",
                "postgres",
                "PostgreSQL",
            )

        with mock.patch.object(
            self.tool,
            "network_attachments",
            side_effect=[app_networks, postgres_networks],
        ):
            with self.assertRaisesRegex(
                self.tool.CanaryError,
                "host does not identify the supplied container",
            ):
                self.tool.require_legacy_dependency(
                    "legacy-app",
                    "wrong-postgres",
                    "unrelated-database",
                    "PostgreSQL",
                )

        with mock.patch.object(
            self.tool,
            "network_attachments",
            side_effect=[
                app_networks,
                {"other": {"NetworkID": "b" * 64, "Aliases": ["postgres"]}},
            ],
        ):
            with self.assertRaisesRegex(self.tool.CanaryError, "does not share"):
                self.tool.require_legacy_dependency(
                    "legacy-app",
                    "legacy-postgres",
                    "postgres",
                    "PostgreSQL",
                )

    def test_each_equal_legacy_target_identity_is_rejected(self):
        base = {"app": "a", "postgres": "p", "redis": "r"}
        for component in base:
            target = {"app": "a2", "postgres": "p2", "redis": "r2"}
            target[component] = base[component]
            with self.subTest(component=component):
                with self.assertRaisesRegex(
                    self.tool.CanaryError, f"distinct {component} identity"
                ):
                    self.tool.require_distinct(base, target)

    def test_runtime_status_rejects_active_host_swap(self):
        with mock.patch.object(
            self.tool.pathlib.Path,
            "read_text",
            return_value="Filename Type Size Used Priority\n",
        ):
            self.tool.require_no_active_swap()
        with mock.patch.object(
            self.tool.pathlib.Path,
            "read_text",
            return_value=(
                "Filename Type Size Used Priority\n"
                "/swap.img file 1048576 0 -2\n"
            ),
        ):
            with self.assertRaisesRegex(self.tool.CanaryError, "active host swap"):
                self.tool.require_no_active_swap()

    def test_runtime_pins_docker_to_the_trusted_local_socket(self):
        socket_path = mock.Mock()
        socket_path.stat.return_value = mock.Mock(
            st_mode=stat.S_IFSOCK | 0o660,
            st_uid=0,
        )
        socket_path.is_symlink.return_value = False
        with mock.patch.object(self.tool, "DOCKER_SOCKET", socket_path), mock.patch.dict(
            os.environ,
            {
                "DOCKER_HOST": "tcp://remote.example.test:2376",
                "DOCKER_CONTEXT": "remote",
                "DOCKER_TLS_VERIFY": "1",
            },
        ):
            self.tool.pin_local_docker_socket()
            self.assertEqual(os.environ["DOCKER_HOST"], "unix:///var/run/docker.sock")
            self.assertNotIn("DOCKER_CONTEXT", os.environ)
            self.assertNotIn("DOCKER_TLS_VERIFY", os.environ)

    def test_legacy_names_cannot_alias_target_or_each_other(self):
        invalid = (
            [
                "verify",
                "--legacy-sub2api-container",
                self.tool.TARGET_APP,
                "--legacy-postgres-container",
                "legacy-postgres",
                "--legacy-redis-container",
                "legacy-redis",
            ],
            [
                "verify",
                "--legacy-sub2api-container",
                "same",
                "--legacy-postgres-container",
                "same",
                "--legacy-redis-container",
                "legacy-redis",
            ],
        )
        for argv in invalid:
            with self.subTest(argv=argv):
                with self.assertRaises(self.tool.UsageError):
                    self.tool.parse_arguments(argv)


if __name__ == "__main__":
    unittest.main()
