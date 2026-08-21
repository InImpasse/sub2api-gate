import hashlib
import hmac
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
COMPOSE_PATH = ROOT / "docker-compose.sync-canary.yml"
MAIN_COMPOSE_PATH = ROOT / "docker-compose.yml"
DOCKERFILE_PATH = ROOT / "sub2api-sync" / "Dockerfile"
DOCKERIGNORE_PATH = ROOT / "sub2api-sync" / ".dockerignore"
TOOL_PATH = ROOT / "deploy" / "sync-canary.py"
ROLE_GATE_PATH = ROOT / "migrations" / "verify_sync_role_least_privilege.sql"


def load_tool():
    spec = importlib.util.spec_from_file_location("sync_canary", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TtyBuffer(io.StringIO):
    def __init__(self, is_tty=True):
        super().__init__()
        self._is_tty = is_tty

    def isatty(self):
        return self._is_tty


class SyncCanaryComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = COMPOSE_PATH.read_text(encoding="utf-8")

    def service(self, name, next_name=None):
        body = self.compose.split(f"  {name}:\n", 1)[1]
        if next_name:
            return body.split(f"\n  {next_name}:\n", 1)[0]
        return body.split("\nnetworks:\n", 1)[0]

    def test_canary_is_separate_loopback_only_and_never_on_v1(self):
        self.assertIn("name: sub2api-gate-sync-canary", self.compose)
        canary = self.service("sub2api-sync-canary", "sub2api-sync-stable")
        stable = self.service("sub2api-sync-stable")
        self.assertIn('"127.0.0.1:3022:3021"', canary)
        self.assertIn('"127.0.0.1:3021:3021"', stable)
        self.assertIn("sub2api-gate.request-path: never-v1", canary)
        self.assertIn("sub2api-gate.request-path: never-v1", stable)
        self.assertNotIn("8080:", self.compose)
        self.assertNotIn("8081:", self.compose)
        self.assertNotIn("nginx", self.compose.lower())
        self.assertNotIn("mirror", self.compose.lower())

    def test_sync_services_are_non_root_read_only_and_logless(self):
        template = self.compose.split("x-sync-service: &sync-service\n", 1)[1].split(
            "\nservices:\n", 1
        )[0]
        self.assertIn('user: "65532:65532"', template)
        self.assertIn("read_only: true", template)
        self.assertIn('driver: "none"', template)
        self.assertIn("cap_drop:\n    - ALL", template)
        self.assertIn("no-new-privileges:true", template)
        self.assertIn("core:\n      soft: 0\n      hard: 0", template)
        self.assertIn("/tmp:rw,noexec,nosuid,nodev", template)
        self.assertNotIn("docker.sock", self.compose)

    def test_sync_image_is_prebuilt_from_fixed_sources_and_never_pulled(self):
        image = "sub2api-gate/sub2api-sync:pg18.4-r1"
        template = self.compose.split("x-sync-service: &sync-service\n", 1)[1].split(
            "\nservices:\n", 1
        )[0]
        main = MAIN_COMPOSE_PATH.read_text(encoding="utf-8")
        main_service = main.split("  sub2api-sync:\n", 1)[1].split(
            "\n  postgres:\n", 1
        )[0]
        dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")

        for service in (template, main_service):
            self.assertIn(f"image: {image}", service)
            self.assertIn("pull_policy: never", service)
            self.assertNotIn("build:", service)
        self.assertIn(
            "FROM postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15 AS postgres-client",
            dockerfile,
        )
        self.assertIn(
            "FROM python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df",
            dockerfile,
        )
        self.assertIn('psql (PostgreSQL) 18.4', dockerfile)
        self.assertNotRegex(dockerfile, r"\b(?:apk\s+add|apt-get|dnf\s|yum\s)")

    def test_sync_psql_wrapper_is_owner_executable_for_trusted_image_builds(self):
        wrapper = ROOT / "sub2api-sync" / "psql-wrapper.sh"
        metadata = wrapper.stat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertTrue(metadata.st_mode & stat.S_IXUSR)

    def test_sync_build_context_is_an_explicit_source_allowlist(self):
        entries = [
            line
            for line in DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(
            entries,
            [
                "*",
                "!Dockerfile",
                "!psql-wrapper.sh",
                "!sub2api_sync.py",
                "!usage_metadata.py",
            ],
        )

    def test_canary_targets_migrated_services_and_uses_persistent_nonce_only(self):
        self.assertIn("SUB2API_SYNC_DATABASE_HOST: traffic-canary-postgres", self.compose)
        self.assertIn("SUB2API_SYNC_DATABASE_USER: sub2api_sync", self.compose)
        self.assertIn(
            "SUB2API_INTERNAL_LOGIN_URL: http://sub2api-traffic-canary:8080/api/v1/auth/login",
            self.compose,
        )
        self.assertIn("SUB2API_SYNC_REDIS_HOST: sync-canary-redis-nonce", self.compose)
        self.assertIn("source: /mnt/data/sub2api-gate/redis/nonce", self.compose)
        self.assertIn("create_host_path: false", self.compose)
        self.assertIn("--appendonly\n      - \"yes\"", self.compose)
        self.assertIn("--appendfsync\n      - \"always\"", self.compose)
        self.assertIn("mem_limit: 128m", self.compose)
        self.assertIn("--maxmemory\n      - 32mb", self.compose)
        self.assertIn("--maxmemory-policy\n      - noeviction", self.compose)
        self.assertIn(
            "name: sub2api-gate-traffic-canary_traffic-canary-data", self.compose
        )

    def test_compose_config_parses_without_runtime_values(self):
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("docker CLI is unavailable")
        result = subprocess.run(
            [
                docker,
                "compose",
                "--file",
                COMPOSE_PATH,
                "--profile",
                "sync-canary",
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


class SyncRoleGateTests(unittest.TestCase):
    def test_role_gate_is_read_only_and_rejects_content_or_broad_privileges(self):
        sql = ROLE_GATE_PATH.read_text(encoding="utf-8")
        self.assertIn("unexpected_table_privileges", sql)
        self.assertIn("missing_table_privileges", sql)
        self.assertIn("unexpected_usage_columns", sql)
        self.assertIn("NOT has_table_privilege('sub2api_sync', 'public.usage_logs', 'SELECT')", sql)
        self.assertIn("NOT rolsuper", sql)
        self.assertIn("NOT rolbypassrls", sql)
        self.assertNotRegex(sql, r"(?im)^\s*(insert|update|delete|alter|create|drop|truncate)\b")


class SyncCanaryToolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def test_check_and_mutation_dry_run_are_offline(self):
        for argv in (
            ["check"],
            ["prepare-image"],
            ["start"],
            ["promote"],
            ["rollback"],
        ):
            calls = []

            def forbidden(*args, **kwargs):
                calls.append((args, kwargs))
                raise AssertionError("offline mode ran a command")

            stdout = io.StringIO()
            result = self.tool.main(
                argv,
                runner=forbidden,
                stdin=io.StringIO(),
                stdout=stdout,
                stderr=io.StringIO(),
            )
            self.assertEqual(result, 0, argv)
            self.assertEqual(calls, [], argv)
            self.assertTrue(stdout.getvalue().strip())

    def test_apply_requires_private_root_tty_before_file_or_command_access(self):
        calls = []

        def forbidden(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("invalid apply ran a command")

        with mock.patch.object(self.tool.os, "geteuid", return_value=0):
            result = self.tool.main(
                ["start", "--apply", "--env-file", "/private/env"],
                runner=forbidden,
                stdin=io.StringIO(),
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )
        self.assertEqual(result, 1)
        self.assertEqual(calls, [])

    def test_diagnostics_uses_private_readonly_context_without_docker_or_release_gate(self):
        def forbidden(*_args, **_kwargs):
            raise AssertionError("diagnostics ran a local command")

        stdout = TtyBuffer()
        with mock.patch.object(self.tool, "require_readonly_context") as context, \
             mock.patch.object(
                 self.tool, "parse_private_env", return_value={"SUB2API_SYNC_SECRET": "s" * 32}
             ), mock.patch.object(
                 self.tool, "print_diagnostic"
             ) as diagnostic:
            result = self.tool.main(
                [
                    "diagnostics", "--env-file", "/private/env",
                    "--request-id", "worker-diagnostic-main",
                ],
                runner=forbidden,
                stdin=TtyBuffer(),
                stdout=stdout,
                stderr=TtyBuffer(),
                secret_reader=lambda _prompt: "s" * 32,
            )

        self.assertEqual(result, 0)
        context.assert_called_once()
        diagnostic.assert_called_once_with(
            3021, "s" * 32, "worker-diagnostic-main", stdout=stdout
        )

    def test_apply_rejects_noncanonical_release_before_private_access_or_commands(self):
        calls = []

        def forbidden(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("untrusted apply ran a command")

        secret_reader = mock.Mock()
        stderr = TtyBuffer()
        with mock.patch.object(self.tool.os, "geteuid", return_value=0), \
             mock.patch.object(self.tool, "load_private_env_parser") as parser_loader:
            result = self.tool.main(
                ["start", "--apply", "--env-file", "/private/env"],
                runner=forbidden,
                stdin=TtyBuffer(),
                stdout=TtyBuffer(),
                stderr=stderr,
                secret_reader=secret_reader,
            )
        self.assertEqual(result, 1)
        self.assertEqual(calls, [])
        parser_loader.assert_not_called()
        secret_reader.assert_not_called()
        self.assertIn("trusted production release tree", stderr.getvalue())

    def test_apply_context_requires_all_private_ttys(self):
        with mock.patch.object(
            self.tool, "TRUSTED_RELEASE_ROOT", self.tool.ROOT
        ), mock.patch.object(
            self.tool.os, "geteuid", return_value=0
        ), mock.patch.object(
            self.tool, "require_trusted_release_tree"
        ) as trusted_tree:
            for stream_name, streams in (
                ("stdin", (TtyBuffer(False), TtyBuffer(), TtyBuffer())),
                ("stdout", (TtyBuffer(), TtyBuffer(False), TtyBuffer())),
                ("stderr", (TtyBuffer(), TtyBuffer(), TtyBuffer(False))),
            ):
                with self.subTest(stream=stream_name), self.assertRaisesRegex(
                    self.tool.CanaryError, "private interactive TTY"
                ):
                    self.tool.require_production_apply_context(
                        self.tool.ROOT, streams=streams
                    )
                trusted_tree.assert_not_called()

            self.tool.require_production_apply_context(
                self.tool.ROOT,
                streams=(TtyBuffer(), TtyBuffer(), TtyBuffer()),
            )
        trusted_tree.assert_called_once_with(self.tool.ROOT)

    def test_trusted_release_tree_validates_fixed_sources_and_controllers(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted_root = pathlib.Path(directory) / "sub2api-gate-release"
            trusted_root.mkdir()
            trusted_root.chmod(0o755)
            for relative_path in self.tool.TRUSTED_RELEASE_DIRECTORIES:
                path = trusted_root / relative_path
                path.mkdir(parents=True, exist_ok=True)
                path.chmod(0o755)
            for relative_path, executable in self.tool.TRUSTED_RELEASE_FILES:
                path = trusted_root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("trusted fixture\n", encoding="ascii")
                path.chmod(0o755 if executable else 0o644)

            source = trusted_root / self.tool.SYNC_CANARY_SOURCE_RELATIVE_PATH
            release_guard = trusted_root / self.tool.RELEASE_GUARD_RELATIVE_PATH
            traffic_controller = (
                trusted_root / self.tool.TRAFFIC_CONTROLLER_RELATIVE_PATH
            )
            private_env = trusted_root / self.tool.PRIVATE_ENV_RELATIVE_PATH
            replacement = trusted_root / "deploy" / "replacement.py"
            replacement.write_text("pass\n", encoding="ascii")
            replacement.chmod(0o644)

            with mock.patch.object(
                self.tool, "TRUSTED_RELEASE_ROOT", trusted_root
            ):
                self.tool.require_trusted_release_tree(
                    trusted_root,
                    source_path=source,
                    clean_worktree=release_guard,
                    traffic_controller=traffic_controller,
                    private_env=private_env,
                    expected_uid=os.getuid(),
                )
                with self.assertRaisesRegex(
                    self.tool.CanaryError, "outside the trusted release tree"
                ):
                    self.tool.require_trusted_release_tree(
                        trusted_root,
                        source_path=replacement,
                        clean_worktree=release_guard,
                        traffic_controller=traffic_controller,
                        private_env=private_env,
                        expected_uid=os.getuid(),
                    )
                with self.assertRaisesRegex(
                    self.tool.CanaryError, "release guard"
                ):
                    self.tool.require_trusted_release_tree(
                        trusted_root,
                        source_path=source,
                        clean_worktree=replacement,
                        traffic_controller=traffic_controller,
                        private_env=private_env,
                        expected_uid=os.getuid(),
                    )
                with self.assertRaisesRegex(
                    self.tool.CanaryError, "traffic controller"
                ):
                    self.tool.require_trusted_release_tree(
                        trusted_root,
                        source_path=source,
                        clean_worktree=release_guard,
                        traffic_controller=replacement,
                        private_env=private_env,
                        expected_uid=os.getuid(),
                    )
                release_guard.chmod(0o775)
                with self.assertRaisesRegex(
                    self.tool.CanaryError, "unsafe identity"
                ):
                    self.tool.require_trusted_release_tree(
                        trusted_root,
                        source_path=source,
                        clean_worktree=release_guard,
                        traffic_controller=traffic_controller,
                        private_env=private_env,
                        expected_uid=os.getuid(),
                    )
    def test_private_env_rejects_quotes_comments_escapes_and_duplicates(self):
        bad_lines = (
            'SUB2API_SYNC_SECRET="quoted"',
            "SUB2API_SYNC_SECRET=value # comment",
            r"SUB2API_SYNC_SECRET=value\withescape",
            "SUB2API_SYNC_SECRET=$INTERPOLATED",
            "SUB2API_SYNC_SECRET=one\nSUB2API_SYNC_SECRET=two",
        )
        for content in bad_lines:
            with self.subTest(content=content), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "runtime.env"
                path.write_text(content + "\n", encoding="utf-8")
                path.chmod(0o600)
                with self.assertRaises(self.tool.CanaryError):
                    self.tool.parse_private_env(path)

    def test_private_env_requires_exact_data_root_strong_secrets_and_https_urls(self):
        valid = "\n".join((
            "SUB2API_DATA_ROOT=/mnt/data/sub2api-gate",
            "POSTGRES_DB=sub2api",
            "SUB2API_SYNC_DATABASE_PASSWORD=" + "d" * 32,
            "SUB2API_SYNC_REDIS_PASSWORD=" + "r" * 32,
            "SUB2API_SYNC_SECRET=" + "s" * 32,
            "SUB2API_LOGIN_URL=https://api.example.test/login",
            "SUB2API_PUBLIC_BASE_URL=https://api.example.test/v1",
            "",
        ))
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "runtime.env"
            path.write_text(valid, encoding="utf-8")
            path.chmod(0o600)
            values = self.tool.parse_private_env(path)
            self.assertEqual(values["SUB2API_DATA_ROOT"], "/mnt/data/sub2api-gate")

            path.write_text(valid.replace("/mnt/data/sub2api-gate", "/tmp/data"), encoding="utf-8")
            with self.assertRaisesRegex(self.tool.CanaryError, "data root"):
                self.tool.parse_private_env(path)

            path.write_text(valid.replace("https://api.example.test/login", "http://api.example.test/login"), encoding="utf-8")
            with self.assertRaisesRegex(self.tool.CanaryError, "public URL"):
                self.tool.parse_private_env(path)

    def test_compose_environment_cannot_be_overridden_by_shell_values(self):
        with mock.patch.dict(
            os.environ,
            {
                "PATH": "/usr/bin",
                "POSTGRES_DB": "host-override",
                "DOCKER_HOST": "tcp://untrusted.example.test:2375",
                "COMPOSE_PROJECT_NAME": "untrusted",
            },
            clear=True,
        ):
            environment = self.tool.compose_environment({"POSTGRES_DB": "private"})
        expected = self.tool.safe_system_environment()
        expected["DOCKER_HOST"] = self.tool.LOCAL_DOCKER_HOST
        self.assertEqual(environment, expected)
        self.assertNotIn("POSTGRES_DB", environment)
        self.assertNotIn("COMPOSE_PROJECT_NAME", environment)

    def test_direct_docker_commands_and_prepare_image_pin_the_local_endpoint(self):
        image_id = "sha256:" + "a" * 64
        git_head = "b" * 40
        calls = []
        socket_metadata = mock.Mock(
            st_mode=stat.S_IFSOCK | 0o660,
            st_uid=0,
        )
        socket_path = mock.Mock()
        socket_path.lstat.return_value = socket_metadata

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        with mock.patch.object(self.tool, "DOCKER_SOCKET", socket_path), \
             mock.patch.object(self.tool, "require_trusted_docker_binary") as trusted_binary, \
             mock.patch.object(self.tool.subprocess, "run", side_effect=run), \
             mock.patch.object(self.tool, "current_git_head", return_value=git_head), \
             mock.patch.object(
                 self.tool,
                 "inspect_local_sync_image",
                 side_effect=[image_id, image_id],
             ), \
             mock.patch.object(self.tool, "write_image_state"), \
             mock.patch.dict(
                 os.environ,
                 {
                     "PATH": "/usr/bin",
                     "DOCKER_HOST": "tcp://untrusted.example.test:2375",
                     "DOCKER_CONTEXT": "untrusted",
                     "DOCKER_CONFIG": "/tmp/untrusted-docker-config",
                     "BUILDKIT_HOST": "tcp://untrusted.example.test:1234",
                     "BUILDX_BUILDER": "untrusted",
                     "UNRELATED": "retained",
                 },
                 clear=True,
             ):
            self.tool.run_command(["docker", "image", "inspect", "test-image"])
            self.assertEqual(self.tool.prepare_sync_image(), image_id)

        self.assertEqual(
            [command[0:2] for command, _kwargs in calls],
            [
                [self.tool.DOCKER_BINARY, "image"],
                [self.tool.DOCKER_BINARY, "build"],
                [self.tool.DOCKER_BINARY, "image"],
            ],
        )
        self.assertEqual(trusted_binary.call_count, 3)
        expected = self.tool.safe_system_environment()
        expected["DOCKER_HOST"] = self.tool.LOCAL_DOCKER_HOST
        for _command, kwargs in calls:
            self.assertEqual(kwargs["env"], expected)
            self.assertNotIn("UNRELATED", kwargs["env"])

    def test_all_child_processes_use_a_minimal_environment(self):
        calls = []

        def run(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        hostile_environment = {
            "PATH": "/attacker/bin",
            "GIT_DIR": "/attacker/repository",
            "GIT_WORK_TREE": "/attacker/worktree",
            "GIT_CONFIG_GLOBAL": "/attacker/gitconfig",
            "SYSTEMD_PAGER": "/attacker/pager",
            "SYSTEMD_LESS": "FRX",
            "LD_PRELOAD": "/attacker/library.so",
            "BASH_ENV": "/attacker/bashrc",
            "PYTHONPATH": "/attacker/python",
        }
        with mock.patch.object(
            self.tool, "require_trusted_system_binary"
        ) as trusted_binary, mock.patch.object(
            self.tool.subprocess, "run", side_effect=run
        ), mock.patch.dict(os.environ, hostile_environment, clear=True):
            self.tool.run_command([str(self.tool.CLEAN_WORKTREE)])
            self.tool.run_command(
                [sys.executable, str(self.tool.TRAFFIC_CONTROLLER), "status"]
            )
            self.tool.run_command(["git", "rev-parse", "--verify", "HEAD^{commit}"])
            self.tool.run_command(
                ["systemctl", "is-active", "--quiet", self.tool.LEGACY_UNIT]
            )

        self.assertEqual(
            [command[0] for command, _kwargs in calls],
            [
                str(self.tool.CLEAN_WORKTREE),
                sys.executable,
                self.tool.GIT_BINARY,
                self.tool.SYSTEMCTL_BINARY,
            ],
        )
        self.assertEqual(
            trusted_binary.call_args_list,
            [
                mock.call(self.tool.GIT_BINARY),
                mock.call(self.tool.SYSTEMCTL_BINARY),
            ],
        )
        for _command, kwargs in calls:
            self.assertEqual(kwargs["env"], self.tool.safe_system_environment())
            self.assertNotIn("GIT_DIR", kwargs["env"])
            self.assertNotIn("SYSTEMD_PAGER", kwargs["env"])
            self.assertNotIn("LD_PRELOAD", kwargs["env"])
            self.assertNotIn("BASH_ENV", kwargs["env"])
            self.assertNotIn("PYTHONPATH", kwargs["env"])

    def test_trusted_system_binary_rejects_unsafe_metadata(self):
        cases = (
            ("relative", stat.S_IFREG | 0o755, 0, 0, False),
            ("symlink", stat.S_IFLNK | 0o777, 0, 0, True),
            ("not-regular", stat.S_IFDIR | 0o755, 0, 0, True),
            ("not-root-owned", stat.S_IFREG | 0o755, 1000, 0, True),
            ("not-root-group", stat.S_IFREG | 0o755, 0, 1000, True),
            ("group-writable", stat.S_IFREG | 0o775, 0, 0, True),
        )
        for label, mode, uid, gid, absolute in cases:
            with self.subTest(label=label):
                binary_path = mock.Mock()
                binary_path.is_absolute.return_value = absolute
                binary_path.lstat.return_value = mock.Mock(
                    st_mode=mode,
                    st_uid=uid,
                    st_gid=gid,
                )
                with mock.patch.object(
                    self.tool.pathlib, "Path", return_value=binary_path
                ), self.assertRaisesRegex(self.tool.CanaryError, "unsafe"):
                    self.tool.require_trusted_system_binary("/safe/command")

    def test_trusted_docker_binary_rejects_unsafe_metadata(self):
        cases = (
            ("not-regular", stat.S_IFDIR | 0o755, 0, 0),
            ("not-root-owned", stat.S_IFREG | 0o755, 1000, 0),
            ("not-root-group", stat.S_IFREG | 0o755, 0, 1000),
            ("group-writable", stat.S_IFREG | 0o775, 0, 0),
        )
        for label, mode, uid, gid in cases:
            with self.subTest(label=label):
                binary_path = mock.Mock()
                binary_path.lstat.return_value = mock.Mock(
                    st_mode=mode,
                    st_uid=uid,
                    st_gid=gid,
                )
                with mock.patch.object(self.tool.pathlib, "Path", return_value=binary_path):
                    with self.assertRaisesRegex(self.tool.CanaryError, "unsafe"):
                        self.tool.require_trusted_docker_binary()

    def test_local_docker_socket_rejects_unsafe_metadata(self):
        cases = (
            ("not-a-socket", stat.S_IFREG | 0o660, 0),
            ("not-root-owned", stat.S_IFSOCK | 0o660, 1000),
            ("world-writable", stat.S_IFSOCK | 0o666, 0),
        )
        for label, mode, uid in cases:
            with self.subTest(label=label):
                socket_path = mock.Mock()
                socket_path.lstat.return_value = mock.Mock(
                    st_mode=mode,
                    st_uid=uid,
                )
                with mock.patch.object(self.tool, "DOCKER_SOCKET", socket_path):
                    with self.assertRaisesRegex(self.tool.CanaryError, "unsafe"):
                        self.tool.require_local_docker_socket()

    def test_signed_status_uses_canonical_hmac_and_replay_headers(self):
        secret = "s" * 32
        response_body = b'{"ok":true,"action":"status","exists":false}'

        class Response:
            status = 200

            def getheader(self, name):
                return str(len(response_body)) if name.lower() == "content-length" else None

            def read(self, _size):
                return response_body

        requests = []

        class Connection:
            def __init__(self, host, port, timeout):
                self.endpoint = (host, port, timeout)

            def request(self, method, path, body, headers):
                requests.append((method, path, body, headers))

            def getresponse(self):
                return Response()

            def close(self):
                return None

        with mock.patch.object(self.tool.http.client, "HTTPConnection", Connection):
            status, _body, headers, body = self.tool.signed_status_request(
                3022,
                secret,
                timestamp=1_750_000_000,
                nonce="a" * 32,
                probe_uuid="00000000-0000-4000-8000-000000000001",
            )
        expected = hmac.new(
            secret.encode(),
            b"1750000000." + b"a" * 32 + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(status, 200)
        self.assertEqual(headers["x-sub2api-sync-signature"], expected)
        self.assertEqual(requests[0][0:2], ("POST", "/provision"))
        self.assertNotIn(secret, json.dumps(headers))

    def test_signed_diagnostics_uses_bounded_request_metadata(self):
        secret = "s" * 32
        request_id = "worker-diagnostic-1"
        response_body = b'{"ok":true,"action":"diagnostics","diagnostic":{"requestId":"worker-diagnostic-1","action":"provision","category":"database_error","sqlstate":"23505","recordedAt":1}}'

        class Response:
            status = 200

            def getheader(self, name):
                return str(len(response_body)) if name.lower() == "content-length" else None

            def read(self, _size):
                return response_body

        requests = []

        class Connection:
            def __init__(self, *_args, **_kwargs):
                pass

            def request(self, method, path, body, headers):
                requests.append((method, path, body, headers))

            def getresponse(self):
                return Response()

            def close(self):
                return None

        with mock.patch.object(self.tool.http.client, "HTTPConnection", Connection):
            status, _body = self.tool.signed_diagnostic_request(
                3021, secret, request_id, timestamp=1_750_000_000, nonce="b" * 32
            )

        self.assertEqual(status, 200)
        self.assertEqual(requests[0][0:2], ("POST", "/provision"))
        self.assertEqual(json.loads(requests[0][2]), {
            "action": "diagnostics", "requestId": request_id,
        })
        self.assertNotIn(secret, json.dumps(requests[0][3]))

    def test_print_diagnostic_rejects_unbounded_or_private_response_data(self):
        stdout = io.StringIO()
        record = {
            "requestId": "worker-diagnostic-2",
            "action": "provision",
            "category": "database_error",
            "sqlstate": "23505",
            "recordedAt": 1,
            "private": "sk-private-sentinel",
        }
        body = json.dumps({
            "ok": True, "action": "diagnostics", "diagnostic": record,
        }).encode()
        with mock.patch.object(
            self.tool, "signed_diagnostic_request", return_value=(200, body)
        ):
            self.tool.print_diagnostic(
                3021, "s" * 32, "worker-diagnostic-2", stdout=stdout
            )
        self.assertEqual(json.loads(stdout.getvalue()), {
            "requestId": "worker-diagnostic-2",
            "action": "provision",
            "category": "database_error",
            "sqlstate": "23505",
            "recordedAt": 1,
        })
        self.assertNotIn("sk-private-sentinel", stdout.getvalue())

    def test_verify_requires_successful_status_and_rejected_replay(self):
        body = b'{"ok":true,"action":"status","exists":false}'
        with mock.patch.object(
            self.tool,
            "signed_status_request",
            return_value=(200, body, {"x": "y"}, b"request"),
        ), mock.patch.object(self.tool, "replay_request", return_value=401):
            self.tool.verify_signed_status(3022, "s" * 32)

        with mock.patch.object(
            self.tool,
            "signed_status_request",
            return_value=(200, body, {"x": "y"}, b"request"),
        ), mock.patch.object(self.tool, "replay_request", return_value=200):
            with self.assertRaisesRegex(self.tool.CanaryError, "replay"):
                self.tool.verify_signed_status(3022, "s" * 32)

    def test_image_state_round_trip_is_private_and_rejects_symlinks(self):
        image_id = "sha256:" + "a" * 64
        git_head = "b" * 40
        with tempfile.TemporaryDirectory() as directory:
            state_directory = pathlib.Path(directory) / "run-state"
            state_path = state_directory / "sync-image.json"
            with mock.patch.object(self.tool, "STATE_DIRECTORY", state_directory), \
                 mock.patch.object(self.tool, "SYNC_IMAGE_STATE", state_path), \
                 mock.patch.object(self.tool, "STATE_UID", os.geteuid()), \
                 mock.patch.object(self.tool, "STATE_GID", os.getegid()):
                self.tool.write_image_state(image_id, git_head)
                self.assertEqual(stat.S_IMODE(state_directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
                self.assertEqual(
                    self.tool.read_image_state(),
                    {
                        "version": 1,
                        "image": self.tool.SYNC_IMAGE,
                        "image_id": image_id,
                        "git_head": git_head,
                    },
                )
                state_path.unlink()
                target = state_directory / "target"
                target.write_text("{}", encoding="ascii")
                target.chmod(0o600)
                state_path.symlink_to(target)
                with self.assertRaisesRegex(self.tool.CanaryError, "unavailable"):
                    self.tool.read_image_state()

    def test_image_state_rejects_unknown_fields_and_invalid_id(self):
        base = {
            "version": 1,
            "image": self.tool.SYNC_IMAGE,
            "image_id": "sha256:" + "a" * 64,
            "git_head": "b" * 40,
        }
        for mutation in (
            {**base, "unexpected": True},
            {**base, "image_id": "sha256:short"},
            {**base, "git_head": "not-a-commit"},
        ):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(
                self.tool.CanaryError, "state is invalid"
            ):
                self.tool.validate_image_state_payload(json.dumps(mutation).encode())

    def test_local_image_attestation_checks_labels_id_and_psql_without_network(self):
        image_id = "sha256:" + "a" * 64
        labels = json.dumps(self.tool.SYNC_IMAGE_LABELS, sort_keys=True)
        calls = []

        def runner(command, **_kwargs):
            calls.append(command)
            if command[1:3] == ["image", "inspect"]:
                output = f"{image_id}|linux|amd64|{labels}\n".encode()
            elif command[1] == "run":
                output = b"psql (PostgreSQL) 18.4\n"
            else:
                raise AssertionError(command)
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")

        self.assertEqual(
            self.tool.inspect_local_sync_image(
                self.tool.SYNC_IMAGE,
                expected_id=image_id,
                runner=runner,
            ),
            image_id,
        )
        run_command = calls[1]
        self.assertIn("--pull", run_command)
        self.assertEqual(run_command[run_command.index("--pull") + 1], "never")
        self.assertEqual(run_command[run_command.index("--network") + 1], "none")
        self.assertIn("--read-only", run_command)
        self.assertIn(image_id, run_command)
        with self.assertRaisesRegex(self.tool.CanaryError, "identity"):
            self.tool.inspect_local_sync_image(
                self.tool.SYNC_IMAGE,
                expected_id="sha256:" + "c" * 64,
                runner=runner,
            )

    def test_prepare_builds_before_cutover_and_records_exact_git_image_pair(self):
        image_id = "sha256:" + "a" * 64
        git_head = "b" * 40
        commands = []

        def runner(command, **_kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        with mock.patch.object(self.tool, "current_git_head", return_value=git_head), \
             mock.patch.object(
                 self.tool,
                 "inspect_local_sync_image",
                 side_effect=[image_id, image_id],
             ) as inspect_image, \
             mock.patch.object(self.tool, "write_image_state") as write_state:
            self.assertEqual(self.tool.prepare_sync_image(runner=runner), image_id)
        build = commands[0]
        self.assertEqual(build[0:2], ["docker", "build"])
        self.assertIn("--pull", build)
        self.assertIn("--no-cache", build)
        self.assertEqual(build[build.index("--network") + 1], "none")
        self.assertEqual(commands[1][0:3], ["docker", "image", "tag"])
        self.assertEqual(inspect_image.call_count, 2)
        write_state.assert_called_once_with(image_id, git_head)

    def test_prebuilt_image_rejects_a_different_git_revision(self):
        with mock.patch.object(
            self.tool,
            "read_image_state",
            return_value={
                "version": 1,
                "image": self.tool.SYNC_IMAGE,
                "image_id": "sha256:" + "a" * 64,
                "git_head": "b" * 40,
            },
        ), mock.patch.object(self.tool, "current_git_head", return_value="c" * 40), \
             mock.patch.object(self.tool, "inspect_local_sync_image") as inspect_image:
            with self.assertRaisesRegex(self.tool.CanaryError, "Git revision"):
                self.tool.require_prebuilt_sync_image()
        inspect_image.assert_not_called()

    def test_start_profile_forbids_build_and_registry_pull(self):
        calls = []

        def runner(command, **_kwargs):
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        self.tool.start_profile(
            pathlib.Path("/private/env"),
            "sync-canary",
            self.tool.CANARY_CONTAINER,
            {},
            runner=runner,
        )
        command = calls[0]
        self.assertIn("--no-build", command)
        self.assertNotIn("--build", command)
        self.assertEqual(command[command.index("--pull") + 1], "never")

    def test_running_container_must_use_the_recorded_exact_image_id(self):
        image_id = "sha256:" + "a" * 64
        labels = {
            "com.docker.compose.project": "sub2api-gate-sync-canary",
            "com.docker.compose.service": "sub2api-sync-canary",
            "sub2api-gate.request-path": "never-v1",
        }
        metadata = "|".join(
            (
                image_id,
                self.tool.SYNC_IMAGE,
                "true",
                "healthy",
                "65532:65532",
                "true",
                "none",
                "[]",
                json.dumps({self.tool.TARGET_NETWORK: {}}),
                json.dumps(labels),
            )
        ).encode()

        def runner(command, **_kwargs):
            output = metadata if command[1] == "inspect" else b"127.0.0.1:3022\n"
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b"")

        self.tool.inspect_sync_container(
            self.tool.CANARY_CONTAINER,
            self.tool.SYNC_CANARY_PORT,
            image_id,
            runner=runner,
        )
        with self.assertRaisesRegex(self.tool.CanaryError, "runtime contract"):
            self.tool.inspect_sync_container(
                self.tool.CANARY_CONTAINER,
                self.tool.SYNC_CANARY_PORT,
                "sha256:" + "c" * 64,
                runner=runner,
            )

    def test_nonce_runtime_requires_exact_memory_and_noeviction_command(self):
        labels = {
            "com.docker.compose.project": "sub2api-gate-sync-canary",
            "com.docker.compose.service": self.tool.NONCE_REDIS_SERVICE,
        }
        command = [
            "redis-server",
            "--appendonly", "yes",
            "--appendfsync", "always",
            "--save", "",
            "--maxmemory", "32mb",
            "--maxmemory-policy", "noeviction",
        ]
        mounts = [
            {"Source": str(self.tool.DATA_ROOT / "redis" / "nonce")},
            {"Source": str(self.tool.DATA_ROOT / "redis" / "nonce-users.acl")},
        ]
        fields = [
            "true",
            "healthy",
            "999:1000",
            "true",
            "none",
            str(128 * 1024 * 1024),
            json.dumps(command),
            json.dumps(mounts),
            json.dumps({self.tool.TARGET_NETWORK: {}}),
            json.dumps(labels),
        ]

        def runner(_command, **_kwargs):
            return subprocess.CompletedProcess(_command, 0, stdout="|".join(fields).encode())

        self.tool.inspect_nonce_redis(runner=runner)
        fields[5] = "0"
        with self.assertRaisesRegex(self.tool.CanaryError, "runtime contract"):
            self.tool.inspect_nonce_redis(runner=runner)

    def test_promote_stops_legacy_before_3021_and_recovers_on_failure(self):
        events = []

        def systemctl(action, **_kwargs):
            events.append(("systemctl", action))

        def start_profile(*_args, **_kwargs):
            events.append(("start", self.tool.STABLE_CONTAINER))
            raise self.tool.CanaryError("injected")

        with mock.patch.object(self.tool, "inspect_sync_container"), \
             mock.patch.object(self.tool, "inspect_nonce_redis"), \
             mock.patch.object(self.tool, "verify_signed_status"), \
             mock.patch.object(self.tool, "require_legacy_service"), \
             mock.patch.object(self.tool, "systemctl", side_effect=systemctl), \
             mock.patch.object(self.tool, "require_port_free", side_effect=lambda _port: events.append(("port", 3021))), \
             mock.patch.object(self.tool, "start_profile", side_effect=start_profile), \
             mock.patch.object(self.tool, "stop_service"):
            with self.assertRaisesRegex(self.tool.CanaryError, "recovery"):
                self.tool.promote(
                    pathlib.Path("/private/env"),
                    {},
                    "s" * 32,
                    "sha256:" + "a" * 64,
                    runner=lambda *_a, **_k: None,
                )
        self.assertEqual(events[0], ("systemctl", "stop"))
        self.assertIn(("systemctl", "start"), events)
        self.assertLess(events.index(("systemctl", "stop")), events.index(("port", 3021)))

    def test_controller_has_no_nginx_or_v1_mutation_path(self):
        source = TOOL_PATH.read_text(encoding="utf-8").lower()
        self.assertNotIn("nginx", source)
        self.assertNotIn("switch-nginx", source)
        self.assertNotIn("sub2api-upstream", source)
        self.assertNotIn("docker.sock:/", source)
        self.assertNotIn('"--build"', source)
        self.assertIn('"--no-build"', source)


if __name__ == "__main__":
    unittest.main()
