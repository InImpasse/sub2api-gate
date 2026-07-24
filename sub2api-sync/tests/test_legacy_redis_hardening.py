import importlib.util
import io
import json
import os
import pathlib
import stat
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "deploy" / "harden-legacy-redis.py"

OLD_PASSWORD = "O" * 32
NEW_PASSWORD = "N" * 32
APP_OLD = "a" * 64
REDIS_OLD = "b" * 64
APP_HARDENED = "c" * 64
REDIS_HARDENED = "d" * 64
APP_ROLLED_BACK = "e" * 64
REDIS_ROLLED_BACK = "f" * 64
APP_IMAGE = "sha256:" + "1" * 64
REDIS_IMAGE = "sha256:" + "2" * 64

SOURCE_COMPOSE = """services:
  sub2api:
    image: example/sub2api:reviewed
    container_name: sub2api
    environment:
      - REDIS_HOST=redis
      - REDIS_PASSWORD=${REDIS_PASSWORD:?required}
  redis:
    image: redis:7-alpine
    container_name: sub2api-redis
    command: >
      sh -c 'exec redis-server --appendonly yes --save 60 1 ${REDIS_PASSWORD:+--requirepass "$REDIS_PASSWORD"}'
    volumes:
      - ./redis_data:/data
"""


def load_tool():
    name = "legacy_redis_hardening_test_module"
    spec = importlib.util.spec_from_file_location(name, TOOL)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


class FakeRunner:
    def __init__(self, tool, paths, *, fail_hardened_app=False):
        self.tool = tool
        self.paths = paths
        self.fail_hardened_app = fail_hardened_app
        self.calls = []
        self.containers = {
            "sub2api": {
                "identity": APP_OLD,
                "running": True,
                "health": "healthy",
                "image": "example/sub2api:reviewed",
                "image_identity": APP_IMAGE,
                "service": "sub2api",
            },
            "sub2api-redis": {
                "identity": REDIS_OLD,
                "running": True,
                "health": "healthy",
                "image": "redis:7-alpine",
                "image_identity": REDIS_IMAGE,
                "service": "redis",
            },
        }

    def hardened(self):
        return b"--aclfile" in self.paths.compose_file.read_bytes()

    def find(self, reference):
        for name, container in self.containers.items():
            if reference in {name, container["identity"]}:
                return name, container
        raise AssertionError(f"unexpected container reference: {reference}")

    def metadata(self, name, container):
        running = "true" if container["running"] else "false"
        return (
            f"{container['identity']}|/{name}|{running}|{container['health']}|"
            f"{container['image']}|{container['image_identity']}|"
            f"sub2api-deploy|{container['service']}"
        ).encode("utf-8")

    def json_inspect(self, name, template):
        hardened = self.hardened()
        if template == "{{json .NetworkSettings.Ports}}":
            if name == "sub2api":
                return {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}
            return {}
        if template == "{{json .NetworkSettings.Networks}}":
            return {"sub2api-deploy_default": {"IPAddress": "172.19.0.10"}}
        if template == "{{json .Mounts}}":
            if name != "sub2api-redis":
                raise AssertionError("only Redis mount metadata is expected")
            if hardened:
                return [
                    {
                        "Type": "bind",
                        "Source": str(self.paths.acl_file),
                        "Destination": "/etc/redis/users.acl",
                        "RW": False,
                    }
                ]
            return [
                {
                    "Type": "bind",
                    "Source": str(self.paths.redis_data),
                    "Destination": "/data",
                    "RW": True,
                }
            ]
        if template == "{{json .Config.Cmd}}":
            if not hardened:
                raise AssertionError("legacy Redis command is not inspected after rollback")
            return ["redis-server", "--aclfile", "/etc/redis/users.acl", "--save", ""]
        if template == "{{json .HostConfig}}":
            if not hardened:
                raise AssertionError("legacy Redis host config is not inspected after rollback")
            return {
                "ReadonlyRootfs": True,
                "Tmpfs": {"/data": "rw,noexec,nosuid,nodev"},
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
            }
        raise AssertionError(f"unexpected inspect template: {template}")

    def update_service(self, service):
        hardened = self.hardened()
        if service == "redis":
            self.containers["sub2api-redis"].update(
                identity=REDIS_HARDENED if hardened else REDIS_ROLLED_BACK,
                running=True,
                health="healthy" if hardened else "none",
            )
            return
        if service == "sub2api":
            if hardened and self.fail_hardened_app:
                raise self.tool.CommandError("simulated service failure")
            self.containers["sub2api"].update(
                identity=APP_HARDENED if hardened else APP_ROLLED_BACK,
                running=True,
                health="healthy",
            )
            return
        raise AssertionError(f"unexpected Compose service: {service}")

    def __call__(self, argv, *, timeout, environment, input_data, allow_failure):
        argv = tuple(str(value) for value in argv)
        self.calls.append((argv, dict(environment), input_data, allow_failure))
        for value in (OLD_PASSWORD, NEW_PASSWORD):
            self_test = "\0".join(argv) + "\0" + "\0".join(environment.values())
            if value in self_test:
                raise AssertionError("a Redis password reached argv or environment")
        for selector in (
            "DOCKER_CONTEXT",
            "DOCKER_TLS",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CERT_PATH",
            "DOCKER_API_VERSION",
        ):
            if selector in environment:
                raise AssertionError("a Docker endpoint selector was inherited")
        if "exec" in argv:
            self.assert_no_password_in_exec_argv(argv)
            return self.tool.CommandResult(0, b"errors: 0, replies: 2\n")
        if "inspect" in argv:
            template = argv[argv.index("--format") + 1]
            name, container = self.find(argv[-1])
            if template.startswith("{{.Id}}|"):
                return self.tool.CommandResult(0, self.metadata(name, container))
            return self.tool.CommandResult(
                0,
                json.dumps(self.json_inspect(name, template), separators=(",", ":")).encode("utf-8"),
            )
        if "compose" in argv:
            if "stop" in argv:
                for service, name in (("sub2api", "sub2api"), ("redis", "sub2api-redis")):
                    if service in argv:
                        self.containers[name]["running"] = False
                return self.tool.CommandResult(0)
            if "up" in argv:
                self.update_service(argv[-1])
                return self.tool.CommandResult(0)
            if "config" in argv:
                return self.tool.CommandResult(0)
        raise AssertionError(f"unexpected command: {argv}")

    @staticmethod
    def assert_no_password_in_exec_argv(argv):
        if any("--pass" in value or "--requirepass" in value for value in argv):
            raise AssertionError("Redis password was sent through a Docker exec argument")


class LegacyRedisHardeningTests(unittest.TestCase):
    def test_controller_uses_isolated_system_python(self):
        self.assertEqual(
            TOOL.read_text(encoding="utf-8").splitlines()[0], "#!/usr/bin/python3 -I"
        )

    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def make_paths(self, directory):
        root = pathlib.Path(directory)
        legacy = root / "sub2api-deploy"
        private = root / "private"
        runtime_parent = root / "run" / "sub2api-gate"
        legacy.mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        runtime_parent.mkdir(parents=True, mode=0o700)
        redis_data = legacy / "redis_data"
        redis_data.mkdir(mode=0o700)
        compose = legacy / "docker-compose.local.yml"
        environment = legacy / ".env"
        compose.write_text(SOURCE_COMPOSE, encoding="utf-8")
        environment.write_text(
            f"REDIS_PASSWORD={OLD_PASSWORD}\nJWT_SECRET={'J' * 32}\n",
            encoding="ascii",
        )
        compose.chmod(0o600)
        environment.chmod(0o600)
        return self.tool.HardeningPaths(
            legacy_root=legacy,
            compose_file=compose,
            env_file=environment,
            redis_data=redis_data,
            private_root=private,
            state_dir=private / "legacy-redis-hardening",
            acl_dir=private / "legacy-redis",
            acl_file=private / "legacy-redis" / "users.acl",
            docker_socket=root / "docker.sock",
            docker_config_dir=runtime_parent / "legacy-redis-docker",
        )

    def make_hardener(self, paths, runner):
        hardener = self.tool.LegacyRedisHardener(
            paths=paths,
            runner=runner,
            password_reader=lambda: (OLD_PASSWORD, NEW_PASSWORD),
            health_probe=lambda: None,
            sleep=lambda _seconds: None,
            owner_uid=os.geteuid(),
            owner_gid=os.getegid(),
            source_path_validator=lambda *_arguments, **_keywords: None,
        )
        hardener._pin_docker_socket = lambda: None
        hardener._validate_docker_binary = lambda: None
        return hardener

    def test_check_mode_is_offline_and_secret_free(self):
        calls = []
        output = io.StringIO()

        def runner(*arguments, **kwargs):
            calls.append((arguments, kwargs))
            raise AssertionError("check mode must not invoke a command")

        code = self.tool.main(["check"], runner=runner, stdout=output)
        self.assertEqual(code, 0)
        self.assertIn("no private file was read", output.getvalue())
        self.assertFalse(calls)
    def test_apply_rejects_non_tty_stdout_before_release_actions(self):
        class Terminal(io.StringIO):
            def __init__(self, tty):
                super().__init__()
                self.tty = tty

            def isatty(self):
                return self.tty

        arguments = [
            "--apply",
            "--source-app-container",
            "sub2api",
            "--source-app-id",
            APP_OLD,
            "--source-redis-container",
            "sub2api-redis",
            "--source-redis-id",
            REDIS_OLD,
        ]
        stdin = Terminal(True)
        stdout = Terminal(False)
        stderr = Terminal(True)
        original_geteuid = self.tool.os.geteuid
        guard_calls = []
        self.tool.os.geteuid = lambda: 0
        try:
            code = self.tool.main(
                arguments,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                release_guard=lambda _runner: guard_calls.append(True),
            )
        finally:
            self.tool.os.geteuid = original_geteuid
        self.assertEqual(code, 1)
        self.assertFalse(guard_calls)


    def test_transform_replaces_shell_password_and_persistent_data(self):
        contract = self.tool.transform_compose(SOURCE_COMPOSE.encode("utf-8"))
        rendered = contract.hardened_compose.decode("utf-8")
        redis_block = rendered.split("  redis:\n", 1)[1]
        self.assertEqual(contract.redis_image, "redis:7-alpine")
        self.assertNotIn("sh -c", redis_block)
        self.assertNotIn("--requirepass", redis_block)
        self.assertNotIn("${REDIS_PASSWORD", redis_block)
        self.assertNotIn("./redis_data", redis_block)
        self.assertIn("--aclfile", redis_block)
        self.assertIn("/data:rw,noexec,nosuid,nodev", redis_block)
        self.assertIn("read_only: true", redis_block)
        self.assertIn("no-new-privileges:true", redis_block)
        self.assertIn("NOAUTH Authentication required", redis_block)

    def test_transform_rejects_unreviewed_legacy_contracts(self):
        unsafe_port = SOURCE_COMPOSE.replace(
            "    volumes:\n", "    ports:\n      - \"6379:6379\"\n    volumes:\n"
        )
        missing_marker = SOURCE_COMPOSE.replace(
            '${REDIS_PASSWORD:+--requirepass "$REDIS_PASSWORD"}', ""
        )
        for source in (unsafe_port, missing_marker):
            with self.subTest(source=source[:48]):
                with self.assertRaises(self.tool.LegacyRedisHardeningError):
                    self.tool.transform_compose(source.encode("utf-8"))

    def test_acl_and_environment_keep_passwords_out_of_rendered_policy(self):
        acl = self.tool.render_acl(NEW_PASSWORD)
        self.assertNotIn(NEW_PASSWORD, acl)
        self.assertRegex(acl, r"#[0-9a-f]{64}")
        replacement = self.tool.replace_legacy_redis_password(
            f"REDIS_PASSWORD={OLD_PASSWORD}\nJWT_SECRET={'J' * 32}\n".encode("ascii"),
            NEW_PASSWORD,
        )
        self.assertIn(f"REDIS_PASSWORD={NEW_PASSWORD}".encode("ascii"), replacement)
        with self.assertRaises(self.tool.LegacyRedisHardeningError):
            self.tool.parse_legacy_environment(
                f"REDIS_PASSWORD={OLD_PASSWORD}\nDOCKER_HOST=unix:///bad.sock\n".encode("ascii")
            )

    def test_docker_environment_ignores_remote_context_selectors(self):
        environment = self.tool._process_environment(
            {
                "PATH": "/unsafe/bin",
                "DOCKER_HOST": "tcp://remote.invalid:2376",
                "DOCKER_CONTEXT": "remote",
                "DOCKER_TLS_VERIFY": "1",
                "DOCKER_CERT_PATH": "/secrets",
            },
            docker_config_dir=pathlib.Path("/run/sub2api-gate/isolated"),
        )
        self.assertEqual(environment["DOCKER_HOST"], "unix:///var/run/docker.sock")
        self.assertEqual(environment["DOCKER_CONFIG"], "/run/sub2api-gate/isolated")
        self.assertEqual(environment["PATH"], self.tool.SAFE_PROCESS_PATH)
        self.assertEqual(environment["LANG"], "C.UTF-8")
        self.assertEqual(environment["LC_ALL"], "C.UTF-8")
        self.assertEqual(environment["TZ"], "UTC")
        self.assertNotIn("DOCKER_CONTEXT", environment)
        self.assertNotIn("DOCKER_TLS_VERIFY", environment)
        self.assertNotIn("DOCKER_CERT_PATH", environment)

    def test_docker_binary_requires_root_controlled_nonwritable_absolute_file(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = pathlib.Path(directory) / "docker"
            binary.write_bytes(b"#!/bin/sh\n")
            binary.chmod(0o755)
            self.assertEqual(
                self.tool._require_trusted_docker_binary(binary, expected_uid=os.geteuid()),
                binary,
            )
            binary.chmod(0o775)
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                self.tool._require_trusted_docker_binary(binary, expected_uid=os.geteuid())

    def test_controller_uses_fixed_absolute_docker_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.make_paths(directory)
            hardener = self.make_hardener(paths, FakeRunner(self.tool, paths))
            self.assertEqual(hardener._docker_argv("version")[0], str(self.tool.DOCKER_BINARY))
            self.assertTrue(pathlib.PurePath(hardener._docker_argv("version")[0]).is_absolute())

    def test_untrusted_workspace_is_not_a_production_release_tree(self):
        with self.assertRaises(self.tool.LegacyRedisHardeningError):
            self.tool._require_trusted_release_tree()
        main_source = TOOL.read_text(encoding="utf-8").split("def main(", 1)[1]
        self.assertLess(main_source.index("_require_trusted_release_tree()"), main_source.index("release_guard(runner)"))
    def test_trusted_release_tree_checks_parent_and_guard_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory) / "opt"
            trusted = parent / "sub2api-gate-release"
            deploy = trusted / "deploy"
            deploy.mkdir(parents=True)
            controller = deploy / "harden-legacy-redis.py"
            guard = deploy / "require-clean-worktree.sh"
            controller.write_text("# reviewed\n", encoding="utf-8")
            guard.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            parent.chmod(0o755)
            trusted.chmod(0o755)
            deploy.chmod(0o755)
            controller.chmod(0o644)
            guard.chmod(0o755)
            arguments = {
                "repo_dir": trusted,
                "trusted_root": trusted,
                "source_path": controller,
                "release_guard": guard,
                "expected_uid": os.geteuid(),
            }
            self.tool._require_trusted_release_tree(**arguments)
            guard.chmod(0o644)
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                self.tool._require_trusted_release_tree(**arguments)
            guard.chmod(0o755)
            parent.chmod(0o775)
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                self.tool._require_trusted_release_tree(**arguments)


    def test_trusted_legacy_source_chain_rejects_writable_or_symlinked_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            trusted_root = pathlib.Path(directory) / "trusted-root"
            source = trusted_root / "home" / "ubuntu" / "sub2api-deploy"
            source.mkdir(parents=True)
            for candidate in (
                trusted_root,
                trusted_root / "home",
                trusted_root / "home" / "ubuntu",
                source,
            ):
                candidate.chmod(0o755)
            self.tool._require_trusted_directory_chain(
                source,
                expected_uid=os.geteuid(),
                root=trusted_root,
            )
            (trusted_root / "home" / "ubuntu").chmod(0o775)
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                self.tool._require_trusted_directory_chain(
                    source,
                    expected_uid=os.geteuid(),
                    root=trusted_root,
                )

            linked = trusted_root / "alias"
            linked.symlink_to(trusted_root / "home", target_is_directory=True)
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                self.tool._require_trusted_directory_chain(
                    linked / "ubuntu" / "sub2api-deploy",
                    expected_uid=os.geteuid(),
                    root=trusted_root,
                )

    def test_source_path_gate_runs_before_docker_or_private_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.make_paths(directory)
            calls = []

            def reject_source_path(*_arguments, **_keywords):
                calls.append("source")
                raise self.tool.LegacyRedisHardeningError("unsafe test source")

            hardener = self.tool.LegacyRedisHardener(
                paths=paths,
                runner=lambda *_arguments, **_keywords: calls.append("runner"),
                password_reader=lambda: calls.append("password"),
                owner_uid=os.geteuid(),
                owner_gid=os.getegid(),
                source_path_validator=reject_source_path,
            )
            hardener._validate_docker_binary = lambda: calls.append("docker")
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                hardener.apply(APP_OLD, REDIS_OLD)
            self.assertEqual(calls, ["source"])


    def test_health_probe_requires_200_and_closes_a_bounded_response(self):
        class FakeResponse:
            status = 503

            def __init__(self):
                self.read_sizes = []

            def read(self, amount):
                self.read_sizes.append(amount)
                return b"unhealthy"

        class FakeConnection:
            instances = []

            def __init__(self, *_arguments, **_keywords):
                self.response = FakeResponse()
                self.closed = False
                type(self).instances.append(self)

            def request(self, *arguments, **keywords):
                self.request_arguments = (arguments, keywords)

            def getresponse(self):
                return self.response

            def close(self):
                self.closed = True

        original_connection = self.tool.http.client.HTTPConnection
        self.tool.http.client.HTTPConnection = FakeConnection
        try:
            hardener = self.tool.LegacyRedisHardener(paths=None)
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                hardener._probe_app_health()
        finally:
            self.tool.http.client.HTTPConnection = original_connection
        connection = FakeConnection.instances[0]
        self.assertEqual(connection.response.read_sizes, [1024])
        self.assertTrue(connection.closed)
        self.assertEqual(connection.request_arguments[0][:2], ("GET", "/health"))
    def test_source_compose_and_environment_must_be_controller_owned_mode_0600(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.make_paths(directory)
            runner = FakeRunner(self.tool, paths)
            hardener = self.make_hardener(paths, runner)
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                self.tool._stat_regular(paths.compose_file, maximum_bytes=1024, expected_uid=os.geteuid() + 1, expected_mode=0o600)
            paths.env_file.chmod(0o640)
            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                hardener.apply(APP_OLD, REDIS_OLD)
            self.assertFalse(runner.calls)
            validation_source = TOOL.read_text(encoding="utf-8").split("def _validate_paths", 1)[1].split("def _take_source_control", 1)[0]
            self.assertGreaterEqual(validation_source.count("expected_uid=self.owner_uid"), 2)
            self.assertGreaterEqual(validation_source.count("expected_mode=0o600"), 2)


    def test_apply_rotates_password_without_argv_or_environment_leakage(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.make_paths(directory)
            runner = FakeRunner(self.tool, paths)
            hardener = self.make_hardener(paths, runner)

            hardener.apply(APP_OLD, REDIS_OLD)

            acl = paths.acl_file.read_text(encoding="ascii")
            self.assertNotIn(NEW_PASSWORD, acl)
            self.assertRegex(acl, r"#[0-9a-f]{64}")
            self.assertEqual(stat.S_IMODE(paths.acl_file.stat().st_mode), 0o400)
            self.assertNotIn("--requirepass", paths.compose_file.read_text(encoding="utf-8"))
            self.assertNotIn("redis_data", paths.compose_file.read_text(encoding="utf-8"))
            self.assertIn(f"REDIS_PASSWORD={NEW_PASSWORD}", paths.env_file.read_text(encoding="ascii"))
            self.assertEqual(stat.S_IMODE(paths.legacy_root.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(paths.redis_data.stat().st_mode), 0o700)
            self.assertEqual(list(paths.state_dir.iterdir()), [])
            self.assertTrue(any(call[2] is not None for call in runner.calls))

    def test_apply_failure_restores_legacy_compose_environment_and_services(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = self.make_paths(directory)
            runner = FakeRunner(self.tool, paths, fail_hardened_app=True)
            hardener = self.make_hardener(paths, runner)

            with self.assertRaises(self.tool.LegacyRedisHardeningError):
                hardener.apply(APP_OLD, REDIS_OLD)

            restored_compose = paths.compose_file.read_text(encoding="utf-8")
            restored_environment = paths.env_file.read_text(encoding="ascii")
            self.assertIn("sh -c", restored_compose)
            self.assertIn("--requirepass", restored_compose)
            self.assertIn(f"REDIS_PASSWORD={OLD_PASSWORD}", restored_environment)
            self.assertEqual(list(paths.state_dir.iterdir()), [])
            self.assertFalse(paths.acl_file.exists())
            self.assertEqual(runner.containers["sub2api"]["identity"], APP_ROLLED_BACK)
            self.assertEqual(runner.containers["sub2api-redis"]["identity"], REDIS_ROLLED_BACK)

    def test_cli_accepts_only_fixed_source_container_names_and_full_ids(self):
        mode, options = self.tool.parse_arguments(
            [
                "--apply",
                "--source-app-container",
                "sub2api",
                "--source-app-id",
                APP_OLD,
                "--source-redis-container",
                "sub2api-redis",
                "--source-redis-id",
                REDIS_OLD,
            ]
        )
        self.assertEqual(mode, "--apply")
        self.assertEqual(options.source_app_id, APP_OLD)
        with self.assertRaises(self.tool.UsageError):
            self.tool.parse_arguments(
                [
                    "--apply",
                    "--source-app-container",
                    "another-app",
                    "--source-app-id",
                    APP_OLD,
                    "--source-redis-container",
                    "sub2api-redis",
                    "--source-redis-id",
                    REDIS_OLD,
                ]
            )


if __name__ == "__main__":
    unittest.main()
