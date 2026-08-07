import importlib.util
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "sub2api-sync" / "sub2api_sync.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("sub2api_sync_dependency_integration", MODULE_PATH)
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)

POSTGRES_IMAGE = "postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
REDIS_IMAGE = "redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005"
TEST_PASSWORD = "local-sync-dependency-test-password"


def docker(*arguments, **kwargs):
    return subprocess.run(
        [shutil.which("docker") or "docker", *arguments],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        **kwargs,
    )


@unittest.skipUnless(
    os.environ.get("SUB2API_RUN_DEPENDENCY_INTEGRATION") == "1",
    "set SUB2API_RUN_DEPENDENCY_INTEGRATION=1 to run Docker dependency integration",
)
class SyncDependencyIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.suffix = uuid.uuid4().hex
        self.postgres_name = f"sub2api-sync-test-pg-{self.suffix}"
        self.redis_name = f"sub2api-sync-test-redis-{self.suffix}"
        self.temporary = tempfile.TemporaryDirectory(prefix="sub2api-sync-dependency-")
        self.original_environment = os.environ.copy()
        self.postgres_started = False
        self.redis_started = False
        self._start_dependencies()
        self._configure_sync_process()

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.original_environment)
        for name, started in ((self.redis_name, self.redis_started), (self.postgres_name, self.postgres_started)):
            if started:
                subprocess.run(
                    [shutil.which("docker") or "docker", "rm", "--force", name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
        self.temporary.cleanup()

    def _start_dependencies(self):
        docker(
            "run", "--detach", "--rm", "--name", self.postgres_name,
            "--env", "POSTGRES_USER=sync_test",
            "--env", f"POSTGRES_PASSWORD={TEST_PASSWORD}",
            "--env", "POSTGRES_DB=sync_test",
            POSTGRES_IMAGE,
        )
        self.postgres_started = True
        docker(
            "run", "--detach", "--rm", "--name", self.redis_name,
            "--publish", "127.0.0.1::6379",
            REDIS_IMAGE,
            "redis-server", "--save", "", "--appendonly", "no",
            "--requirepass", TEST_PASSWORD,
        )
        self.redis_started = True
        self._wait_for_postgres()
        self.redis_port = self._mapped_port(self.redis_name, "6379/tcp")
        self._wait_for_redis()

    def _wait_for_postgres(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            result = subprocess.run(
                [
                    shutil.which("docker") or "docker", "exec",
                    "-e", f"PGPASSWORD={TEST_PASSWORD}", self.postgres_name,
                    "psql", "--host", "127.0.0.1", "--username", "sync_test",
                    "--dbname", "sync_test", "--no-psqlrc", "--quiet",
                    "--tuples-only", "--no-align", "--command", "SELECT 1;",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                return
            time.sleep(0.2)
        self.fail("temporary PostgreSQL did not become ready")

    def _wait_for_redis(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.redis_port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.1)
        self.fail("temporary Redis did not become ready")

    def _mapped_port(self, container, container_port):
        value = docker("port", container, container_port).stdout.strip()
        host, separator, port = value.rpartition(":")
        if not separator or host not in {"127.0.0.1", "[::1]"}:
            self.fail("temporary Redis did not bind to loopback")
        return int(port)

    def _configure_sync_process(self):
        wrapper = pathlib.Path(self.temporary.name) / "psql"
        wrapper.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "exec \"$SYNC_TEST_DOCKER\" exec -i -e \"PGPASSWORD=$PGPASSWORD\" \"$SYNC_TEST_POSTGRES\" psql \"$@\"\n",
            encoding="ascii",
        )
        wrapper.chmod(0o700)
        os.environ.update({
            "PATH": f"{self.temporary.name}:{self.original_environment.get('PATH', '')}",
            "SYNC_TEST_DOCKER": shutil.which("docker") or "docker",
            "SYNC_TEST_POSTGRES": self.postgres_name,
            "SUB2API_SYNC_DATABASE_HOST": "127.0.0.1",
            "SUB2API_SYNC_DATABASE_PORT": "5432",
            "SUB2API_SYNC_DATABASE_NAME": "sync_test",
            "SUB2API_SYNC_DATABASE_USER": "sync_test",
            "SUB2API_SYNC_DATABASE_PASSWORD": TEST_PASSWORD,
            "SUB2API_SYNC_REDIS_HOST": "127.0.0.1",
            "SUB2API_SYNC_REDIS_PORT": str(self.redis_port),
            "SUB2API_SYNC_REDIS_PASSWORD": TEST_PASSWORD,
            "SUB2API_SYNC_REDIS_USERNAME": "",
        })

    def test_postgres_transaction_and_timeout_recovery_use_real_psql(self):
        direct = docker(
            "exec", "-e", f"PGPASSWORD={TEST_PASSWORD}", self.postgres_name,
            "psql", "--host", "127.0.0.1", "--port", "5432",
            "--username", "sync_test", "--dbname", "sync_test",
            "--no-psqlrc", "--quiet", "--tuples-only", "--no-align",
            "--field-separator", "\t", "--set", "ON_ERROR_STOP=1",
            "--command", "SELECT 42;",
        )
        self.assertEqual(direct.stdout.strip(), "42")
        self.assertEqual(SYNC.psql("SELECT 42;"), "42")
        with SYNC.database_transaction(timeout=2) as transaction:
            self.assertEqual(transaction.execute("SELECT 7;"), "7")

        with self.assertRaises(subprocess.TimeoutExpired):
            with SYNC.database_transaction(timeout=0.05) as transaction:
                transaction.execute("SELECT pg_sleep(0.2);")

        self.assertEqual(SYNC.psql("SELECT 1;"), "1")

    def test_redis_protocol_authentication_and_timeout_recovery_use_real_redis(self):
        key = f"sync-test:{self.suffix}"
        self.assertEqual(SYNC.redis_command("SET", key, "ok", timeout=1), "OK")
        self.assertEqual(SYNC.redis_command("GET", key, timeout=1), "ok")
        self.assertEqual(SYNC.redis_command("CLIENT", "PAUSE", "200", timeout=1), "OK")
        with self.assertRaises((socket.timeout, TimeoutError)):
            SYNC.redis_command("PING", timeout=0.05)
        self.assertEqual(SYNC.redis_command("PING", timeout=1), "PONG")
