import importlib.util
import http.server
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from contextlib import contextmanager


ROOT = pathlib.Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "sub2api-sync" / "sub2api_sync.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("sub2api_sync_dependency_integration", MODULE_PATH)
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)

POSTGRES_IMAGE = "postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
REDIS_IMAGE = "redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005"
TEST_PASSWORD = "local-sync-dependency-test-password"
SYNC_SECRET = "s" * 32


class LoginUpstream(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, expected):
        self.expected = expected
        self.requests = 0
        super().__init__(("127.0.0.1", 0), LoginHandler)


class LoginHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        body = json.loads(self.rfile.read(length))
        self.server.requests += 1
        if (
            self.path != "/api/v1/auth/login"
            or body.get("email") != self.server.expected["email"]
            or body.get("password") != self.server.expected["password"]
        ):
            payload = {"code": 1}
            status = 401
        else:
            payload = {
                "code": 0,
                "data": {
                    "access_token": "isolated-access-token",
                    "refresh_token": "isolated-refresh-token",
                    "expires_in": 3600,
                    "user": {
                        "id": self.server.expected.get(
                            "response_user_id", self.server.expected["user_id"]
                        ),
                        "username": self.server.expected["username"],
                        "email": self.server.expected["email"],
                        "role": "user",
                        "status": "active",
                    },
                },
            }
            status = 200
        encoded = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        return


@contextmanager
def running_login_upstream(expected):
    server = LoginUpstream(expected)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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
            "SUB2API_SYNC_SECRET": SYNC_SECRET,
            "SUB2API_SYNC_DEFAULT_GROUP": "openai-default",
            "SUB2API_LOGIN_URL": "https://api.example.test",
            "SUB2API_PUBLIC_BASE_URL": "https://api.example.test/v1",
        })

    def _install_sync_schema(self):
        SYNC.psql("""
            CREATE EXTENSION pgcrypto;
            CREATE TABLE users (
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                email text NOT NULL UNIQUE,
                password_hash text NOT NULL,
                role text NOT NULL,
                balance numeric NOT NULL DEFAULT 0,
                concurrency integer NOT NULL DEFAULT 0,
                status text NOT NULL,
                username text NOT NULL UNIQUE,
                notes text,
                deleted_at timestamptz,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now()
            );
            CREATE TABLE groups (
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                name text NOT NULL,
                description text,
                platform text,
                subscription_type text,
                rate_multiplier numeric,
                status text NOT NULL,
                allow_messages_dispatch boolean,
                deleted_at timestamptz,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now()
            );
            CREATE UNIQUE INDEX groups_active_name_idx
                ON groups (name) WHERE deleted_at IS NULL;
            CREATE TABLE subscription_plans (
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                group_id bigint NOT NULL REFERENCES groups(id),
                name text NOT NULL,
                description text,
                price numeric,
                original_price numeric,
                validity_days integer,
                validity_unit text,
                features text,
                product_name text,
                for_sale boolean,
                sort_order integer,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now(),
                UNIQUE (group_id, name)
            );
            CREATE TABLE user_allowed_groups (
                user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                group_id bigint NOT NULL REFERENCES groups(id),
                created_at timestamptz NOT NULL DEFAULT now(),
                PRIMARY KEY (user_id, group_id)
            );
            CREATE TABLE user_subscriptions (
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                group_id bigint NOT NULL REFERENCES groups(id),
                starts_at timestamptz,
                expires_at timestamptz,
                status text,
                assigned_at timestamptz,
                notes text,
                deleted_at timestamptz,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now()
            );
            CREATE UNIQUE INDEX user_subscriptions_active_idx
                ON user_subscriptions (user_id, group_id)
                WHERE deleted_at IS NULL;
            CREATE TABLE api_keys (
                id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                user_id bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                key text NOT NULL UNIQUE,
                name text,
                group_id bigint REFERENCES groups(id),
                status text,
                quota numeric NOT NULL DEFAULT 0,
                quota_used numeric NOT NULL DEFAULT 0,
                expires_at timestamptz,
                deleted_at timestamptz,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now()
            );
            CREATE TABLE sub2api_sync_invite_owners (
                user_id bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                invite_fingerprint char(64) NOT NULL UNIQUE,
                created_at timestamptz NOT NULL DEFAULT now(),
                updated_at timestamptz NOT NULL DEFAULT now()
            );
        """)

    def _scalar(self, sql):
        return SYNC.psql(sql).strip()

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

    def test_invite_identity_lifecycle_uses_real_postgres_and_login_http(self):
        self._install_sync_schema()
        invite_uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11"
        foreign_uuid = "8d595f85-7e04-44e2-a552-11d8e9c5bc22"
        username = "temporary-flow"
        email = "temporary-flow@example.test"
        password = "temporary-password"
        token = "sk-" + "a" * 48

        SYNC.psql(
            "INSERT INTO users "
            "(email,password_hash,role,balance,concurrency,status,username,created_at,updated_at) "
            f"VALUES ({SYNC.sql_quote(email)},crypt({SYNC.sql_quote(password)},gen_salt('bf')),'user',0,5,'active',"
            f"{SYNC.sql_quote(username)},now(),now());"
        )
        legacy_user_id = int(self._scalar(
            f"SELECT id FROM users WHERE username={SYNC.sql_quote(username)};"
        ))
        self.assertEqual(
            self._scalar("SELECT count(*) FROM sub2api_sync_invite_owners;"),
            "0",
        )

        expected = {
            "user_id": legacy_user_id,
            "response_user_id": legacy_user_id + 1,
            "username": username,
            "email": email,
            "password": password,
        }
        os.environ["SUB2API_INTERNAL_LOGIN_URL"] = ""
        with running_login_upstream(expected) as upstream:
            os.environ["SUB2API_INTERNAL_LOGIN_URL"] = (
                f"http://127.0.0.1:{upstream.server_port}/api/v1/auth/login"
            )
            login_payload = {
                "uuid": invite_uuid,
                "username": username,
                "sub2apiUserId": legacy_user_id,
                "email": email,
                "loginPassword": password,
            }
            for rejected in (
                {**login_payload, "username": "different-user"},
                {**login_payload, "email": "different-user@example.test"},
            ):
                with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                    SYNC.login(rejected)
            self.assertEqual(upstream.requests, 0)
            self.assertEqual(
                self._scalar("SELECT count(*) FROM sub2api_sync_invite_owners;"),
                "0",
            )

            with self.assertRaisesRegex(RuntimeError, "sub2api_login_response_identity_mismatch"):
                SYNC.login(login_payload)
            self.assertEqual(upstream.requests, 1)
            expected["response_user_id"] = legacy_user_id
            self.assertEqual(SYNC.login(login_payload)["auth"]["user"]["id"], legacy_user_id)
            self.assertEqual(SYNC.login(login_payload)["auth"]["user"]["id"], legacy_user_id)
            self.assertEqual(upstream.requests, 3)
            self.assertEqual(
                self._scalar("SELECT count(*) FROM sub2api_sync_invite_owners;"),
                "1",
            )

            for rejected in (
                {**login_payload, "uuid": foreign_uuid},
                {**login_payload, "sub2apiUserId": legacy_user_id + 1000},
            ):
                with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                    SYNC.login(rejected)
            self.assertEqual(upstream.requests, 3)

        SYNC.purge({
            "uuid": invite_uuid,
            "username": username,
            "sub2apiUserId": legacy_user_id,
        })
        self.assertEqual(self._scalar("SELECT count(*) FROM users;"), "0")
        self.assertEqual(
            self._scalar("SELECT count(*) FROM sub2api_sync_invite_owners;"),
            "0",
        )

        provision_payload = {
            "uuid": invite_uuid,
            "username": username,
            "email": email,
            "loginPassword": password,
            "tokens": [{"tokenKey": token, "tokenName": "Temporary key"}],
        }
        provisioned = SYNC.provision(provision_payload)
        SYNC.psql(
            "UPDATE groups SET rate_multiplier=2.75 "
            "WHERE name='openai-default' AND deleted_at IS NULL;"
        )
        reprovisioned = SYNC.provision({
            **provision_payload,
            "sub2apiUserId": provisioned["userId"],
        })
        self.assertEqual(reprovisioned["userId"], provisioned["userId"])
        self.assertEqual(reprovisioned["apiKeyId"], provisioned["apiKeyId"])
        self.assertEqual(
            self._scalar(
                "SELECT rate_multiplier FROM groups "
                "WHERE name='openai-default' AND deleted_at IS NULL;"
            ),
            "2.75",
        )
        conflicting_email = "already-used@example.test"
        conflicting_key = "sk-" + "b" * 48
        SYNC.psql(
            "INSERT INTO users "
            "(email,password_hash,role,balance,concurrency,status,username,created_at,updated_at) "
            f"VALUES ({SYNC.sql_quote(conflicting_email)},crypt('temporary-password',gen_salt('bf')),'user',0,5,'active',"
            "'other-active-user',now(),now());"
            "INSERT INTO api_keys "
            "(user_id,key,name,status,quota,quota_used,created_at,updated_at) "
            "SELECT id,"
            f"{SYNC.sql_quote(conflicting_key)},'Other key','active',0,0,now(),now() "
            "FROM users WHERE username='other-active-user';"
        )
        with self.assertRaisesRegex(RuntimeError, "email_conflict"):
            SYNC.provision({
                **provision_payload,
                "sub2apiUserId": provisioned["userId"],
                "email": conflicting_email,
            })
        with self.assertRaisesRegex(RuntimeError, "api_key_conflict"):
            SYNC.provision({
                **provision_payload,
                "sub2apiUserId": provisioned["userId"],
                "tokens": [{"tokenKey": conflicting_key, "tokenName": "Conflict"}],
            })
        self.assertEqual(
            self._scalar(
                f"SELECT email FROM users WHERE id={provisioned['userId']};"
            ),
            email,
        )
        self.assertEqual(
            self._scalar(
                f"SELECT key FROM api_keys WHERE id={provisioned['apiKeyId']};"
            ),
            token,
        )
        status = SYNC.status({
            "uuid": invite_uuid,
            "username": username,
            "sub2apiUserId": provisioned["userId"],
        })
        self.assertTrue(status["exists"])
        self.assertEqual(status["userId"], provisioned["userId"])

        expected["user_id"] = provisioned["userId"]
        expected["response_user_id"] = provisioned["userId"]
        with running_login_upstream(expected) as upstream:
            os.environ["SUB2API_INTERNAL_LOGIN_URL"] = (
                f"http://127.0.0.1:{upstream.server_port}/api/v1/auth/login"
            )
            login_payload = {
                "uuid": invite_uuid,
                "username": username,
                "sub2apiUserId": provisioned["userId"],
                "email": email,
                "loginPassword": password,
            }
            self.assertEqual(SYNC.login(login_payload)["auth"]["user"]["id"], provisioned["userId"])
            self.assertEqual(upstream.requests, 1)

        SYNC.deprovision({
            "uuid": invite_uuid,
            "username": username,
            "sub2apiUserId": provisioned["userId"],
            "sub2apiApiKeyId": provisioned["apiKeyId"],
        })
        SYNC.purge({
            "uuid": invite_uuid,
            "username": username,
            "sub2apiUserId": provisioned["userId"],
            "sub2apiApiKeyId": provisioned["apiKeyId"],
        })
        recreated = SYNC.provision(provision_payload)
        self.assertNotEqual(recreated["userId"], provisioned["userId"])
        self.assertEqual(
            self._scalar("SELECT count(*) FROM sub2api_sync_invite_owners;"),
            "1",
        )
