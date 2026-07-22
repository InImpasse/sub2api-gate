import importlib.util
import io
import json
import os
import pathlib
import subprocess
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
CANARY_CLIENT = ROOT / "deploy" / "run-v1-responses-canary.py"
CANARY_COMPOSE = ROOT / "docker-compose.canary.yml"


def load_client():
    spec = importlib.util.spec_from_file_location("v1_responses_canary", CANARY_CLIENT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TtyBuffer(io.StringIO):
    def isatty(self):
        return True


class FakeResponse:
    def __init__(self, body, *, status=200, headers=None, chunks=None):
        self.status = status
        self.headers = {key.lower(): value for key, value in (headers or {}).items()}
        self.chunks = list(chunks) if chunks is not None else [body, b""]
        self.read_calls = 0
        self.closed = False

    def getheader(self, name):
        return self.headers.get(name.lower())

    def read(self, _size):
        self.read_calls += 1
        return self.chunks.pop(0) if self.chunks else b""

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.request_call = None
        self.closed = False
        self.sock = None

    def request(self, method, path, body, headers):
        self.request_call = (method, path, bytes(body), dict(headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class SyntheticCanaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = load_client()

    def test_default_check_is_offline_and_does_not_read_any_key(self):
        stdout = io.StringIO()

        def forbidden(*_args, **_kwargs):
            raise AssertionError("offline check attempted a secret read or network call")

        result = self.client.main(
            [],
            password_reader=forbidden,
            request_runner=forbidden,
            release_guard=forbidden,
            stdin=io.StringIO(),
            stdout=stdout,
            stderr=io.StringIO(),
        )
        self.assertEqual(result, 0)
        self.assertIn("no API key was read", stdout.getvalue())
        self.assertIn("no network connection was opened", stdout.getvalue())

    def test_default_check_ignores_api_key_environment_variables(self):
        env = os.environ.copy()
        env["OPENAI_API_KEY"] = "environment-secret-must-not-be-read"
        env["SUB2API_API_KEY"] = "second-environment-secret"
        result = subprocess.run(
            [CANARY_CLIENT, "check"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertNotIn("environment-secret", result.stdout + result.stderr)
        self.assertIn("no network connection was opened", result.stdout)

    def test_url_policy_allows_only_loopback_http_or_approved_https(self):
        for url in (
            "http://127.0.0.1:8081/v1/responses",
            "http://[::1]:8081/v1/responses",
        ):
            with self.subTest(url=url):
                self.client.validate_endpoint(url)
        endpoint = self.client.validate_endpoint(
            "https://gateway.example.test/v1/responses",
            {"gateway.example.test"},
        )
        self.assertEqual(endpoint.hostname, "gateway.example.test")

        rejected = (
            ("http://gateway.example.test/v1/responses", {"gateway.example.test"}),
            ("http://localhost:8081/v1/responses", {"gateway.example.test"}),
            ("https://gateway.example.test/v1/responses", set()),
            ("https://sub.gateway.example.test/v1/responses", {"gateway.example.test"}),
            ("https://127.0.0.1/v1/responses", {"gateway.example.test"}),
            ("ftp://gateway.example.test/v1/responses", {"gateway.example.test"}),
            ("http://127.0.0.1:8081/v1/responses/", {"gateway.example.test"}),
            ("http://127.0.0.1:8081/v1/responses?debug=1", {"gateway.example.test"}),
            ("http://user:password@127.0.0.1:8081/v1/responses", {"gateway.example.test"}),
        )
        for url, approved_hostnames in rejected:
            with self.subTest(url=url):
                with self.assertRaises(self.client.CanaryUsageError):
                    self.client.validate_endpoint(url, approved_hostnames)

    def test_apply_requires_model_private_tty_and_clean_release_before_key_read(self):
        reads = []

        def password_reader(_prompt):
            reads.append(True)
            return "private-key"

        with self.assertRaises(self.client.CanaryError):
            self.client.main(
                ["--apply", "--model", "model-test"],
                password_reader=password_reader,
                release_guard=lambda: None,
                stdin=io.StringIO(),
                stdout=io.StringIO(),
                stderr=io.StringIO(),
            )
        self.assertEqual(reads, [])

        with self.assertRaises(self.client.CanaryError):
            self.client.main(
                ["--apply", "--model", "model-test"],
                password_reader=password_reader,
                release_guard=lambda: (_ for _ in ()).throw(
                    self.client.CanaryError("dirty")
                ),
                stdin=TtyBuffer(),
                stdout=io.StringIO(),
                stderr=TtyBuffer(),
            )
        self.assertEqual(reads, [])

    def test_apply_reads_key_only_from_getpass_and_outputs_metadata_only(self):
        stdout = io.StringIO()
        stderr = TtyBuffer()
        observed = {}
        metadata = {
            "status": 200,
            "request_id": "req-safe",
            "input_tokens": 2,
            "output_tokens": 1,
            "total_tokens": 3,
            "total_cost": "0.0003",
            "actual_cost": "0.0002",
            "latency_ms": 75,
        }

        def runner(endpoint, model, api_key):
            observed.update(endpoint=endpoint, model=model, api_key=api_key)
            return metadata

        with mock.patch.dict(
            os.environ,
            {"OPENAI_API_KEY": "wrong-environment-key", "SUB2API_API_KEY": "also-wrong"},
        ):
            result = self.client.main(
                ["--apply", "--model", "model-test"],
                password_reader=lambda _prompt: "tty-only-api-key",
                request_runner=runner,
                release_guard=lambda: None,
                stdin=TtyBuffer(),
                stdout=stdout,
                stderr=stderr,
            )
        self.assertEqual(result, 0)
        self.assertEqual(observed["api_key"], "tty-only-api-key")
        self.assertEqual(observed["model"], "model-test")
        self.assertEqual(json.loads(stdout.getvalue()), metadata)
        combined = stdout.getvalue() + stderr.getvalue()
        for forbidden in ("tty-only-api-key", "wrong-environment-key", "also-wrong"):
            self.assertNotIn(forbidden, combined)

    def test_main_filters_unexpected_fields_before_printing(self):
        stdout = io.StringIO()
        metadata = {
            "status": 200,
            "request_id": "req-safe",
            "input_tokens": 1,
            "output_tokens": 1,
            "total_tokens": 2,
            "total_cost": None,
            "actual_cost": None,
            "latency_ms": 10,
            "response_body": "private response content",
        }
        result = self.client.main(
            ["--apply", "--model", "model-test"],
            password_reader=lambda _prompt: "tty-only-api-key",
            request_runner=lambda *_args: metadata,
            release_guard=lambda: None,
            stdin=TtyBuffer(),
            stdout=stdout,
            stderr=TtyBuffer(),
        )
        self.assertEqual(result, 0)
        rendered = stdout.getvalue()
        self.assertNotIn("response_body", rendered)
        self.assertNotIn("private response content", rendered)

    def test_main_preserves_null_for_absent_response_metadata_headers(self):
        stdout = io.StringIO()
        metadata = {
            "status": 200,
            "request_id": None,
            "input_tokens": None,
            "output_tokens": None,
            "total_tokens": None,
            "total_cost": None,
            "actual_cost": None,
            "latency_ms": 10,
        }
        result = self.client.main(
            ["--apply", "--model", "model-test"],
            password_reader=lambda _prompt: "tty-only-api-key",
            request_runner=lambda *_args: metadata,
            release_guard=lambda: None,
            stdin=TtyBuffer(),
            stdout=stdout,
            stderr=TtyBuffer(),
        )
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue()), metadata)

    def test_api_key_command_line_is_rejected_without_echoing_its_value(self):
        result = subprocess.run(
            [CANARY_CLIENT, "--apply", "--api-key=must-not-appear"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("must-not-appear", result.stdout + result.stderr)

    def test_success_drains_private_body_and_uses_only_allowlisted_headers(self):
        body = json.dumps({
            "id": "response-private-value",
            "output": [{"content": [{"text": "private response content"}]}],
            "usage": {
                "input_tokens": "private-body-must-never-be-parsed",
                "output_tokens": 999999,
                "total_tokens": 999999,
                "total_cost": "999999",
                "actual_cost": "999999",
            },
        }).encode()
        response = FakeResponse(body, headers={
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body)),
            "X-Request-ID": "req-canary-test",
            "X-Sub2API-Input-Tokens": "4",
            "X-Sub2API-Output-Tokens": "2",
            "X-Sub2API-Total-Tokens": "6",
            "X-Sub2API-Total-Cost": "0.004",
            "X-Sub2API-Actual-Cost": "0.003",
        }, chunks=[body[:31], body[31:79], body[79:], b""])
        connection = FakeConnection(response)
        endpoint = self.client.validate_endpoint(self.client.DEFAULT_URL)
        metadata = self.client.perform_canary(
            endpoint,
            "model-test",
            "private-api-key",
            connection_factory=lambda _endpoint, _timeout: connection,
        )
        method, path, request_body, headers = connection.request_call
        self.assertEqual((method, path), ("POST", "/v1/responses"))
        self.assertEqual(headers["Authorization"], "Bearer private-api-key")
        self.assertEqual(json.loads(request_body)["stream"], False)
        self.assertEqual(metadata["request_id"], "req-canary-test")
        self.assertEqual(metadata["input_tokens"], 4)
        self.assertEqual(metadata["output_tokens"], 2)
        self.assertEqual(metadata["total_tokens"], 6)
        self.assertEqual(metadata["total_cost"], "0.004")
        self.assertEqual(metadata["actual_cost"], "0.003")
        serialized = json.dumps(metadata)
        self.assertNotIn("private response content", serialized)
        self.assertNotIn("response-private-value", serialized)
        self.assertEqual(response.read_calls, 4)
        self.assertEqual(response.chunks, [])
        self.assertTrue(response.closed)
        self.assertTrue(connection.closed)

    def test_http_error_body_is_not_read(self):
        response = FakeResponse(
            b"private upstream error response",
            status=502,
            headers={"X-Request-ID": "req-http-error"},
        )
        connection = FakeConnection(response)
        metadata = self.client.perform_canary(
            self.client.validate_endpoint(self.client.DEFAULT_URL),
            "model-test",
            "private-api-key",
            connection_factory=lambda _endpoint, _timeout: connection,
        )
        self.assertEqual(metadata["status"], 502)
        self.assertEqual(metadata["request_id"], "req-http-error")
        self.assertEqual(response.read_calls, 0)
        self.assertNotIn("private", json.dumps(metadata))

    def test_success_without_allowlisted_metadata_headers_returns_null(self):
        body = b'not-json\x00private-response-content'
        response = FakeResponse(body, headers={
            "Content-Type": "text/plain",
            "Content-Length": str(len(body)),
            "X-Input-Tokens": "700",
            "X-Output-Tokens": "300",
            "X-Total-Tokens": "1000",
            "X-Total-Cost": "99",
            "X-Actual-Cost": "88",
        })
        metadata = self.client.perform_canary(
            self.client.validate_endpoint(self.client.DEFAULT_URL),
            "model-test",
            "private-api-key",
            connection_factory=lambda _endpoint, _timeout: FakeConnection(response),
        )
        self.assertIsNone(metadata["request_id"])
        for name in (
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "total_cost",
            "actual_cost",
        ):
            with self.subTest(name=name):
                self.assertIsNone(metadata[name])
        self.assertGreaterEqual(response.read_calls, 2)
        self.assertEqual(response.chunks, [])

    def test_response_size_and_allowlisted_metadata_are_fail_closed(self):
        cases = (
            FakeResponse(
                b"{}",
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(self.client.MAX_RESPONSE_BYTES + 1),
                },
            ),
            FakeResponse(
                b"private-body",
                headers={"X-Sub2API-Total-Tokens": "1.5"},
            ),
            FakeResponse(
                b"private-body",
                headers={"X-Sub2API-Actual-Cost": "1e-10000"},
            ),
            FakeResponse(
                b"",
                headers={"Content-Type": "application/json"},
                chunks=[b"x" * self.client.MAX_RESPONSE_BYTES, b"x", b""],
            ),
        )
        for response in cases:
            with self.subTest(headers=response.headers):
                connection = FakeConnection(response)
                with self.assertRaises(self.client.CanaryError):
                    self.client.perform_canary(
                        self.client.validate_endpoint(self.client.DEFAULT_URL),
                        "model-test",
                        "private-api-key",
                        connection_factory=lambda _endpoint, _timeout, value=connection: value,
                    )

    def test_elapsed_deadline_is_enforced_between_bounded_reads(self):
        body = b'{"usage":{}}'
        response = FakeResponse(
            body,
            headers={"Content-Type": "application/json"},
            chunks=[body, b""],
        )
        connection = FakeConnection(response)
        times = iter((0.0, 0.0, 0.0, 11.0))
        with self.assertRaises(self.client.CanaryDeadlineExceeded):
            self.client.perform_canary(
                self.client.validate_endpoint(self.client.DEFAULT_URL),
                "model-test",
                "private-api-key",
                connection_factory=lambda _endpoint, _timeout: connection,
                clock=lambda: next(times),
            )


class CanaryComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compose = CANARY_COMPOSE.read_text(encoding="utf-8")

    def test_canary_services_are_independent_and_disabled_by_default(self):
        self.assertEqual(self.compose.count('profiles: ["preflight-canary"]'), 3)
        self.assertNotIn("extends:", self.compose)
        self.assertNotIn("docker-compose.yml", self.compose)
        self.assertRegex(self.compose, r"(?m)^  canary-postgres:$")
        self.assertRegex(self.compose, r"(?m)^  canary-redis:$")
        self.assertIn('user: "70:70"', self.compose)
        self.assertIn("PGDATA: /var/lib/postgresql/18/docker", self.compose)
        self.assertIn("/var/lib/postgresql:rw,noexec,nosuid,nodev", self.compose)
        self.assertIn("cap_drop:\n      - ALL", self.compose)
        self.assertNotIn("PGDATA: /var/lib/postgresql/data", self.compose)
        self.assertIn("internal: true", self.compose)
        self.assertNotIn("external: true", self.compose)
        self.assertNotIn("SUB2API_CANARY_EXTERNAL_NETWORK", self.compose)
        self.assertIn("empty-data preflight only", self.compose)
        self.assertIn("must never be used", self.compose)

    def test_sub2api_canary_is_pinned_loopback_only_and_discards_logs(self):
        service = self.compose.split("  sub2api-canary:\n", 1)[1].split(
            "\nnetworks:\n", 1
        )[0]
        self.assertIn(
            "weishaw/sub2api@sha256:469790e0389bf31379978687149280a4e135393ad98a9a401951b6be9b1df444",
            service,
        )
        self.assertIn('"127.0.0.1:18081:8080"', service)
        self.assertNotIn('"127.0.0.1:8081:8080"', service)
        self.assertIn(
            "sub2api-gate.canary-purpose: empty-data-preflight-only", service
        )
        self.assertIn('driver: "none"', service)
        self.assertIn("LOG_OUTPUT_TO_FILE: \"false\"", service)
        self.assertIn("GATEWAY_LOG_UPSTREAM_ERROR_BODY: \"false\"", service)
        self.assertIn("read_only: true", service)
        self.assertIn("/app/data:rw,noexec,nosuid,nodev", service)
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=1000,gid=1000", service)
        self.assertNotIn("/mnt/data", service)
        self.assertIn("Sub2API 0.1.162", service)
        self.assertIn('AUTO_SETUP: "true"', service)
        self.assertIn("DATABASE_HOST: canary-postgres", service)
        self.assertIn("REDIS_HOST: canary-redis", service)

    def test_empty_preflight_does_not_offer_an_unsafe_sync_or_traffic_canary(self):
        self.assertNotIn("sub2api-sync-canary", self.compose)
        self.assertNotIn("127.0.0.1:3022", self.compose)
        self.assertNotIn("SUB2API_CANARY_SYNC_DATABASE", self.compose)
        self.assertNotIn("SUB2API_CANARY_LOGIN_URL", self.compose)
        self.assertNotIn("SUB2API_CANARY_PUBLIC_BASE_URL", self.compose)

    def test_database_and_redis_endpoints_are_fixed_to_isolated_services(self):
        required = (
            "SUB2API_CANARY_POSTGRES_PASSWORD",
            "SUB2API_CANARY_REDIS_PASSWORD",
            "SUB2API_CANARY_ADMIN_PASSWORD",
            "SUB2API_CANARY_JWT_SECRET",
            "SUB2API_CANARY_TOTP_ENCRYPTION_KEY",
            "SUB2API_CANARY_UPSTREAM_HOSTS",
        )
        for name in required:
            with self.subTest(name=name):
                self.assertIn("${" + name + ":?", self.compose)
        for forbidden in (
            "SUB2API_CANARY_DATABASE_HOST",
            "SUB2API_CANARY_REDIS_HOST",
            "SUB2API_CANARY_EXTERNAL_NETWORK",
        ):
            self.assertNotIn(forbidden, self.compose)
        self.assertNotIn("api.example.com", self.compose)

    def test_client_has_no_environment_key_or_file_persistence_path(self):
        source = CANARY_CLIENT.read_text(encoding="utf-8")
        self.assertNotIn("OPENAI_API_KEY", source)
        self.assertNotIn("SUB2API_API_KEY", source)
        self.assertNotIn("write_text", source)
        self.assertNotIn("open(", source)
        self.assertIn("require-clean-worktree.sh", source)


if __name__ == "__main__":
    unittest.main()
