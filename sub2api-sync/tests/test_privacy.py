import importlib.util
import io
import json
import pathlib
import sys
import threading
import unittest
from contextlib import nullcontext
from email.message import Message
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).parents[1] / "sub2api_sync.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("sub2api_sync", MODULE_PATH)
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)

SENTINEL = "PRIVATE_CONVERSATION_SENTINEL_7f3b90"


class PrivacyContractTests(unittest.TestCase):
    def test_default_group_is_openai_default(self):
        with mock.patch.dict(SYNC.os.environ, {}, clear=True):
            self.assertEqual(SYNC.configured_groups(), ["openai-default"])

    def test_usage_filter_sql_only_searches_metadata(self):
        query, _failed, clause = SYNC.usage_log_filters({"query": SENTINEL})
        self.assertNotIn("body", clause.lower())
        self.assertNotIn("prompt", clause.lower())
        self.assertEqual(query, SENTINEL)
        self.assertIn(SENTINEL.replace("_", "!_"), clause)

    def test_usage_list_never_returns_content_fields(self):
        row = {
            "id": 42,
            "requestId": "req-1",
            "model": "gpt-test",
            "inputTokens": 12,
            "outputTokens": 5,
            "actualCost": "0.001",
            "durationMs": 80,
            "createdAt": "2026-07-19T00:00:00Z",
            "prompt": SENTINEL,
            "bodyText": SENTINEL,
            "responsePreview": SENTINEL,
        }
        with mock.patch.object(SYNC, "query_json_value", return_value=[row]):
            result = SYNC.list_usage_logs({"pageSize": 25})
        encoded = json.dumps(result)
        self.assertNotIn(SENTINEL, encoded)
        self.assertEqual(
            set(result["items"][0]),
            {
                "id", "requestId", "model", "requestedModel", "inputTokens",
                "outputTokens", "cacheCreationTokens", "cacheReadTokens",
                "totalCost", "actualCost", "durationMs", "stream",
                "requestType", "inboundEndpoint", "createdAt",
            },
        )

    def test_http_handler_has_no_capture_or_gateway_route(self):
        handler = object.__new__(SYNC.Handler)
        handler.path = "/v1/responses"
        handler.command = "POST"
        handler.headers = {"content-length": str(len(SENTINEL))}
        handler.rfile = io.BytesIO(SENTINEL.encode())
        handler.client_address = ("127.0.0.1", 1234)
        responses = []
        handler.respond = lambda status, payload: responses.append((status, payload))
        handler.do_POST()
        self.assertEqual(responses[0][0], 404)
        self.assertEqual(handler.rfile.tell(), 0)

    def test_hmac_nonce_is_claimed_atomically_after_signature_validation(self):
        secret = "s" * 32
        timestamp = str(int(SYNC.time.time()))
        nonce = "0123456789abcdef" * 2
        body = b'{"action":"status"}'
        signature = SYNC.hmac.new(
            secret.encode(),
            timestamp.encode() + b"." + nonce.encode() + b"." + body,
            SYNC.hashlib.sha256,
        ).hexdigest()
        headers = {
            "x-sub2api-sync-timestamp": timestamp,
            "x-sub2api-sync-nonce": nonce,
            "x-sub2api-sync-signature": signature,
        }
        with mock.patch.dict(SYNC.os.environ, {"SUB2API_SYNC_SECRET": secret}, clear=True), \
             mock.patch.object(SYNC, "claim_nonce", side_effect=[True, False]) as claim:
            self.assertTrue(SYNC.verify_request(headers, body))
            self.assertFalse(SYNC.verify_request(headers, body))
        claim.assert_called_with(nonce)

    def test_nonce_storage_ttl_covers_the_full_signed_timestamp_window(self):
        nonce = "fedcba9876543210" * 2
        with mock.patch.object(SYNC, "redis_command", return_value="OK") as command:
            self.assertTrue(SYNC.claim_nonce(nonce))

        self.assertEqual(
            SYNC.NONCE_TTL_SECONDS,
            SYNC.SIGNATURE_MAX_SKEW_SECONDS * 2 + 1,
        )
        self.assertEqual(command.call_args.args[-2:], ("EX", SYNC.NONCE_TTL_SECONDS))

    def test_redis_uses_named_acl_auth_when_username_is_configured(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        stream = object()
        connection.makefile.return_value = stream
        environment = {
            "SUB2API_SYNC_REDIS_HOST": "redis.example.test",
            "SUB2API_SYNC_REDIS_PORT": "6380",
            "SUB2API_SYNC_REDIS_USERNAME": "sub2api_sync",
            "SUB2API_SYNC_REDIS_PASSWORD": "sync-password",
            "SUB2API_SYNC_REDIS_DB": "0",
        }
        with mock.patch.dict(SYNC.os.environ, environment, clear=True), \
             mock.patch.object(
                 SYNC.socket, "create_connection", return_value=connection
             ) as create_connection, \
             mock.patch.object(SYNC, "_redis_write") as write, \
             mock.patch.object(SYNC, "_redis_read", side_effect=["OK", "PONG"]):
            self.assertEqual(SYNC.redis_command("PING"), "PONG")

        create_connection.assert_called_once_with(
            ("redis.example.test", 6380), timeout=2
        )
        self.assertEqual(
            write.call_args_list,
            [
                mock.call(stream, "AUTH", "sub2api_sync", "sync-password"),
                mock.call(stream, "PING"),
            ],
        )

    def test_redis_retains_password_only_auth_compatibility(self):
        connection = mock.MagicMock()
        connection.__enter__.return_value = connection
        stream = object()
        connection.makefile.return_value = stream
        environment = {
            "SUB2API_SYNC_REDIS_PASSWORD": "legacy-password",
            "SUB2API_SYNC_REDIS_DB": "0",
        }
        with mock.patch.dict(SYNC.os.environ, environment, clear=True), \
             mock.patch.object(
                 SYNC.socket, "create_connection", return_value=connection
             ), mock.patch.object(SYNC, "_redis_write") as write, \
             mock.patch.object(SYNC, "_redis_read", side_effect=["OK", "PONG"]):
            self.assertEqual(SYNC.redis_command("PING"), "PONG")

        self.assertEqual(
            write.call_args_list,
            [
                mock.call(stream, "AUTH", "legacy-password"),
                mock.call(stream, "PING"),
            ],
        )

    def test_redis_rejects_named_acl_auth_without_a_password(self):
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_REDIS_USERNAME": "sub2api_sync"},
            clear=True,
        ), mock.patch.object(SYNC.socket, "create_connection") as connect:
            with self.assertRaisesRegex(
                RuntimeError, "redis_configuration_invalid"
            ):
                SYNC.redis_command("PING")
        connect.assert_not_called()

    def test_hmac_rejects_bad_signatures_and_timestamps_outside_the_window(self):
        secret = "s" * 32
        now = 2_000_000_000
        body = b'{"action":"status"}'

        def signed_headers(offset, nonce, signature=None):
            timestamp = str(now + offset)
            expected = SYNC.hmac.new(
                secret.encode(),
                timestamp.encode() + b"." + nonce.encode() + b"." + body,
                SYNC.hashlib.sha256,
            ).hexdigest()
            return {
                "x-sub2api-sync-timestamp": timestamp,
                "x-sub2api-sync-nonce": nonce,
                "x-sub2api-sync-signature": signature or expected,
            }

        invalid = (
            signed_headers(
                0,
                "10000000000000000000000000000000",
                "0" * 64,
            ),
            signed_headers(
                -SYNC.SIGNATURE_MAX_SKEW_SECONDS - 1,
                "20000000000000000000000000000000",
            ),
            signed_headers(
                SYNC.SIGNATURE_MAX_SKEW_SECONDS + 1,
                "30000000000000000000000000000000",
            ),
        )
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(SYNC.time, "time", return_value=now), \
             mock.patch.object(SYNC, "claim_nonce", return_value=True) as claim:
            for headers in invalid:
                with self.subTest(headers=headers):
                    self.assertFalse(SYNC.verify_request(headers, body))
            claim.assert_not_called()

            for offset, nonce in (
                (-SYNC.SIGNATURE_MAX_SKEW_SECONDS, "40000000000000000000000000000000"),
                (SYNC.SIGNATURE_MAX_SKEW_SECONDS, "50000000000000000000000000000000"),
            ):
                with self.subTest(offset=offset):
                    self.assertTrue(
                        SYNC.verify_request(signed_headers(offset, nonce), body)
                    )
            self.assertEqual(claim.call_count, 2)

    def test_future_timestamp_has_no_replay_gap_after_nonce_expiry(self):
        secret = "s" * 32
        initial_time = 2_000_000_000
        signed_time = initial_time + SYNC.SIGNATURE_MAX_SKEW_SECONDS
        timestamp = str(signed_time)
        nonce = "60000000000000000000000000000000"
        body = b'{"action":"status"}'
        signature = SYNC.hmac.new(
            secret.encode(),
            timestamp.encode() + b"." + nonce.encode() + b"." + body,
            SYNC.hashlib.sha256,
        ).hexdigest()
        headers = {
            "x-sub2api-sync-timestamp": timestamp,
            "x-sub2api-sync-nonce": nonce,
            "x-sub2api-sync-signature": signature,
        }
        clock = {"now": initial_time}
        expirations = {}

        def fake_redis(*parts, **_kwargs):
            key = parts[1]
            if expirations.get(key, 0) > clock["now"]:
                return None
            expirations[key] = clock["now"] + int(parts[-1])
            return "OK"

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC.time,
            "time",
            side_effect=lambda: clock["now"],
        ), mock.patch.object(SYNC, "redis_command", side_effect=fake_redis) as redis:
            self.assertTrue(SYNC.verify_request(headers, body))

            clock["now"] = initial_time + 2 * SYNC.SIGNATURE_MAX_SKEW_SECONDS
            self.assertFalse(SYNC.verify_request(headers, body))

            clock["now"] += 1
            self.assertFalse(SYNC.verify_request(headers, body))

        self.assertEqual(redis.call_count, 2)

    def test_hmac_rejects_non_worker_header_formats_before_claiming_nonce(self):
        secret = "s" * 32
        valid_timestamp = str(int(SYNC.time.time()))
        valid_nonce = "0123456789abcdef" * 2
        body = b'{"action":"status"}'
        invalid_headers = (
            (valid_timestamp, "a" * 31, None),
            (valid_timestamp, "A" * 32, None),
            (valid_timestamp, "g" * 32, None),
            ("0" + valid_timestamp, valid_nonce, None),
            ("+" + valid_timestamp, valid_nonce, None),
            ("9" * 14, valid_nonce, None),
            (valid_timestamp, valid_nonce, "A" * 64),
            (valid_timestamp, valid_nonce, "g" * 64),
            (valid_timestamp, valid_nonce, "a" * 63),
        )
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(SYNC, "claim_nonce") as claim:
            for timestamp, nonce, supplied_signature in invalid_headers:
                signature = supplied_signature or SYNC.hmac.new(
                    secret.encode(),
                    timestamp.encode() + b"." + nonce.encode() + b"." + body,
                    SYNC.hashlib.sha256,
                ).hexdigest()
                headers = {
                    "x-sub2api-sync-timestamp": timestamp,
                    "x-sub2api-sync-nonce": nonce,
                    "x-sub2api-sync-signature": signature,
                }
                with self.subTest(headers=headers):
                    self.assertFalse(SYNC.verify_request(headers, body))
        claim.assert_not_called()

    def test_sync_source_never_logs_database_or_sub2api_response_details(self):
        source = MODULE_PATH.read_text()
        self.assertNotIn("result.stderr", source)
        self.assertNotIn("capture_output=True", source)
        self.assertIn("stderr=subprocess.DEVNULL", source)
        self.assertNotIn("error.read()", source)
        self.assertNotIn('"error": str(error)', source)
        self.assertIn('"--no-psqlrc"', source)

    def test_unknown_action_is_normalized_before_error_logging(self):
        handler = object.__new__(SYNC.Handler)
        sentinel = "sk-private-action-sentinel"
        body = json.dumps({"action": sentinel}).encode()
        handler.path = "/provision"
        handler.command = "POST"
        handler.headers = {
            "content-type": "application/json",
            "content-length": str(len(body)),
        }
        handler.rfile = io.BytesIO(body)
        handler.client_address = ("127.0.0.1", 1234)
        responses = []
        handler.respond = lambda status, payload: responses.append((status, payload))
        output = io.StringIO()
        with mock.patch.object(SYNC, "verify_request", return_value=True), \
             mock.patch("sys.stdout", output):
            handler.do_POST()

        self.assertEqual(responses, [(500, {"ok": False, "error": "sync_action_failed"})])
        self.assertNotIn(sentinel, output.getvalue())
        self.assertIn('"action": "invalid"', output.getvalue())

    def test_invalid_content_length_returns_a_bounded_error(self):
        handler = object.__new__(SYNC.Handler)
        handler.path = "/provision"
        handler.command = "POST"
        handler.headers = {
            "content-type": "application/json",
            "content-length": "not-a-number",
        }
        responses = []
        handler.respond = lambda status, payload: responses.append((status, payload))

        handler.do_POST()

        self.assertEqual(responses, [(400, {"ok": False, "error": "invalid content length"})])

    def test_server_thread_errors_log_only_a_stable_code(self):
        server = object.__new__(SYNC.SafeThreadingHTTPServer)
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            server.handle_error(None, None)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"level": "error", "error_code": "sync_request_failed"},
        )

    def test_server_sets_five_second_connection_timeout(self):
        server = object.__new__(SYNC.SafeThreadingHTTPServer)
        connection = mock.Mock()
        address = ("127.0.0.1", 1234)
        with mock.patch.object(
            SYNC.ThreadingHTTPServer,
            "get_request",
            return_value=(connection, address),
        ):
            self.assertEqual(server.get_request(), (connection, address))
        connection.settimeout.assert_called_once_with(5)

    def test_server_rejects_connections_above_the_thread_limit_with_stable_code(self):
        server = object.__new__(SYNC.SafeThreadingHTTPServer)
        server._request_slots = threading.BoundedSemaphore(1)
        server._request_slots.acquire()
        server.shutdown_request = mock.Mock()
        request = object()
        output = io.StringIO()

        with mock.patch("sys.stdout", output), mock.patch.object(
            SYNC.ThreadingHTTPServer,
            "process_request",
        ) as process_request:
            server.process_request(request, ("127.0.0.1", 1234))

        process_request.assert_not_called()
        server.shutdown_request.assert_called_once_with(request)
        self.assertEqual(
            json.loads(output.getvalue()),
            {"level": "warning", "error_code": "sync_request_capacity_rejected"},
        )

    def test_server_releases_thread_slot_after_request_finishes(self):
        server = object.__new__(SYNC.SafeThreadingHTTPServer)
        server._request_slots = threading.BoundedSemaphore(1)
        self.assertTrue(server._request_slots.acquire(blocking=False))
        with mock.patch.object(
            SYNC.ThreadingHTTPServer,
            "process_request_thread",
        ):
            server.process_request_thread(object(), ("127.0.0.1", 1234))
        self.assertTrue(server._request_slots.acquire(blocking=False))

    def test_body_timeout_and_short_read_use_stable_content_free_errors(self):
        class TimedOutBody:
            def read(self, _length):
                raise TimeoutError("sk-private-timeout-detail")

        cases = (
            (TimedOutBody(), 408, "request timeout", "sync_request_read_timeout"),
            (io.BytesIO(b"short"), 400, "incomplete request body", "sync_request_body_incomplete"),
        )
        for body_stream, status, error, error_code in cases:
            with self.subTest(error_code=error_code):
                handler = object.__new__(SYNC.Handler)
                handler.path = "/provision"
                handler.command = "POST"
                handler.headers = {
                    "content-type": "application/json",
                    "content-length": "128",
                    "x-request-id": "bounded-request-id",
                }
                handler.rfile = body_stream
                handler.client_address = ("127.0.0.1", 1234)
                responses = []
                handler.respond = lambda response_status, payload: responses.append(
                    (response_status, payload)
                )
                output = io.StringIO()
                with mock.patch.object(SYNC, "verify_request") as verify, mock.patch(
                    "sys.stdout", output
                ):
                    handler.do_POST()

                self.assertTrue(handler.close_connection)
                self.assertEqual(responses, [(status, {"ok": False, "error": error})])
                verify.assert_not_called()
                self.assertEqual(
                    json.loads(output.getvalue()),
                    {
                        "level": "warning",
                        "error_code": error_code,
                        "request_id": "bounded-request-id",
                    },
                )
                self.assertNotIn("sk-private-timeout-detail", output.getvalue())

    def test_sub2api_login_response_is_bounded_without_logging_the_body(self):
        login_payload = {
            "uuid": "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
            "username": "user",
            "sub2apiUserId": 9,
            "email": "user@example.test",
            "loginPassword": "password",
        }
        owned_user = [
            "9", "user", "user", "a" * 64, "user@example.test",
            "bcrypt-hash", "active",
        ]

        class OversizedResponse:
            def __init__(self, declared=True):
                self.headers = Message()
                if declared:
                    self.headers["content-length"] = str(SYNC.MAX_LOGIN_RESPONSE_BYTES + 1)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, *_args):
                raise AssertionError("declared oversized response must not be read")

        with mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "resolve_invite_user", return_value=owned_user
        ):
            with mock.patch.object(SYNC.urllib.request, "urlopen", return_value=OversizedResponse()):
                with self.assertRaisesRegex(RuntimeError, "response_too_large"):
                    SYNC.login(login_payload)

            undeclared = OversizedResponse(declared=False)
            undeclared.read = mock.Mock(
                return_value=b"x" * (SYNC.MAX_LOGIN_RESPONSE_BYTES + 1)
            )
            with mock.patch.object(SYNC.urllib.request, "urlopen", return_value=undeclared):
                with self.assertRaisesRegex(RuntimeError, "response_too_large"):
                    SYNC.login(login_payload)
        undeclared.read.assert_called_once_with(SYNC.MAX_LOGIN_RESPONSE_BYTES + 1)


if __name__ == "__main__":
    unittest.main()
