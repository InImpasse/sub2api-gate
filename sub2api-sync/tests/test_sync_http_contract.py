import http.client
import hashlib
import hmac
import importlib.util
import json
import pathlib
import socket
import subprocess
import sys
import threading
import time
import unittest
import urllib.error
from contextlib import nullcontext
from email.message import Message
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).parents[1] / "sub2api_sync.py"
sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("sub2api_sync_http_contract", MODULE_PATH)
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


class RunningSyncServer:
    def __enter__(self):
        self.server = SYNC.SafeThreadingHTTPServer(("127.0.0.1", 0), SYNC.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, *, body=None, headers=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.server.server_address[1], timeout=2
        )
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            payload = response.read()
            return response.status, dict(response.getheaders()), json.loads(payload)
        finally:
            connection.close()

    def raw_request(self, request):
        with socket.create_connection(self.server.server_address, timeout=2) as connection:
            connection.sendall(request)
            response = http.client.HTTPResponse(connection)
            response.begin()
            payload = response.read()
            return response.status, dict(response.getheaders()), json.loads(payload)


class BlockingHandler(SYNC.BaseHTTPRequestHandler):
    entered = 0
    entered_lock = threading.Lock()
    all_entered = threading.Event()
    release = threading.Event()

    def do_GET(self):
        with self.entered_lock:
            type(self).entered += 1
            if type(self).entered == SYNC.MAX_REQUEST_THREADS:
                type(self).all_entered.set()
        type(self).release.wait(timeout=3)
        self.send_response(204)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, _format, *_args):
        return


class SyncHttpContractTests(unittest.TestCase):
    def signed_action_request(
        self,
        server,
        action,
        *,
        request_id,
        side_effect=None,
        verification_delay=0,
    ):
        body = json.dumps({
            "action": action,
            "uuid": "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
        }).encode()
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Request-ID": request_id,
        }
        def verify(*_args):
            if verification_delay:
                time.sleep(verification_delay)
            return True

        patches = [mock.patch.object(SYNC, "verify_request", side_effect=verify)]
        if side_effect is not None:
            handler_name = {
                "usage_logs_list": "list_usage_logs",
                "usage_log_detail": "get_usage_log_detail",
                "list_groups": "list_groups",
                "test_api_key": "test_api_key",
            }.get(action, action)
            patches.append(
                mock.patch.object(SYNC, handler_name, side_effect=side_effect)
            )
        with patches[0]:
            if len(patches) == 1:
                return server.request("POST", "/provision", body=body, headers=headers)
            with patches[1]:
                return server.request("POST", "/provision", body=body, headers=headers)

    def test_unknown_action_is_a_bounded_non_retryable_bad_request(self):
        body = json.dumps({"action": "not-supported"}).encode()
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Request-ID": "req-contract-1",
        }
        with mock.patch.object(SYNC, "verify_request", return_value=True):
            with RunningSyncServer() as server:
                status, response_headers, payload = server.request(
                    "POST", "/provision", body=body, headers=headers
                )

        self.assertEqual(status, 400)
        self.assertEqual(response_headers["x-request-id"], "req-contract-1")
        self.assertEqual(
            payload,
            {
                "ok": False,
                "error": "invalid_action",
                "retryable": False,
                "requestId": "req-contract-1",
            },
        )

    def test_list_groups_and_test_api_key_are_accepted_actions(self):
        with RunningSyncServer() as server:
            status, response_headers, payload = self.signed_action_request(
                server,
                "list_groups",
                request_id="req-groups-ok",
                side_effect=lambda _payload: {
                    "ok": True,
                    "action": "list_groups",
                    "groups": [{"id": 2, "name": "openai-default"}],
                },
            )
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["x-request-id"], "req-groups-ok")
        self.assertEqual(payload["action"], "list_groups")
        self.assertEqual(payload["groups"][0]["name"], "openai-default")
        self.assertNotIn("prompt", json.dumps(payload))

        with RunningSyncServer() as server:
            status, _headers, payload = self.signed_action_request(
                server,
                "test_api_key",
                request_id="req-key-test-ok",
                side_effect=lambda _payload: {
                    "ok": True,
                    "action": "test_api_key",
                    "tested": True,
                    "httpStatus": 200,
                    "modelCount": 1,
                    "modelId": "gpt-5.6-sol",
                },
            )
        self.assertEqual(status, 200)
        self.assertTrue(payload["tested"])
        encoded = json.dumps(payload)
        self.assertNotIn("choices", encoded)
        self.assertNotIn("sk-", encoded)

    def test_missing_api_key_maps_to_stable_bad_request(self):
        with RunningSyncServer() as server:
            status, _headers, payload = self.signed_action_request(
                server,
                "test_api_key",
                request_id="req-key-missing",
                side_effect=ValueError("api_key_not_found"),
            )
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid_request")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["action"], "test_api_key")
        self.assertNotIn("api_key_not_found", json.dumps(payload))

    def test_malformed_json_is_a_bounded_non_retryable_bad_request(self):
        body = b'{"action":'
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Request-ID": "req-contract-2",
        }
        with mock.patch.object(SYNC, "verify_request", return_value=True):
            with RunningSyncServer() as server:
                status, _response_headers, payload = server.request(
                    "POST", "/provision", body=body, headers=headers
                )

        self.assertEqual(status, 400)
        self.assertEqual(
            payload,
            {
                "ok": False,
                "error": "invalid_json",
                "retryable": False,
                "requestId": "req-contract-2",
            },
        )

    def test_non_object_json_is_a_bounded_bad_request(self):
        for label, body in {
            "array": b"[]",
            "null": b"null",
            "string": b'"status"',
            "number": b"42",
        }.items():
            with self.subTest(label=label):
                headers = {
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "X-Request-ID": f"req-contract-{label}",
                }
                with mock.patch.object(SYNC, "verify_request", return_value=True):
                    with RunningSyncServer() as server:
                        status, _response_headers, payload = server.request(
                            "POST", "/provision", body=body, headers=headers
                        )

                self.assertEqual(status, 400)
                self.assertEqual(payload["error"], "invalid_request")
                self.assertFalse(payload["retryable"])
                self.assertEqual(payload["requestId"], f"req-contract-{label}")

    def test_partial_request_body_is_bounded_by_the_connection_deadline(self):
        request = (
            b"POST /provision HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 64\r\n"
            b"X-Request-ID: req-slow-body\r\n"
            b"Connection: close\r\n\r\n"
            b"{"
        )
        with mock.patch.object(SYNC, "HTTP_CONNECTION_TIMEOUT_SECONDS", 0.05):
            with RunningSyncServer() as server:
                started = time.monotonic()
                status, response_headers, payload = server.raw_request(request)
                elapsed = time.monotonic() - started

        self.assertEqual(status, 408)
        self.assertEqual(response_headers["x-request-id"], "req-slow-body")
        self.assertEqual(payload["error"], "request_timeout")
        self.assertTrue(payload["retryable"])
        self.assertLess(elapsed, 0.5)

    def test_nonce_redis_validation_exhausts_the_shared_pre_request_budget(self):
        secret = "test-only-sync-secret-with-at-least-32-bytes"
        body = b'{"action":"status"}'
        timestamp = str(int(time.time()))
        nonce = "a" * 32
        signature = hmac.new(
            secret.encode(),
            timestamp.encode() + b"." + nonce.encode() + b"." + body,
            hashlib.sha256,
        ).hexdigest()
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Request-ID": "req-slow-nonce",
            "X-Sub2API-Sync-Timestamp": timestamp,
            "X-Sub2API-Sync-Nonce": nonce,
            "X-Sub2API-Sync-Signature": signature,
        }
        redis_calls = []

        def slow_redis(*parts, timeout=2):
            redis_calls.append((parts, timeout))
            time.sleep(0.06)
            return SYNC.remaining_timeout(timeout)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC, "DEFAULT_ACTION_TIMEOUT_SECONDS", 0.05
        ), mock.patch.object(
            SYNC, "redis_command", side_effect=slow_redis
        ):
            with RunningSyncServer() as server:
                status, response_headers, payload = server.request(
                    "POST", "/provision", body=body, headers=headers
                )

        self.assertEqual(status, 504)
        self.assertEqual(response_headers["x-request-id"], "req-slow-nonce")
        self.assertEqual(response_headers["retry-after"], "1")
        self.assertEqual(payload["error"], "dependency_timeout")
        self.assertTrue(payload["retryable"])
        self.assertEqual(len(redis_calls), 1)
        self.assertEqual(redis_calls[0][0][0], "SET")

    def test_missing_content_length_returns_length_required(self):
        request = (
            b"POST /provision HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"X-Request-ID: req-contract-3\r\n"
            b"Connection: close\r\n\r\n"
        )
        with RunningSyncServer() as server:
            status, _response_headers, payload = server.raw_request(request)

        self.assertEqual(status, 411)
        self.assertEqual(
            payload,
            {
                "ok": False,
                "error": "length_required",
                "retryable": False,
                "requestId": "req-contract-3",
            },
        )

    def test_invalid_action_payload_maps_to_stable_bad_request(self):
        with RunningSyncServer() as server:
            status, _response_headers, payload = self.signed_action_request(
                server,
                "status",
                request_id="req-contract-4",
                side_effect=ValueError("private validation detail"),
            )

        self.assertEqual(status, 400)
        self.assertEqual(
            payload,
            {
                "ok": False,
                "error": "invalid_request",
                "retryable": False,
                "requestId": "req-contract-4",
                "action": "status",
            },
        )

    def test_missing_usage_record_maps_to_not_found(self):
        with RunningSyncServer() as server:
            status, _response_headers, payload = self.signed_action_request(
                server,
                "usage_log_detail",
                request_id="req-contract-404",
                side_effect=ValueError("usage log not found"),
            )

        self.assertEqual(status, 404)
        self.assertEqual(payload["error"], "not_found")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["action"], "usage_log_detail")

    def test_identity_conflict_maps_to_non_retryable_conflict(self):
        with RunningSyncServer() as server:
            status, _response_headers, payload = self.signed_action_request(
                server,
                "status",
                request_id="req-contract-5",
                side_effect=RuntimeError("invite_identity_mismatch"),
            )

        self.assertEqual(status, 409)
        self.assertEqual(payload["error"], "identity_conflict")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["requestId"], "req-contract-5")
        self.assertEqual(payload["action"], "status")

    def test_email_and_api_key_conflicts_are_non_retryable(self):
        for runtime_code, expected in (
            ("email_conflict", "email_conflict"),
            ("api_key_conflict", "api_key_conflict"),
        ):
            with self.subTest(runtime_code=runtime_code), RunningSyncServer() as server:
                status, response_headers, payload = self.signed_action_request(
                    server,
                    "provision",
                    request_id=f"req-{runtime_code}",
                    side_effect=RuntimeError(runtime_code),
                )

            self.assertEqual(status, 409)
            self.assertNotIn("retry-after", response_headers)
            self.assertEqual(payload["error"], expected)
            self.assertFalse(payload["retryable"])

    def test_unique_violation_maps_to_non_retryable_data_conflict(self):
        with RunningSyncServer() as server:
            status, response_headers, payload = self.signed_action_request(
                server,
                "provision",
                request_id="req-data-conflict",
                side_effect=SYNC.DatabaseCommandError("23505"),
            )

        self.assertEqual(status, 409)
        self.assertNotIn("retry-after", response_headers)
        self.assertEqual(payload["error"], "data_conflict")
        self.assertFalse(payload["retryable"])

    def test_dependency_timeout_maps_to_retryable_gateway_timeout(self):
        with RunningSyncServer() as server:
            status, response_headers, payload = self.signed_action_request(
                server,
                "status",
                request_id="req-contract-6",
                side_effect=subprocess.TimeoutExpired("psql", 3),
            )

        self.assertEqual(status, 504)
        self.assertEqual(response_headers["retry-after"], "1")
        self.assertEqual(payload["error"], "dependency_timeout")
        self.assertTrue(payload["retryable"])
        self.assertEqual(payload["requestId"], "req-contract-6")
        self.assertEqual(payload["action"], "status")

    def test_database_failure_maps_to_retryable_service_unavailable(self):
        with RunningSyncServer() as server:
            status, response_headers, payload = self.signed_action_request(
                server,
                "status",
                request_id="req-contract-7",
                side_effect=RuntimeError("database_command_failed"),
            )

        self.assertEqual(status, 503)
        self.assertEqual(response_headers["retry-after"], "1")
        self.assertEqual(payload["error"], "dependency_unavailable")
        self.assertTrue(payload["retryable"])

    def test_database_failure_keeps_a_signed_bounded_diagnostic(self):
        request_id = "req-diagnostic-db"
        with SYNC._FAILURE_DIAGNOSTICS_LOCK:
            SYNC._FAILURE_DIAGNOSTICS.clear()
        with RunningSyncServer() as server:
            status, _headers, payload = self.signed_action_request(
                server,
                "status",
                request_id=request_id,
                side_effect=SYNC.DatabaseCommandError("42P01"),
            )
            self.assertEqual(status, 503)
            self.assertEqual(payload["error"], "dependency_unavailable")

            body = json.dumps({
                "action": "diagnostics", "requestId": request_id,
            }).encode()
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-Request-ID": "req-diagnostic-query",
            }
            with mock.patch.object(SYNC, "verify_request", return_value=True):
                status, _headers, payload = server.request(
                    "POST", "/provision", body=body, headers=headers
                )

        self.assertEqual(status, 200)
        self.assertEqual(payload["action"], "diagnostics")
        self.assertEqual(payload["diagnostic"], {
            "requestId": request_id,
            "action": "status",
            "category": "database_error",
            "sqlstate": "42P01",
            "recordedAt": payload["diagnostic"]["recordedAt"],
        })
        self.assertIsInstance(payload["diagnostic"]["recordedAt"], int)

    def test_diagnostics_require_a_signature_and_expire_without_persistence(self):
        request_id = "req-diagnostic-expired"
        with SYNC._FAILURE_DIAGNOSTICS_LOCK:
            SYNC._FAILURE_DIAGNOSTICS.clear()
        with mock.patch.object(SYNC.time, "time", return_value=100):
            SYNC.record_failure_diagnostic(
                request_id, "provision", "database_error", "23505"
            )
        with mock.patch.object(
            SYNC.time, "time", return_value=100 + SYNC.FAILURE_DIAGNOSTIC_TTL_SECONDS + 1
        ):
            with self.assertRaisesRegex(ValueError, "diagnostic not found"):
                SYNC.failure_diagnostic(request_id)

        body = json.dumps({
            "action": "diagnostics", "requestId": request_id,
        }).encode()
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-Request-ID": "req-diagnostic-unsigned",
        }
        with mock.patch.object(SYNC, "verify_request", return_value=False):
            with RunningSyncServer() as server:
                status, _headers, payload = server.request(
                    "POST", "/provision", body=body, headers=headers
                )
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"], "unauthorized")

    def test_failure_diagnostics_keep_a_bounded_six_hour_window(self):
        self.assertEqual(SYNC.MAX_FAILURE_DIAGNOSTICS, 256)
        self.assertEqual(SYNC.FAILURE_DIAGNOSTIC_TTL_SECONDS, 6 * 60 * 60)

    def test_login_upstream_failure_maps_to_bad_gateway(self):
        with RunningSyncServer() as server:
            status, _response_headers, payload = self.signed_action_request(
                server,
                "login",
                request_id="req-contract-8",
                side_effect=RuntimeError("sub2api_login_response_invalid"),
            )

        self.assertEqual(status, 502)
        self.assertEqual(payload["error"], "upstream_invalid_response")
        self.assertTrue(payload["retryable"])
        self.assertEqual(payload["action"], "login")

    def test_login_upstream_rate_limit_maps_to_retryable_429(self):
        with RunningSyncServer() as server:
            status, response_headers, payload = self.signed_action_request(
                server,
                "login",
                request_id="req-contract-429",
                side_effect=RuntimeError("sub2api_login_rate_limited"),
            )

        self.assertEqual(status, 429)
        self.assertEqual(response_headers["retry-after"], "1")
        self.assertEqual(payload["error"], "upstream_rate_limited")
        self.assertTrue(payload["retryable"])

    def test_unknown_route_returns_stable_not_found(self):
        with RunningSyncServer() as server:
            status, _response_headers, payload = server.request(
                "GET", "/unknown", headers={"X-Request-ID": "req-contract-9"}
            )

        self.assertEqual(status, 404)
        self.assertEqual(
            payload,
            {
                "ok": False,
                "error": "not_found",
                "retryable": False,
                "requestId": "req-contract-9",
            },
        )

    def test_unsupported_media_type_uses_stable_error_envelope(self):
        with RunningSyncServer() as server:
            status, _response_headers, payload = server.request(
                "POST",
                "/provision",
                body=b"ignored",
                headers={
                    "Content-Type": "text/plain",
                    "X-Request-ID": "req-contract-10",
                },
            )

        self.assertEqual(status, 415)
        self.assertEqual(payload["error"], "unsupported_media_type")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["requestId"], "req-contract-10")

    def test_invalid_signature_uses_stable_unauthorized_envelope(self):
        body = b'{"action":"status"}'
        with mock.patch.object(SYNC, "verify_request", return_value=False):
            with RunningSyncServer() as server:
                status, _response_headers, payload = server.request(
                    "POST",
                    "/provision",
                    body=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-Request-ID": "req-contract-11",
                    },
                )

        self.assertEqual(status, 401)
        self.assertEqual(
            payload,
            {
                "ok": False,
                "error": "unauthorized",
                "retryable": False,
                "requestId": "req-contract-11",
            },
        )

    def test_known_route_with_wrong_method_returns_json_method_not_allowed(self):
        with RunningSyncServer() as server:
            status, response_headers, payload = server.request(
                "PUT", "/provision", headers={"X-Request-ID": "req-contract-12"}
            )

        self.assertEqual(status, 405)
        self.assertEqual(response_headers["allow"], "POST")
        self.assertEqual(payload["error"], "method_not_allowed")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["requestId"], "req-contract-12")

    def test_head_response_has_headers_but_never_writes_a_json_body(self):
        with RunningSyncServer() as server:
            with socket.create_connection(server.server.server_address, timeout=2) as connection:
                connection.sendall(
                    b"HEAD /provision HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\n"
                    b"X-Request-ID: req-contract-head\r\n"
                    b"Connection: close\r\n\r\n"
                )
                chunks = []
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
        headers, body = b"".join(chunks).split(b"\r\n\r\n", 1)
        self.assertIn(b" 405 ", headers)
        self.assertIn(b"allow: post", headers.lower())
        self.assertEqual(body, b"")

    def test_capacity_rejection_returns_bounded_json_without_waiting_for_a_slot(self):
        BlockingHandler.entered = 0
        BlockingHandler.all_entered.clear()
        BlockingHandler.release.clear()
        server = SYNC.SafeThreadingHTTPServer(("127.0.0.1", 0), BlockingHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        occupied = []
        try:
            for _index in range(SYNC.MAX_REQUEST_THREADS):
                connection = socket.create_connection(server.server_address, timeout=2)
                connection.sendall(
                    b"GET /block HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                )
                occupied.append(connection)
            self.assertTrue(BlockingHandler.all_entered.wait(timeout=2))

            started = time.monotonic()
            with socket.create_connection(server.server_address, timeout=2) as rejected:
                rejected.sendall(
                    b"GET /block HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                )
                response = http.client.HTTPResponse(rejected)
                response.begin()
                payload = json.loads(response.read())
                elapsed = time.monotonic() - started

            self.assertEqual(response.status, 503)
            response_headers = dict(response.getheaders())
            self.assertEqual(response_headers["retry-after"], "1")
            self.assertEqual(
                response_headers["content-security-policy"],
                "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            )
            self.assertEqual(payload["error"], "capacity_exceeded")
            self.assertTrue(payload["retryable"])
            self.assertLess(elapsed, 0.1)
        finally:
            BlockingHandler.release.set()
            for connection in occupied:
                connection.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_server_keeps_sixteen_action_slots_and_a_thirty_two_socket_backlog(self):
        self.assertEqual(SYNC.MAX_REQUEST_THREADS, 16)
        self.assertEqual(SYNC.MAX_REQUEST_BACKLOG, 32)
        self.assertEqual(
            SYNC.SafeThreadingHTTPServer.request_queue_size,
            SYNC.MAX_REQUEST_BACKLOG,
        )

    def test_database_calls_share_one_four_second_action_deadline(self):
        observed_timeouts = []

        def fake_run(*_args, **kwargs):
            observed_timeouts.append(kwargs["timeout"])
            time.sleep(0.05)
            return subprocess.CompletedProcess([], 0, stdout="")

        def status_with_two_queries(_payload):
            SYNC.psql("SELECT 1;")
            SYNC.psql("SELECT 2;")
            return {"ok": True, "action": "status"}

        environment = {"SUB2API_SYNC_DATABASE_PASSWORD": "test-only-password"}
        with mock.patch.dict(SYNC.os.environ, environment, clear=True), \
             mock.patch.object(SYNC.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(SYNC, "status", side_effect=status_with_two_queries):
            with RunningSyncServer() as server:
                status, _headers, payload = self.signed_action_request(
                    server,
                    "status",
                    request_id="req-deadline-1",
                    verification_delay=0.08,
                )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertEqual(len(observed_timeouts), 2)
        self.assertLess(observed_timeouts[0], 3.94)
        self.assertLess(observed_timeouts[1], observed_timeouts[0] - 0.03)

    def test_timed_out_transaction_terminates_and_reaps_psql_before_returning(self):
        state = {"returncode": None}
        process = mock.Mock()
        process.stdin = mock.Mock()
        process.stdout = mock.Mock()
        process.stdout.fileno.return_value = 42
        process.poll.side_effect = lambda: state["returncode"]

        def terminate():
            state["returncode"] = -15

        process.terminate.side_effect = terminate
        process.wait.return_value = -15
        marker = "__sub2api_sync_" + "a" * 32 + "__"
        environment = {"SUB2API_SYNC_DATABASE_PASSWORD": "test-only-password"}
        with mock.patch.dict(SYNC.os.environ, environment, clear=True), \
             mock.patch.object(SYNC.subprocess, "Popen", return_value=process), \
             mock.patch.object(SYNC.secrets, "token_hex", return_value="a" * 32), \
             mock.patch.object(
                 SYNC.select,
                 "select",
                 side_effect=[([42], [], []), ([], [], [])],
             ), \
             mock.patch.object(SYNC.os, "read", return_value=(marker + "\n").encode()):
            with self.assertRaises(subprocess.TimeoutExpired):
                with SYNC.database_transaction(timeout=0.1) as transaction:
                    transaction.execute("SELECT pg_sleep(10);", timeout=0.01)

        process.terminate.assert_called_once_with()
        process.wait.assert_called()
        process.kill.assert_not_called()
        self.assertIsNone(getattr(SYNC._DATABASE_TRANSACTION, "session", None))

    def test_login_upstream_call_is_capped_below_the_eight_second_action_budget(self):
        class LoginResponse:
            headers = Message()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return (
                    b'{"code":0,"data":{"access_token":"test-token",'
                    b'"user":{"id":9}}}'
                )

        payload = {
            "uuid": "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
            "email": "user@example.test",
            "loginPassword": "test-password",
        }
        owned_user = [
            "9", "user", "user", "a" * 64, "user@example.test",
            "password-hash", "active",
        ]
        with mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "resolve_invite_user", return_value=owned_user
        ), mock.patch.object(
            SYNC.urllib.request, "urlopen", return_value=LoginResponse()
        ) as urlopen:
            with SYNC.action_deadline("login"):
                result = SYNC.login(payload)

        self.assertTrue(result["ok"])
        timeout = urlopen.call_args.kwargs["timeout"]
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 5)

    def test_wrapped_login_socket_timeout_maps_to_gateway_timeout(self):
        with RunningSyncServer() as server:
            status, _headers, payload = self.signed_action_request(
                server,
                "login",
                request_id="req-deadline-2",
                side_effect=urllib.error.URLError(socket.timeout("private detail")),
            )

        self.assertEqual(status, 504)
        self.assertEqual(payload["error"], "dependency_timeout")
        self.assertTrue(payload["retryable"])

    def test_health_dependencies_share_a_two_second_deadline(self):
        observed = {}

        def database(_sql, *, timeout, **_kwargs):
            observed["database"] = timeout
            time.sleep(0.05)
            return ""

        def redis(*_parts, timeout):
            observed["redis"] = timeout
            return "PONG"

        with mock.patch.object(SYNC, "psql", side_effect=database), \
             mock.patch.object(SYNC, "redis_command", side_effect=redis):
            with RunningSyncServer() as server:
                status, _headers, payload = server.request(
                    "GET", "/healthz", headers={"X-Request-ID": "req-health-1"}
                )

        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertGreater(observed["database"], 0)
        self.assertLessEqual(observed["database"], 1)
        self.assertGreater(observed["redis"], 0)
        self.assertLessEqual(observed["redis"], 1)

    def test_invalid_content_length_uses_stable_bad_request_envelope(self):
        request = (
            b"POST /provision HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: invalid\r\n"
            b"X-Request-ID: req-length-1\r\n"
            b"Connection: close\r\n\r\n"
        )
        with RunningSyncServer() as server:
            status, _headers, payload = server.raw_request(request)

        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid_content_length")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["requestId"], "req-length-1")

    def test_oversized_body_is_rejected_before_reading_it(self):
        request = (
            b"POST /provision HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {SYNC.MAX_BODY_BYTES + 1}\r\n".encode()
            + b"X-Request-ID: req-length-2\r\n"
            b"Connection: close\r\n\r\n"
        )
        with RunningSyncServer() as server:
            status, _headers, payload = server.raw_request(request)

        self.assertEqual(status, 413)
        self.assertEqual(payload["error"], "payload_too_large")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["requestId"], "req-length-2")

    def test_cold_usage_list_reuses_one_database_session(self):
        writes = []
        pending_output = []
        state = {"last_sql": "", "returncode": None}

        class FakeInput:
            def write(self, value):
                text = value.decode() if isinstance(value, bytes) else value
                writes.append(text)
                if text.startswith("\\echo "):
                    if state["last_sql"].lstrip().startswith("SELECT"):
                        pending_output.append("[]\n")
                    pending_output.append(text.removeprefix("\\echo ").strip() + "\n")
                else:
                    state["last_sql"] = text

            def flush(self):
                return None

            def close(self):
                return None

        class FakeOutput:
            def readline(self):
                return pending_output.pop(0) if pending_output else ""

            def close(self):
                return None

        process = mock.Mock()
        process.stdin = FakeInput()
        process.stdout = FakeOutput()
        process.poll.side_effect = lambda: state["returncode"]
        process.wait.return_value = 0
        completed = subprocess.CompletedProcess([], 0, stdout="[]")
        environment = {"SUB2API_SYNC_DATABASE_PASSWORD": "test-only-password"}
        SYNC.metadata_usage_logs.__globals__["_MODEL_CACHE"].update(
            {"expires_at": 0.0, "items": []}
        )
        with mock.patch.dict(SYNC.os.environ, environment, clear=True), \
             mock.patch.object(SYNC.subprocess, "Popen", return_value=process) as popen, \
             mock.patch.object(SYNC.subprocess, "run", return_value=completed) as run:
            result = SYNC.list_usage_logs({"pageSize": 25})

        self.assertTrue(result["ok"])
        popen.assert_called_once()
        run.assert_not_called()
        transcript = "".join(writes)
        self.assertEqual(transcript.count("FROM usage_logs"), 2)
        self.assertIn("BEGIN;", transcript)
        self.assertIn("COMMIT;", transcript)


if __name__ == "__main__":
    unittest.main()
