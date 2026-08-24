import importlib.util
import io
import json
import pathlib
import sys
import threading
import time
import types
import unittest
from contextlib import nullcontext
from concurrent.futures import ThreadPoolExecutor
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SYNC = load_module("sub2api_sync_compat", ROOT / "sub2api_sync.py")
USAGE = load_module("usage_metadata_compat", ROOT / "usage_metadata.py")


class Sub2ApiCompatibilityTests(unittest.TestCase):
    UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11"

    def test_payload_identity_prefers_clean_display_name(self):
        uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11"
        identity = SYNC.payload_identity({"uuid": uuid, "username": "u7c484f746d9", "name": "Alice Example"})
        self.assertEqual(identity[0], uuid)
        self.assertEqual(identity[2], "alice-example")

    def test_payload_identity_rejects_noncanonical_uuid_wrappers(self):
        uuid = "7c484f74-6d93-43d1-9441-00c7d8d4ab11"
        for value in (f"prefix-{uuid}", uuid.replace("-", ""), f"{uuid}<script>"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SYNC.payload_identity({"uuid": value})

    def test_api_key_normalization_and_token_deduplication(self):
        key = "sk-" + "a" * 48
        tokens = SYNC.requested_tokens({
            "tokens": [
                {"tokenKey": key, "tokenName": "primary"},
                {"apiKey": key, "apiKeyName": "duplicate"},
            ],
        })
        self.assertEqual(tokens, [{"key": key, "name": "primary"}])
        self.assertEqual(SYNC.normalize_api_key("b" * 48), "sk-" + "b" * 48)
        for invalid in ("not-a-key", "sk-", "sk-invalid-symbol!"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                SYNC.normalize_api_key(invalid)

    def test_token_normalization_rejects_more_than_the_user_key_limit(self):
        tokens = [
            {"tokenKey": "sk-" + f"{index:048d}", "tokenName": "key"}
            for index in range(101)
        ]
        with self.assertRaisesRegex(RuntimeError, "api_key_limit_exceeded"):
            SYNC.requested_tokens({"tokens": tokens})

    def test_group_profile_and_configured_group_fallback(self):
        self.assertEqual(SYNC.group_profile("default")[0], "openai")
        self.assertEqual(SYNC.group_profile("anthropic-default")[0], "anthropic")
        with mock.patch.dict(SYNC.os.environ, {"SUB2API_SYNC_DEFAULT_GROUP": " openai-default, anthropic-default, openai-default "}, clear=True):
            self.assertEqual(SYNC.configured_groups(), ["openai-default", "anthropic-default"])
        with mock.patch.dict(SYNC.os.environ, {"SUB2API_SYNC_DEFAULT_GROUP": " , "}, clear=True):
            self.assertEqual(SYNC.configured_groups(), ["openai-default"])

    def test_user_key_listing_fails_closed_above_response_limit(self):
        key_rows = [
            [str(index), "name", "sk-" + "a" * 48, "active", "0", "0"]
            for index in range(1, 102)
        ]
        with mock.patch.object(SYNC, "rows", return_value=key_rows) as query:
            with self.assertRaisesRegex(RuntimeError, "api_key_limit_exceeded"):
                SYNC.get_user_keys(7)

        sql = query.call_args.args[0]
        self.assertIn("LIMIT 101", sql)

    def test_existing_user_without_recoverable_password_gets_a_new_password(self):
        statements = []
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return ["9", "u7c484f746d9", "user", owner]
            if "SELECT password_hash FROM users WHERE id=9" in sql:
                return ["bcrypt-hash"]
            raise AssertionError(sql)

        with mock.patch.dict(SYNC.os.environ, {"SUB2API_SYNC_SECRET": secret}, clear=True), \
             mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(SYNC, "ensure_groups", return_value=[("openai-default", 2)]), \
             mock.patch.object(SYNC, "ensure_subscription_plan"), \
             mock.patch.object(SYNC, "ensure_default_subscription"), \
             mock.patch.object(SYNC, "sync_user_keys", return_value=(0, "")), \
             mock.patch.object(SYNC, "get_user_keys", return_value=[]), \
             mock.patch.object(SYNC, "first_row", side_effect=first_row), \
             mock.patch.object(SYNC, "psql", side_effect=statements.append), \
             mock.patch.object(SYNC, "login_password", return_value="replacement-password"), \
             mock.patch.object(SYNC, "password_hash_fingerprint", return_value="fingerprint"):
            result = SYNC.provision({
                "uuid": "7c484f74-6d93-43d1-9441-00c7d8d4ab11",
                "sub2apiUserId": 9,
                "tokens": [],
            })

        self.assertEqual(result["loginPassword"], "replacement-password")
        self.assertTrue(any("password_hash=crypt" in sql for sql in statements))

    def test_provision_rejects_an_explicit_admin_user_before_any_write(self):
        statements = []

        def first_row(sql):
            if "FROM users" in sql and "id=9" in sql:
                return ["9", "alice-example", "admin", ""]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": "s" * 32},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC, "psql", side_effect=statements.append
        ):
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.provision({
                    "uuid": self.UUID,
                    "username": "alice-example",
                    "sub2apiUserId": 9,
                    "tokens": [],
                })

        self.assertEqual(statements, [])

    def test_status_rejects_a_user_id_owned_by_another_invite_before_key_lookup(self):
        foreign_owner = "f" * 64

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return [
                    "9",
                    "alice-example",
                    "user",
                    foreign_owner,
                    "alice@example.test",
                    "bcrypt-hash",
                    "active",
                ]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": "s" * 32},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC, "get_user_keys"
        ) as get_keys:
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.status({
                    "uuid": self.UUID,
                    "username": "alice-example",
                    "sub2apiUserId": 9,
                })

        get_keys.assert_not_called()

    def test_status_first_bind_persists_only_a_domain_separated_hmac(self):
        statements = []
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return [
                    "9",
                    "alice-example",
                    "user",
                    "",
                    "alice@example.test",
                    "bcrypt-hash",
                    "active",
                ]
            if "SELECT invite_fingerprint" in sql:
                return [owner]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC, "psql", side_effect=statements.append
        ), mock.patch.object(
            SYNC, "get_user_keys", return_value=[]
        ), mock.patch.object(
            SYNC, "password_hash_fingerprint", return_value="password-fingerprint"
        ):
            result = SYNC.status({
                "uuid": self.UUID,
                "username": "alice-example",
                "sub2apiUserId": 9,
            })

        self.assertTrue(result["exists"])
        self.assertEqual(len(statements), 1)
        self.assertIn(owner, statements[0])
        self.assertNotIn(self.UUID, statements[0])

    def test_deprovision_rejects_first_bind_to_a_different_username(self):
        statements = []

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return ["9", "bob", "user", ""]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": "s" * 32},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC, "psql", side_effect=statements.append
        ):
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.deprovision({
                    "uuid": self.UUID,
                    "username": "alice-example",
                    "sub2apiUserId": 9,
                })

        self.assertEqual(statements, [])

    def test_deprovision_does_not_claim_an_unbound_matching_user(self):
        statements = []

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return ["9", "alice-example", "user", ""]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": "s" * 32},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC, "psql", side_effect=statements.append
        ):
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.deprovision({
                    "uuid": self.UUID,
                    "username": "alice-example",
                    "sub2apiUserId": 9,
                })

        self.assertEqual(statements, [])

    def test_purge_rejects_a_user_id_owned_by_another_invite(self):
        statements = []

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return ["9", "alice-example", "user", "f" * 64]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": "s" * 32},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC, "psql", side_effect=statements.append
        ):
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.purge({
                    "uuid": self.UUID,
                    "username": "alice-example",
                    "sub2apiUserId": 9,
                })

        self.assertEqual(statements, [])

    def test_login_reconciles_an_unowned_explicit_user_before_upstream_request(self):
        statements = []
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return [
                    "9",
                    "alice-example",
                    "user",
                    "",
                    "alice@example.test",
                    "bcrypt-hash",
                    "active",
                ]
            if "SELECT invite_fingerprint" in sql:
                return [owner]
            raise AssertionError(sql)

        class LoginResponse:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return json.dumps({
                    "code": 0,
                    "data": {
                        "access_token": "test-access-token",
                        "user": {
                            "id": 9,
                            "username": "alice-example",
                            "email": "alice@example.test",
                            "role": "user",
                            "status": "active",
                        },
                    },
                }).encode()

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC, "psql", side_effect=statements.append
        ), mock.patch.object(
            SYNC.urllib.request, "urlopen", return_value=LoginResponse()
        ) as urlopen:
            result = SYNC.login({
                "uuid": self.UUID,
                "username": "alice-example",
                "sub2apiUserId": 9,
                "email": "alice@example.test",
                "loginPassword": "password",
            })

        self.assertEqual(result["auth"]["user"]["id"], 9)
        self.assertEqual(len(statements), 1)
        self.assertIn(owner, statements[0])
        self.assertNotIn(self.UUID, statements[0])
        urlopen.assert_called_once()

    def test_login_rejects_an_owned_user_when_database_email_does_not_match(self):
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return [
                    "9",
                    "alice-example",
                    "user",
                    owner,
                    "other@example.test",
                    "bcrypt-hash",
                    "active",
                ]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC.urllib.request, "urlopen"
        ) as urlopen:
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.login({
                    "uuid": self.UUID,
                    "username": "alice-example",
                    "sub2apiUserId": 9,
                    "email": "alice@example.test",
                    "loginPassword": "password",
                })

        urlopen.assert_not_called()

    def test_login_accepts_old_worker_payload_for_an_existing_owner(self):
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM sub2api_sync_invite_owners o JOIN users u" in sql:
                return [
                    "9",
                    "human-name",
                    "user",
                    owner,
                    "alice@example.test",
                    "bcrypt-hash",
                    "active",
                ]
            raise AssertionError(sql)

        class LoginResponse:
            headers = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return json.dumps({
                    "code": 0,
                    "data": {
                        "access_token": "test-access-token",
                        "refresh_token": "test-refresh-token",
                        "expires_in": 3600,
                        "user": {
                            "id": 9,
                            "username": "human-name",
                            "email": "alice@example.test",
                            "role": "user",
                            "status": "active",
                            "password_hash": "must-not-cross-sync-boundary",
                            "conversation_preview": "must-not-cross-sync-boundary",
                        },
                        "passwordHash": "must-not-cross-sync-boundary",
                        "debug": {"response_body": "must-not-cross-sync-boundary"},
                    },
                }).encode()

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(
            SYNC.urllib.request, "urlopen", return_value=LoginResponse()
        ) as urlopen:
            result = SYNC.login({
                "uuid": self.UUID,
                "email": "alice@example.test",
                "loginPassword": "password",
            })

        self.assertEqual(result["uuid"], self.UUID)
        self.assertEqual(result["auth"], {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "expires_in": 3600,
            "user": {
                "id": 9,
                "username": "human-name",
                "email": "alice@example.test",
                "role": "user",
                "status": "active",
            },
        })
        self.assertNotIn("must-not-cross-sync-boundary", json.dumps(result))
        urlopen.assert_called_once()

    def test_login_auth_projection_matches_the_worker_response_budget(self):
        maximum_ascii_user = {
            field: "x" * SYNC.MAX_LOGIN_USER_FIELD_BYTES
            for field in SYNC.LOGIN_USER_FIELDS
        }
        auth = SYNC.sanitize_login_auth({
            "access_token": "a" * SYNC.MAX_LOGIN_AUTH_TOKEN_BYTES,
            "refresh_token": "b" * SYNC.MAX_LOGIN_AUTH_TOKEN_BYTES,
            "user": maximum_ascii_user,
        })
        encoded = json.dumps(auth, separators=(",", ":")).encode()
        self.assertLessEqual(len(encoded), SYNC.MAX_LOGIN_AUTH_RESPONSE_BYTES)
        self.assertLess(SYNC.MAX_LOGIN_AUTH_RESPONSE_BYTES, 16 * 1024)

        oversized_after_json_escaping = {
            field: "界" * (SYNC.MAX_LOGIN_USER_FIELD_BYTES // 3)
            for field in SYNC.LOGIN_USER_FIELDS
        }
        with self.assertRaisesRegex(RuntimeError, "response_invalid"):
            SYNC.sanitize_login_auth({
                "access_token": "a" * SYNC.MAX_LOGIN_AUTH_TOKEN_BYTES,
                "refresh_token": "b" * SYNC.MAX_LOGIN_AUTH_TOKEN_BYTES,
                "user": oversized_after_json_escaping,
            })

    def test_login_auth_projection_uses_utf8_byte_limits_for_user_fields(self):
        auth = SYNC.sanitize_login_auth({
            "access_token": "access-token",
            "user": {
                "name": "界" * ((SYNC.MAX_LOGIN_USER_FIELD_BYTES // 3) + 1),
                "username": "alice",
            },
        })
        self.assertEqual(auth["user"], {"username": "alice"})

    def test_login_rejects_every_invalid_upstream_user_identity_shape(self):
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()
        owned_user = [
            "9", "alice-example", "user", owner, "alice@example.test",
            "bcrypt-hash", "active",
        ]

        class LoginResponse:
            headers = {}

            def __init__(self, payload):
                self.payload = payload

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return json.dumps(self.payload).encode()

        request = {
            "uuid": self.UUID,
            "username": "alice-example",
            "sub2apiUserId": 9,
            "email": "alice@example.test",
            "loginPassword": "password",
        }
        invalid_users = (
            None,
            {"id": True},
            {"id": "9"},
            {"id": 10},
        )
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", return_value=owned_user
        ):
            for invalid_user in invalid_users:
                data = {"access_token": "test-access-token"}
                if invalid_user is not None:
                    data["user"] = invalid_user
                with self.subTest(invalid_user=invalid_user), mock.patch.object(
                    SYNC.urllib.request,
                    "urlopen",
                    return_value=LoginResponse({"code": 0, "data": data}),
                ), self.assertRaisesRegex(
                    RuntimeError, "sub2api_login_response_identity_mismatch"
                ):
                    SYNC.login(request)

            with mock.patch.object(
                SYNC.urllib.request,
                "urlopen",
                return_value=LoginResponse({"code": 1}),
            ), self.assertRaisesRegex(RuntimeError, "sub2api_login_rejected"):
                SYNC.login(request)

    def test_login_rejects_old_worker_payload_without_existing_ownership(self):
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": "s" * 32},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", return_value=[]
        ) as query, mock.patch.object(
            SYNC.urllib.request, "urlopen"
        ) as urlopen:
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.login({
                    "uuid": self.UUID,
                    "email": "alice@example.test",
                    "loginPassword": "password",
                })

        self.assertIn("sub2api_sync_invite_owners", query.call_args.args[0])
        urlopen.assert_not_called()

    def test_old_token_only_payload_rejects_a_foreign_api_key_owner(self):
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM sub2api_sync_invite_owners o JOIN users u" in sql:
                return ["9", "human-name", "user", owner]
            if "SELECT user_id FROM api_keys WHERE id=41" in sql:
                return ["10"]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(SYNC, "psql") as execute:
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.deprovision({
                    "uuid": self.UUID,
                    "sub2apiApiKeyId": 41,
                })

        execute.assert_not_called()

    def test_deprovision_rejects_an_api_key_owned_by_a_different_user(self):
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM users u" in sql and "u.id=9" in sql:
                return ["9", "alice-example", "user", owner]
            if "SELECT user_id FROM api_keys WHERE id=41" in sql:
                return ["10"]
            raise AssertionError(sql)

        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_SECRET": secret},
            clear=True,
        ), mock.patch.object(
            SYNC, "database_transaction", return_value=nullcontext()
        ), mock.patch.object(
            SYNC, "first_row", side_effect=first_row
        ), mock.patch.object(SYNC, "psql") as execute:
            with self.assertRaisesRegex(RuntimeError, "invite_identity_mismatch"):
                SYNC.deprovision({
                    "uuid": self.UUID,
                    "username": "alice-example",
                    "sub2apiUserId": 9,
                    "sub2apiApiKeyId": 41,
                })

        execute.assert_not_called()

    def test_database_transaction_rolls_back_failed_multistep_write_on_one_connection(self):
        writes = []
        pending_output = []

        class FakeInput:
            def write(self, value):
                if isinstance(value, bytes):
                    value = value.decode()
                writes.append(value)
                if value.startswith("\\echo "):
                    pending_output.append(value.removeprefix("\\echo ").strip() + "\n")

            def flush(self):
                return None

            def close(self):
                return None

        class FakeOutput:
            def readline(self):
                return pending_output.pop(0) if pending_output else ""

            def close(self):
                return None

        process = types.SimpleNamespace(
            stdin=FakeInput(),
            stdout=FakeOutput(),
            poll=lambda: None,
            wait=lambda timeout=None: 0,
            terminate=lambda: None,
            kill=lambda: None,
        )
        environment = {"SUB2API_SYNC_DATABASE_PASSWORD": "test-password"}
        with mock.patch.dict(SYNC.os.environ, environment, clear=True), \
             mock.patch.object(SYNC.subprocess, "Popen", return_value=process) as popen:
            with self.assertRaisesRegex(RuntimeError, "second_write_failed"):
                with SYNC.database_transaction():
                    SYNC.psql("INSERT INTO users (id) VALUES (1);")
                    SYNC.psql("INSERT INTO api_keys (id) VALUES (2);")
                    raise RuntimeError("second_write_failed")

        popen.assert_called_once()
        transcript = "".join(writes)
        self.assertIn("BEGIN;", transcript)
        self.assertIn("INSERT INTO users", transcript)
        self.assertIn("INSERT INTO api_keys", transcript)
        self.assertIn("ROLLBACK;", transcript)
        self.assertNotIn("COMMIT;", transcript)

    def test_healthz_fails_closed_on_a_missing_ownership_schema(self):
        handler = object.__new__(SYNC.Handler)
        handler.path = "/healthz"
        handler.headers = {}
        handler.rfile = io.BytesIO()
        responses = []
        handler.respond = lambda status, payload, extra_headers=None: responses.append(
            (status, payload, extra_headers)
        )

        with mock.patch.object(
            SYNC, "psql", side_effect=RuntimeError("database_command_failed")
        ) as query, mock.patch.object(SYNC, "redis_command") as redis:
            handler.do_GET()

        self.assertEqual(
            responses,
            [(503, {
                "ok": False,
                "error": "dependency_unavailable",
                "retryable": True,
                "requestId": handler.request_id,
            }, {"retry-after": "1"})],
        )
        self.assertIn("sub2api_sync_invite_owners", query.call_args.args[0])
        redis.assert_not_called()

    def test_jsonb_serialization_escapes_quotes_without_retaining_nul(self):
        serialized = SYNC.jsonb({"value": "O'Reilly\x00"})
        self.assertTrue(serialized.endswith("'::jsonb"))
        self.assertNotIn("\x00", serialized)
        self.assertIn("O''Reilly", serialized)

    def test_token_identifier_accepts_current_and_rolling_upgrade_field_names(self):
        aliases = ("sub2apiTokenId", "sub2apiApiKeyId", "tokenId", "apiKeyId")
        for name in aliases:
            with self.subTest(name=name):
                self.assertEqual(SYNC.payload_token_id({name: 41}), 41)
        self.assertEqual(
            SYNC.payload_token_id({"sub2apiTokenId": 41, "tokenId": "41"}),
            41,
        )
        with self.assertRaises(ValueError):
            SYNC.payload_token_id({"sub2apiTokenId": 41, "tokenId": 42})

    def test_token_identifier_rejects_noncanonical_or_lossy_values(self):
        invalid = (True, False, -1, 1.5, "01", "1.0", "-1", 9_007_199_254_740_992)
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                SYNC.payload_token_id({"sub2apiTokenId": value})

    def test_deprovision_disables_token_when_only_current_worker_token_id_exists(self):
        statements = []
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM sub2api_sync_invite_owners o JOIN users u" in sql:
                return ["7", "human-name", "user", owner]
            if "SELECT user_id FROM api_keys WHERE id=41" in sql:
                return ["7"]
            if "u.username=" in sql:
                return []
            raise AssertionError(sql)

        with mock.patch.dict(SYNC.os.environ, {"SUB2API_SYNC_SECRET": secret}, clear=True), \
             mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(SYNC, "first_row", side_effect=first_row), \
             mock.patch.object(SYNC, "psql", side_effect=statements.append):
            result = SYNC.deprovision({
                "uuid": self.UUID,
                "sub2apiTokenId": 41,
            })
        self.assertEqual(result["apiKeyId"], 41)
        self.assertEqual(result["tokenId"], 41)
        self.assertEqual(len(statements), 1)
        self.assertIn("UPDATE api_keys SET status='disabled'", statements[0])
        self.assertIn("WHERE id=41 AND user_id=7", statements[0])
        self.assertNotIn("WHERE user_id=", statements[0])

    def test_purge_deletes_token_when_only_current_worker_token_id_exists(self):
        statements = []
        secret = "s" * 32
        owner = SYNC.hmac.new(
            secret.encode(),
            b"sub2api-invite-owner:v1:" + self.UUID.encode(),
            SYNC.hashlib.sha256,
        ).hexdigest()

        def first_row(sql):
            if "FROM sub2api_sync_invite_owners o JOIN users u" in sql:
                return ["7", "human-name", "user", owner]
            if "SELECT user_id FROM api_keys WHERE id=41" in sql:
                return ["7"]
            if "u.username=" in sql:
                return []
            raise AssertionError(sql)

        with mock.patch.dict(SYNC.os.environ, {"SUB2API_SYNC_SECRET": secret}, clear=True), \
             mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(SYNC, "first_row", side_effect=first_row), \
             mock.patch.object(SYNC, "psql", side_effect=statements.append):
            result = SYNC.purge({
                "uuid": self.UUID,
                "sub2apiTokenId": "41",
            })
        self.assertEqual(result["apiKeyId"], 41)
        self.assertEqual(result["tokenId"], 41)
        self.assertEqual(statements, ["DELETE FROM api_keys WHERE id=41 AND user_id=7;"])

    def test_usage_queries_use_shorter_database_and_client_timeouts(self):
        with mock.patch.object(SYNC, "psql", return_value='{"items":[]}') as execute:
            self.assertEqual(SYNC.query_json_value("SELECT usage"), {"items": []})
        execute.assert_called_once_with(
            "SELECT usage",
            timeout=SYNC.USAGE_DB_CLIENT_TIMEOUT_SECONDS,
            statement_timeout_ms=SYNC.USAGE_DB_STATEMENT_TIMEOUT_MS,
        )

    def test_psql_keeps_normal_timeout_and_accepts_bounded_usage_override(self):
        completed = types.SimpleNamespace(returncode=0, stdout="")
        environment = {"SUB2API_SYNC_DATABASE_PASSWORD": "test-password"}
        with mock.patch.dict(SYNC.os.environ, environment, clear=True), \
             mock.patch.object(SYNC.subprocess, "run", return_value=completed) as run:
            SYNC.psql("SELECT provision;")
            provision_call = run.call_args
            SYNC.psql(
                "SELECT usage;",
                timeout=SYNC.USAGE_DB_CLIENT_TIMEOUT_SECONDS,
                statement_timeout_ms=SYNC.USAGE_DB_STATEMENT_TIMEOUT_MS,
            )
            usage_call = run.call_args
        self.assertEqual(
            provision_call.kwargs["timeout"],
            SYNC.DEFAULT_DB_CLIENT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            provision_call.kwargs["env"]["PGOPTIONS"],
            "-c statement_timeout=3000 -c lock_timeout=2000",
        )
        self.assertEqual(
            usage_call.kwargs["timeout"],
            SYNC.USAGE_DB_CLIENT_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            usage_call.kwargs["env"]["PGOPTIONS"],
            f"-c statement_timeout={SYNC.USAGE_DB_STATEMENT_TIMEOUT_MS} -c lock_timeout=2000",
        )

    def test_usage_metadata_bounds_queries_and_excludes_content(self):
        rows = [
            {"id": 3, "model": "gpt-test", "prompt": "private"},
            {"id": 2, "model": "gpt-test"},
        ]
        calls = []

        def query(sql):
            calls.append(sql)
            return rows if "json_agg(item" in sql else ["gpt-test"]

        result = USAGE.list_usage_logs(query, {"pageSize": 1, "query": "gpt", "timePreset": "7d"})
        self.assertEqual(result["page"]["pageSize"], 1)
        self.assertTrue(result["page"]["hasMore"])
        self.assertEqual(result["page"]["nextCursor"], 3)
        self.assertNotIn("prompt", json.dumps(result).lower())
        self.assertTrue(any("created_at >= now() - interval '604800 seconds'" in sql for sql in calls))

    def test_usage_metadata_bounds_database_controlled_text_fields(self):
        oversized = "x" * 10_000

        def query(sql):
            if "json_agg(item" in sql:
                return [{
                    "id": 3,
                    "requestId": oversized,
                    "model": oversized,
                    "requestedModel": oversized,
                    "requestType": oversized,
                    "inboundEndpoint": oversized,
                    "createdAt": oversized,
                }]
            return [oversized]

        result = USAGE.list_usage_logs(query, {"pageSize": 1})
        item = result["items"][0]
        self.assertLessEqual(len(item["requestId"]), 128)
        self.assertLessEqual(len(item["model"]), 128)
        self.assertLessEqual(len(item["requestedModel"]), 128)
        self.assertLessEqual(len(item["requestType"]), 32)
        self.assertLessEqual(len(item["inboundEndpoint"]), 256)
        self.assertLessEqual(len(item["createdAt"]), 64)
        self.assertLessEqual(len(result["modelOptions"][0]), 128)

    def test_usage_detail_rejects_missing_rows(self):
        with self.assertRaises(ValueError):
            USAGE.get_usage_log_detail(lambda _sql: [], {"id": 1})

    def test_usage_request_type_is_cast_before_empty_fallback(self):
        sql = USAGE.usage_log_select("WHERE id=1", 1)
        self.assertIn("COALESCE(request_type::text,'')", sql)
        self.assertIn("ORDER BY created_at DESC,id DESC", sql)
        self.assertIn("json_agg(item ORDER BY created_at DESC,id DESC)", sql)

    def test_usage_detail_keeps_item_and_items_during_rolling_upgrade(self):
        item = {"id": 7, "model": "gpt-test"}
        result = USAGE.get_usage_log_detail(lambda _sql: [item], {"id": 7})
        self.assertEqual(result["item"]["id"], 7)
        self.assertEqual(result["items"], [result["item"]])

    def test_usage_queries_are_always_bounded_to_thirty_days(self):
        _query, _failed, where = USAGE.usage_log_filters(
            {"timePreset": "all", "dateFrom": "2020-01-01T00:00:00Z"}
        )
        self.assertIn("created_at >= now() - interval '2592000 seconds'", where)
        model_sql = []
        USAGE._MODEL_CACHE.update({"expires_at": 0.0, "items": []})
        USAGE.list_usage_models(lambda sql: model_sql.append(sql) or [])
        self.assertIn("created_at >= now() - interval '2592000 seconds'", model_sql[0])

        detail_sql = []
        with self.assertRaises(ValueError):
            USAGE.get_usage_log_detail(lambda sql: detail_sql.append(sql) or [], {"id": 7})
        self.assertIn("created_at >= now() - interval '2592000 seconds'", detail_sql[0])

    def test_usage_search_treats_sql_wildcards_as_literal_text(self):
        _query, _failed, where = USAGE.usage_log_filters({
            "query": "100%_done!",
            "requestId": "req_%",
            "model": "gpt_%",
        })
        self.assertIn("100!%!_done!!", where)
        self.assertIn("req!_!%", where)
        self.assertIn("gpt!_!%", where)
        self.assertEqual(where.count("ESCAPE '!'"), 4)

    def test_usage_general_search_matches_the_trigram_index_expression(self):
        _query, _failed, where = USAGE.usage_log_filters({"query": "no-match"})
        expression = (
            "(COALESCE(request_id, '') || ' ' || COALESCE(model, '') || ' ' || "
            "COALESCE(requested_model, '') || ' ' || "
            "COALESCE(inbound_endpoint, ''))"
        )
        self.assertIn(expression + " ILIKE", where)
        self.assertNotIn(" OR ", where)

    def test_usage_model_options_are_cached_for_five_minutes(self):
        USAGE._MODEL_CACHE.update({"expires_at": 0.0, "items": []})
        calls = []
        query = lambda sql: calls.append(sql) or ["gpt-test"]
        self.assertEqual(USAGE.list_usage_models(query), ["gpt-test"])
        self.assertEqual(USAGE.list_usage_models(query), ["gpt-test"])
        self.assertEqual(len(calls), 1)
        self.assertEqual(USAGE.MODEL_CACHE_SECONDS, 300)

    def test_usage_model_cache_coalesces_concurrent_cold_queries(self):
        USAGE._MODEL_CACHE.update({"expires_at": 0.0, "items": []})
        worker_count = 8
        ready = threading.Barrier(worker_count + 1)
        query_started = threading.Event()
        release_query = threading.Event()
        calls = []
        calls_lock = threading.Lock()

        def query(sql):
            with calls_lock:
                calls.append(sql)
            query_started.set()
            if not release_query.wait(timeout=2):
                raise AssertionError("model query release timed out")
            return ["gpt-test"]

        def load_models():
            ready.wait(timeout=2)
            return USAGE.list_usage_models(query)

        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(load_models) for _ in range(worker_count)]
            ready.wait(timeout=2)
            query_did_start = query_started.wait(timeout=1)
            time.sleep(0.05)
            release_query.set()
            results = [future.result(timeout=2) for future in futures]

        self.assertTrue(query_did_start)
        self.assertEqual(calls.__len__(), 1)
        self.assertEqual(results, [["gpt-test"]] * worker_count)

    def test_usage_cursor_combines_creation_time_and_id(self):
        _query, _failed, where = USAGE.usage_log_filters({
            "cursorId": 17,
            "cursorCreatedAt": "2026-07-19T00:00:00Z",
        })
        self.assertIn("(created_at,id) <", where)
        self.assertIn(",17)", where)

    def test_usage_cursor_accepts_postgresql_bigint_ids_within_js_safe_range(self):
        usage_id = 4_294_967_296
        _query, _failed, where = USAGE.usage_log_filters({"cursorId": usage_id})
        self.assertIn(f"id < {usage_id}", where)
        detail_sql = []
        result = USAGE.get_usage_log_detail(
            lambda sql: detail_sql.append(sql) or [{"id": usage_id}],
            {"id": usage_id},
        )
        self.assertEqual(result["item"]["id"], usage_id)
        self.assertIn(f"WHERE id={usage_id}", detail_sql[0])
        self.assertEqual(USAGE.clamp_identifier(1.5), 0)
        self.assertEqual(USAGE.clamp_identifier(True), 0)
        self.assertEqual(USAGE.clamp_identifier("12.5"), 0)
        self.assertEqual(USAGE.clamp_identifier("0", 0, 1), 0)
        self.assertEqual(USAGE.clamp_identifier(str(USAGE.MAX_SAFE_ID + 1)), 0)


if __name__ == "__main__":
    unittest.main()
