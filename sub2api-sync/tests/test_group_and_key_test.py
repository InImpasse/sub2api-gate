import importlib.util
import io
import json
import pathlib
import sys
import unittest
from contextlib import nullcontext
from unittest import mock
from urllib.error import HTTPError, URLError


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    "sub2api_sync_group_key_test", ROOT / "sub2api_sync.py"
)
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)

UUID = "7c484f74-6d93-43d1-9441-00c7d8d4ab11"
CONVERSATION_SENTINEL = "PRIVATE_CONVERSATION_SENTINEL_key_test"


class GroupCatalogTests(unittest.TestCase):
    def test_configured_groups_reject_default_and_invalid_names(self):
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_DEFAULT_GROUP": "default, openai-default, Default, grok, bad name, .."},
            clear=True,
        ):
            self.assertEqual(
                SYNC.configured_groups(),
                ["openai-default", "grok"],
            )

    def test_configured_groups_fall_back_when_only_default_is_set(self):
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_DEFAULT_GROUP": "default"},
            clear=True,
        ):
            self.assertEqual(SYNC.configured_groups(), ["openai-default"])

    def test_validate_group_name_rejects_default_and_unknown_shapes(self):
        self.assertEqual(SYNC.validate_group_name("openai-default"), "openai-default")
        self.assertEqual(SYNC.validate_group_name("grok"), "grok")
        for invalid in ("default", "Default", "DEFAULT", "", "bad name", "../x", "a" * 65):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                SYNC.validate_group_name(invalid)

    def test_requested_groups_fail_closed_on_explicit_default(self):
        with self.assertRaises(ValueError):
            SYNC.requested_groups({"allowedGroups": ["default"]})
        with self.assertRaises(ValueError):
            SYNC.requested_groups({"allowedGroups": ["unknown!"]})
        with self.assertRaises(ValueError):
            SYNC.requested_groups({"allowedGroups": []})

    def test_requested_groups_accept_real_model_groups_and_token_overrides(self):
        self.assertEqual(
            SYNC.requested_groups({"allowedGroups": ["grok", "openai-default", "grok"]}),
            ["grok", "openai-default"],
        )
        self.assertEqual(
            SYNC.requested_groups({
                "tokens": [{"groupName": "grok", "tokenKey": "sk-" + "a" * 48}],
            }),
            ["grok"],
        )

    def test_requested_groups_fall_back_to_configured_catalog(self):
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_SYNC_DEFAULT_GROUP": "openai-default"},
            clear=True,
        ):
            self.assertEqual(SYNC.requested_groups({}), ["openai-default"])

    def test_list_groups_filters_default_and_is_bounded(self):
        rows = [
            [1, "default", "openai"],
            [2, "openai-default", "openai"],
            [3, "grok", "openai"],
            [4, "bad name", "openai"],
        ] + [[10 + index, f"extra-{index}", "openai"] for index in range(40)]
        with mock.patch.object(SYNC, "rows", return_value=rows) as query:
            catalog = SYNC.load_group_catalog(force=True)

        sql = query.call_args.args[0]
        self.assertIn("FROM groups", sql)
        self.assertIn("LIMIT 33", sql)
        names = [item["name"] for item in catalog]
        self.assertNotIn("default", names)
        self.assertIn("openai-default", names)
        self.assertIn("grok", names)
        self.assertLessEqual(len(catalog), SYNC.MAX_GROUP_CATALOG)
        self.assertTrue(all("id" in item and "name" in item for item in catalog))

    def test_group_catalog_reuses_cache_until_forced(self):
        SYNC._GROUP_CATALOG.clear()
        with mock.patch.object(
            SYNC, "rows", return_value=[[2, "openai-default", "openai"]]
        ) as query:
            first = SYNC.load_group_catalog(force=True)
            second = SYNC.load_group_catalog()
            third = SYNC.load_group_catalog(force=True)
        self.assertEqual(query.call_count, 2)
        self.assertEqual(first, second)
        self.assertEqual(second, third)

    def test_list_groups_action_returns_metadata_only(self):
        with mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(
                 SYNC,
                 "load_group_catalog",
                 return_value=[{"id": 2, "name": "openai-default", "platform": "openai"}],
             ):
            result = SYNC.list_groups({})
        self.assertEqual(result["ok"], True)
        self.assertEqual(result["action"], "list_groups")
        self.assertEqual(result["groups"][0]["name"], "openai-default")
        encoded = json.dumps(result)
        self.assertNotIn("prompt", encoded)
        self.assertNotIn("content", encoded)

    def test_resolve_provision_groups_uses_ensure_groups_for_configured_fallback(self):
        with mock.patch.object(
            SYNC, "ensure_groups", return_value=[("openai-default", 2)]
        ) as ensure:
            groups = SYNC.resolve_provision_groups({})
        self.assertEqual(groups, [("openai-default", 2)])
        ensure.assert_called_once_with()

    def test_resolve_provision_groups_looks_up_existing_non_configured_groups(self):
        with mock.patch.object(SYNC, "configured_groups", return_value=["openai-default"]), \
             mock.patch.object(SYNC, "lookup_active_group_id", return_value=9) as lookup, \
             mock.patch.object(SYNC, "ensure_group") as ensure:
            groups = SYNC.resolve_provision_groups({"allowedGroups": ["grok"]})
        self.assertEqual(groups, [("grok", 9)])
        lookup.assert_called_once_with("grok")
        ensure.assert_not_called()

    def test_resolve_provision_groups_fail_closed_when_group_is_missing(self):
        with mock.patch.object(SYNC, "configured_groups", return_value=["openai-default"]), \
             mock.patch.object(SYNC, "lookup_active_group_id", return_value=None):
            with self.assertRaises(ValueError):
                SYNC.resolve_provision_groups({"allowedGroups": ["grok"]})

    def test_group_profile_recognizes_grok(self):
        self.assertEqual(SYNC.group_profile("grok")[0], "openai")
        self.assertIn("Grok", SYNC.group_profile("grok")[1])

    def test_ensure_group_sets_default_rate_only_on_insert(self):
        with mock.patch.object(SYNC, "psql") as execute, \
             mock.patch.object(SYNC, "lookup_active_group_id", return_value=9):
            self.assertEqual(SYNC.ensure_group("openai-default"), 9)

        sql = execute.call_args.args[0]
        insert_sql, update_sql = sql.split("UPDATE groups SET", 1)
        self.assertIn("rate_multiplier", insert_sql)
        self.assertNotIn("rate_multiplier", update_sql)


class ProvisionSelectedGroupTests(unittest.TestCase):
    def test_provision_assigns_only_the_selected_group(self):
        statements = []
        secret = "s" * 32

        def first_row(sql):
            if "SELECT password_hash" in sql:
                return ["bcrypt-hash"]
            raise AssertionError(sql)

        with mock.patch.dict(SYNC.os.environ, {"SUB2API_SYNC_SECRET": secret}, clear=True), \
             mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(
                 SYNC, "resolve_invite_user", return_value=["9", "alice", "user", ""]
             ), \
             mock.patch.object(
                 SYNC, "resolve_provision_groups", return_value=[("grok", 7)]
             ), \
             mock.patch.object(SYNC, "ensure_subscription_plan") as plan, \
             mock.patch.object(SYNC, "ensure_default_subscription") as subscription, \
             mock.patch.object(SYNC, "sync_user_keys", return_value=(3, "sk-" + "a" * 48)) as keys, \
             mock.patch.object(SYNC, "get_user_keys", return_value=[]), \
             mock.patch.object(SYNC, "first_row", side_effect=first_row), \
             mock.patch.object(SYNC, "psql", side_effect=statements.append), \
             mock.patch.object(SYNC, "password_hash_fingerprint", return_value="f" * 64):
            result = SYNC.provision({
                "uuid": UUID,
                "username": "alice",
                "sub2apiUserId": 9,
                "allowedGroups": ["grok"],
                "tokens": [],
            })

        self.assertEqual(result["allowedGroups"], ["grok"])
        plan.assert_called_once_with(7)
        subscription.assert_called_once_with(9, 7)
        self.assertEqual(keys.call_args.args[1], 7)
        self.assertTrue(any("user_allowed_groups" in sql and ",7," in sql for sql in statements))
        self.assertFalse(any(",2," in sql and "user_allowed_groups" in sql for sql in statements))

    def test_requested_tokens_carry_group_name(self):
        key = "sk-" + "a" * 48
        tokens = SYNC.requested_tokens({
            "tokens": [{"tokenKey": key, "tokenName": "primary", "groupName": "grok"}],
        })
        self.assertEqual(tokens, [{"key": key, "name": "primary", "groupName": "grok"}])

    def test_get_user_keys_includes_group_name_without_content_fields(self):
        with mock.patch.object(
            SYNC,
            "rows",
            return_value=[[1, "Sub2API", "sk-" + "a" * 48, "active", "0", "0", "openai-default"]],
        ) as query:
            keys = SYNC.get_user_keys(9)
        sql = query.call_args.args[0]
        self.assertIn("JOIN groups", sql)
        self.assertEqual(keys[0]["groupName"], "openai-default")
        self.assertNotIn("prompt", sql.lower())
        self.assertNotIn("response_body", sql.lower())


class ApiKeyTestActionTests(unittest.TestCase):
    def test_internal_models_url_is_derived_from_the_login_url(self):
        with mock.patch.dict(
            SYNC.os.environ,
            {"SUB2API_INTERNAL_LOGIN_URL": "http://sub2api:8080/api/v1/auth/login"},
            clear=True,
        ):
            self.assertEqual(
                SYNC.internal_models_url(),
                "http://sub2api:8080/v1/models",
            )

    def test_internal_models_url_rejects_unexpected_hosts_and_paths(self):
        for value in (
            "http://169.254.169.254/api/v1/auth/login",
            "http://sub2api:8080/api/v1/auth/login?next=1",
            "https://api.openai.com/api/v1/auth/login",
            "http://user:pass@sub2api:8080/api/v1/auth/login",
        ):
            with self.subTest(value=value), mock.patch.dict(
                SYNC.os.environ, {"SUB2API_INTERNAL_LOGIN_URL": value}, clear=True
            ):
                with self.assertRaises(ValueError):
                    SYNC.internal_models_url()

    def test_key_test_success_returns_bounded_metadata_without_bodies(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return json.dumps({
                    "object": "list",
                    "data": [
                        {"id": "gpt-5.6", "object": "model"},
                        {"id": "gpt-5.6-mini", "object": "model"},
                    ],
                    "choices": [{"message": {"content": CONVERSATION_SENTINEL}}],
                }).encode()

            headers = {"content-length": "200"}

        captured = {}

        def urlopen(request, timeout=None):
            captured["url"] = request.full_url
            captured["authorization"] = request.get_header("Authorization")
            captured["timeout"] = timeout
            captured["method"] = request.get_method()
            return FakeResponse()

        with mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(
                 SYNC, "resolve_invite_user", return_value=["9", "alice", "user", ""]
             ), \
             mock.patch.object(
                 SYNC, "first_row", return_value=[21, "sk-" + "a" * 48]
             ), \
             mock.patch.object(SYNC, "internal_models_url", return_value="http://sub2api:8080/v1/models"), \
             mock.patch.object(SYNC.urllib.request, "urlopen", side_effect=urlopen):
            result = SYNC.test_api_key({
                "uuid": UUID,
                "sub2apiUserId": 9,
                "apiKeyId": 21,
            })

        self.assertEqual(result["ok"], True)
        self.assertEqual(result["action"], "test_api_key")
        self.assertEqual(result["tested"], True)
        self.assertEqual(result["httpStatus"], 200)
        self.assertEqual(result["modelCount"], 2)
        self.assertEqual(result["modelId"], "gpt-5.6")
        self.assertEqual(captured["url"], "http://sub2api:8080/v1/models")
        self.assertEqual(captured["method"], "GET")
        encoded = json.dumps(result)
        self.assertNotIn(CONVERSATION_SENTINEL, encoded)
        self.assertNotIn("choices", encoded)
        self.assertNotIn("sk-", encoded)
        self.assertNotIn("content", encoded)

    def test_key_test_unauthorized_is_failure_without_upstream_body(self):
        error = HTTPError(
            "http://sub2api:8080/v1/models",
            401,
            "Unauthorized",
            {},
            io.BytesIO(json.dumps({
                "error": {"message": CONVERSATION_SENTINEL, "type": "invalid_request_error"},
            }).encode()),
        )
        with mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(
                 SYNC, "resolve_invite_user", return_value=["9", "alice", "user", ""]
             ), \
             mock.patch.object(
                 SYNC, "first_row", return_value=[21, "sk-" + "a" * 48]
             ), \
             mock.patch.object(SYNC, "internal_models_url", return_value="http://sub2api:8080/v1/models"), \
             mock.patch.object(SYNC.urllib.request, "urlopen", side_effect=error):
            result = SYNC.test_api_key({
                "uuid": UUID,
                "sub2apiUserId": 9,
                "apiKeyId": 21,
            })

        self.assertEqual(result["tested"], False)
        self.assertEqual(result["httpStatus"], 401)
        self.assertEqual(result["errorCode"], "unauthorized")
        encoded = json.dumps(result)
        self.assertNotIn(CONVERSATION_SENTINEL, encoded)
        self.assertNotIn("invalid_request_error", encoded)

    def test_key_test_timeout_is_failure_without_retrying_as_a_write(self):
        with mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(
                 SYNC, "resolve_invite_user", return_value=["9", "alice", "user", ""]
             ), \
             mock.patch.object(
                 SYNC, "first_row", return_value=[21, "sk-" + "a" * 48]
             ), \
             mock.patch.object(SYNC, "internal_models_url", return_value="http://sub2api:8080/v1/models"), \
             mock.patch.object(
                 SYNC.urllib.request,
                 "urlopen",
                 side_effect=URLError(TimeoutError("timed out")),
             ):
            result = SYNC.test_api_key({
                "uuid": UUID,
                "sub2apiUserId": 9,
                "apiKeyId": 21,
            })

        self.assertEqual(result["tested"], False)
        self.assertEqual(result["errorCode"], "timeout")
        self.assertEqual(result["httpStatus"], 0)

    def test_key_test_missing_key_does_not_probe_upstream(self):
        probed = False

        def urlopen(*_args, **_kwargs):
            nonlocal probed
            probed = True
            raise AssertionError("upstream must not be contacted")

        with mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(
                 SYNC, "resolve_invite_user", return_value=["9", "alice", "user", ""]
             ), \
             mock.patch.object(SYNC, "first_row", return_value=None), \
             mock.patch.object(SYNC.urllib.request, "urlopen", side_effect=urlopen):
            with self.assertRaisesRegex(ValueError, "api_key_not_found"):
                SYNC.test_api_key({"uuid": UUID, "apiKeyId": 21, "sub2apiUserId": 9})
        self.assertFalse(probed)

    def test_sanitize_models_probe_ignores_non_model_payloads(self):
        count, model_id = SYNC._sanitize_models_probe({
            "object": "list",
            "data": [
                {"id": "not a model", "object": "model"},
                {"id": "gpt-5.6-sol", "object": "model"},
                {"choices": [{"message": {"content": CONVERSATION_SENTINEL}}]},
            ],
            "choices": [{"message": {"content": CONVERSATION_SENTINEL}}],
        })
        self.assertEqual(count, 1)
        self.assertEqual(model_id, "gpt-5.6-sol")
        self.assertEqual(SYNC._sanitize_models_probe("not-json"), (0, ""))

    def test_key_test_does_not_send_prompts_or_chat_completions(self):
        captured = {}

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _size):
                return b'{"data":[]}'

            headers = {}

        def urlopen(request, timeout=None):
            captured["url"] = request.full_url
            captured["data"] = request.data
            captured["method"] = request.get_method()
            return FakeResponse()

        with mock.patch.object(SYNC, "database_transaction", return_value=nullcontext()), \
             mock.patch.object(
                 SYNC, "resolve_invite_user", return_value=["9", "alice", "user", ""]
             ), \
             mock.patch.object(
                 SYNC, "first_row", return_value=[21, "sk-" + "a" * 48]
             ), \
             mock.patch.object(SYNC, "internal_models_url", return_value="http://sub2api:8080/v1/models"), \
             mock.patch.object(SYNC.urllib.request, "urlopen", side_effect=urlopen):
            result = SYNC.test_api_key({"uuid": UUID, "apiKeyId": 21, "sub2apiUserId": 9})

        self.assertTrue(result["tested"])
        self.assertIsNone(captured["data"])
        self.assertNotIn("/chat/", captured["url"])
        self.assertNotIn("/responses", captured["url"])


if __name__ == "__main__":
    unittest.main()
