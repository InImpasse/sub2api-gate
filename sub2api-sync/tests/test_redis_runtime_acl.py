import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
ACL_TOOL = ROOT / "deploy" / "configure-redis-acl.py"
ACL_INTEGRATION = ROOT / "deploy" / "test-redis-runtime-acl.sh"
MIGRATION_ACL_TOOL = ROOT / "deploy" / "configure-redis-migration-acl.py"
COMPOSE = (ROOT / "docker-compose.yml").read_text()
CANARY_COMPOSE = (ROOT / "docker-compose.canary.yml").read_text()


def load_python_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RedisRuntimeACLTests(unittest.TestCase):
    def test_acl_contains_only_password_hashes_and_separate_users(self):
        self.assertTrue(ACL_TOOL.exists())
        acl = load_python_script(ACL_TOOL, "redis_acl_hashes")
        default_password = "default-password-0000000000000001"
        sync_password = "sync-password-00000000000000000002"
        migration_password = "migration-password-000000000000003"
        rendered = "".join((
            acl.render_application_acl(default_password),
            acl.render_nonce_acl(sync_password),
            acl.render_migration_acl(migration_password),
        ))

        self.assertNotIn(default_password, rendered)
        self.assertNotIn(sync_password, rendered)
        self.assertNotIn(migration_password, rendered)
        self.assertIn("#" + hashlib.sha256(default_password.encode()).hexdigest(), rendered)
        self.assertIn("#" + hashlib.sha256(sync_password.encode()).hexdigest(), rendered)
        self.assertIn("#" + hashlib.sha256(migration_password.encode()).hexdigest(), rendered)
        self.assertEqual(acl.render_application_acl(default_password).count("user default "), 1)
        self.assertEqual(rendered.count("user sub2api_sync "), 1)
        self.assertEqual(rendered.count("user sub2api_migration "), 1)

    def test_default_user_is_limited_to_source_audited_keys_and_channels(self):
        acl = load_python_script(ACL_TOOL, "redis_acl_policy")
        rendered = acl.render_application_acl("d" * 32)
        default_line = next(
            line for line in rendered.splitlines() if line.startswith("user default ")
        )

        self.assertNotIn("~*", default_line)
        self.assertIn("+@all -@admin -@dangerous", default_line)
        for key_pattern in (
            "~billing:*",
            "~concurrency:*",
            "~cyber_session_block:*",
            "~refresh_token:*",
            "~sched:*",
            "~sticky_session:*",
            "~umq:*",
            "~sub2api:dashboard:*",
            "~wait:account:*",
        ):
            self.assertIn(key_pattern, default_line)
        for channel in (
            "&auth:cache:invalidate",
            "&subscription:cache:invalidate",
            "&error_passthrough_rules_updated",
            "&tls_fingerprint_profiles_updated",
            "&sub2api:prompt_guard:config:invalidate",
        ):
            self.assertIn(channel, default_line)
        for forbidden in (
            "~sub2api:prompt_audit:payload:*",
            "~image_task:*",
            "~content_moderation:*",
            "~batch_image:*",
            "~openai:response:*",
        ):
            self.assertNotIn(forbidden, default_line)

    def test_runtime_session_keys_are_volatile_and_never_migration_copy_rules(self):
        acl = load_python_script(ACL_TOOL, "redis_acl_runtime_sessions")
        rendered = acl.render_application_acl("d" * 32)
        policy = json.loads(
            (ROOT / "deploy" / "redis-key-prefixes.json").read_text()
        )
        copy_prefixes = {
            entry["prefix"]
            for entries in policy["categories"].values()
            for entry in entries
        }
        discard_rules = {
            entry["prefix"]: entry["reason"]
            for entry in policy["discard_prefixes"]
        }

        for prefix in ("wait:account:", "sticky_session:", "cyber_session_block:"):
            self.assertIn("~" + prefix + "*", rendered)
            self.assertNotIn(prefix, copy_prefixes)
            self.assertIn(prefix, discard_rules)
            self.assertIn("runtime-only", discard_rules[prefix])

    def test_sync_user_can_only_manage_nonce_keys(self):
        acl = load_python_script(ACL_TOOL, "redis_acl_sync")
        rendered = acl.render_nonce_acl("s" * 32)
        sync_line = next(
            line
            for line in rendered.splitlines()
            if line.startswith("user sub2api_sync ")
        )
        self.assertIn("~sub2api-sync:nonce:*", sync_line)
        self.assertIn("-@all +ping +set +ttl +select", sync_line)
        self.assertNotIn("~billing:", sync_line)
        self.assertNotIn("~*", sync_line)
        self.assertNotIn("&*", sync_line)
        self.assertNotIn("sub2api_migration", rendered)

    def test_migration_user_is_offline_nonce_only_and_not_a_runtime_user(self):
        acl = load_python_script(ACL_TOOL, "redis_acl_migration")
        rendered = acl.render_migration_acl("m" * 32)
        migration_line = next(
            line for line in rendered.splitlines()
            if line.startswith("user sub2api_migration ")
        )
        self.assertIn("~sub2api-sync:nonce:*", migration_line)
        self.assertIn("-@all", migration_line)
        for command in ("+config|get", "+restore", "+unlink", "+info", "+dbsize"):
            self.assertIn(command, migration_line)
        self.assertNotIn("+save", migration_line)
        self.assertNotIn("~*", migration_line)
        self.assertNotIn("sub2api_sync", rendered)

    def test_acl_rejects_weak_or_reused_credentials(self):
        acl = load_python_script(ACL_TOOL, "redis_acl_validation")
        with self.assertRaisesRegex(ValueError, "at least 24"):
            acl.render_application_acl("short")
        with self.assertRaisesRegex(ValueError, "distinct"):
            acl.validate_distinct_passwords("x" * 32, "x" * 32)

    def test_check_mode_never_reads_secrets_or_writes_an_acl(self):
        env = os.environ.copy()
        env.pop("REDIS_PASSWORD", None)
        env.pop("SUB2API_SYNC_REDIS_PASSWORD", None)
        result = subprocess.run(
            [ACL_TOOL, "check"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("no secret was read", result.stdout)
        self.assertIn("no file was written", result.stdout)
        migration = subprocess.run(
            [MIGRATION_ACL_TOOL, "check"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("no secret was read", migration.stdout)
        self.assertIn("no file was written", migration.stdout)
        self.assertIn("/run/sub2api-gate", MIGRATION_ACL_TOOL.read_text())

    def test_compose_separates_volatile_app_cache_from_durable_nonce_store(self):
        redis_service = re.search(
            r"^  redis:\n(?P<body>.*?)(?=^  [a-z0-9-]+:|^networks:)",
            COMPOSE,
            re.MULTILINE | re.DOTALL,
        ).group("body")
        nonce_service = re.search(
            r"^  redis-nonce:\n(?P<body>.*?)(?=^  [a-z0-9-]+:|^networks:)",
            COMPOSE,
            re.MULTILINE | re.DOTALL,
        ).group("body")
        self.assertIn("/redis/users.acl", redis_service)
        self.assertIn("target: /etc/redis/users.acl", redis_service)
        self.assertIn("read_only: true", redis_service)
        self.assertIn("/data:rw,noexec,nosuid,nodev", redis_service)
        self.assertNotIn("target: /data\n        bind:", redis_service)
        self.assertIn("--aclfile", redis_service)
        self.assertIn('--appendonly\n      - "no"', redis_service)
        self.assertIn('--save\n      - ""', redis_service)
        self.assertIn("mem_limit: 256m", redis_service)
        self.assertIn('--maxmemory\n      - 128mb', redis_service)
        self.assertIn('--maxmemory-policy\n      - noeviction', redis_service)
        self.assertNotIn("--requirepass", redis_service)

        self.assertIn("/redis/nonce", nonce_service)
        self.assertIn("/redis/nonce-users.acl", nonce_service)
        self.assertIn('--appendonly\n      - "yes"', nonce_service)
        self.assertIn('--appendfsync\n      - "always"', nonce_service)
        self.assertIn('--save\n      - ""', nonce_service)
        self.assertIn("mem_limit: 128m", nonce_service)
        self.assertIn('--maxmemory\n      - 32mb', nonce_service)
        self.assertIn('--maxmemory-policy\n      - noeviction', nonce_service)
        self.assertIn('--aof-use-rdb-preamble\n      - "yes"', nonce_service)
        self.assertNotIn("${REDIS_PASSWORD:", nonce_service)

        self.assertIn("SUB2API_SYNC_REDIS_HOST=redis-nonce", COMPOSE)
        self.assertIn("SUB2API_SYNC_REDIS_USERNAME=sub2api_sync", COMPOSE)
        self.assertIn(
            "SUB2API_SYNC_REDIS_PASSWORD=${SUB2API_SYNC_REDIS_PASSWORD:?",
            COMPOSE,
        )
        self.assertNotIn("SUB2API_SYNC_REDIS_PASSWORD=${REDIS_PASSWORD", COMPOSE)
        self.assertIn("IMAGE_STORAGE_ENABLED=false", COMPOSE)

    def test_empty_preflight_canary_has_no_sync_redis_boundary(self):
        self.assertNotIn("sub2api-sync-canary", CANARY_COMPOSE)
        self.assertNotIn("SUB2API_SYNC_REDIS_PASSWORD", CANARY_COMPOSE)
        self.assertIn("REDIS_HOST: canary-redis", CANARY_COMPOSE)
        self.assertIn('IMAGE_STORAGE_ENABLED: "false"', CANARY_COMPOSE)

    def test_real_redis_acl_gate_is_available(self):
        self.assertTrue(ACL_INTEGRATION.exists())
        source = ACL_INTEGRATION.read_text()
        self.assertIn("volatile application Redis retained data after SIGKILL", source)
        self.assertIn("wait:account:42", source)
        self.assertIn("sticky_session:7:", source)
        self.assertIn("cyber_session_block:", source)
        self.assertIn("application Redis created an RDB or AOF file", source)
        self.assertIn("forbidden content key was writable through Lua", source)
        self.assertIn(
            "forbidden dynamically addressed content key was writable through Lua",
            source,
        )
        self.assertIn("retained data after graceful restart", source)
        self.assertIn("nonce replay succeeded after Redis SIGKILL", source)
        self.assertIn("appendfsync", source)
        self.assertIn("one-time migration user was enabled at runtime", source)


if __name__ == "__main__":
    unittest.main()
