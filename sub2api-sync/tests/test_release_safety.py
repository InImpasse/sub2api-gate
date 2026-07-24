import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yml").read_text()
ENV_EXAMPLE = (ROOT / ".env.example").read_text()
PREFLIGHT = (ROOT / "deploy" / "security-preflight.sh").read_text()
WRANGLER_CONFIG = json.loads("\n".join(
    line
    for line in (ROOT / "worker-allow-ip" / "wrangler.jsonc").read_text().splitlines()
    if not line.lstrip().startswith("//")
))
WORKER_PACKAGE = json.loads((ROOT / "worker-allow-ip" / "package.json").read_text())
NO_CONTENT_LOGGING_TEST = (
    ROOT / "deploy" / "test-sub2api-no-content-logging.sh"
).read_text()
NGINX_TEST_CONFIG = (ROOT / "nginx" / "test-nginx.conf").read_text()
NGINX_CORE_DROP_IN = ROOT / "nginx" / "systemd" / "nginx-core-limit.conf"
SYNC_DOCKERFILE = (ROOT / "sub2api-sync" / "Dockerfile").read_text()
SYNC_CANARY_COMPOSE = (ROOT / "docker-compose.sync-canary.yml").read_text()
SYNC_CANARY_TOOL = (ROOT / "deploy" / "sync-canary.py").read_text()
DEPLOY_README = (ROOT / "deploy" / "README.md").read_text()


class ReleaseSafetyTests(unittest.TestCase):
    def test_stable_compose_isolates_data_services_from_egress(self):
        expected_networks = {
            "sub2api": ["sub2api-data", "sub2api-egress"],
            "sub2api-sync": ["sub2api-data"],
            "postgres": ["sub2api-data"],
            "redis": ["sub2api-data"],
            "redis-nonce": ["sub2api-data"],
        }
        for service, expected in expected_networks.items():
            service_block = re.search(
                rf"^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [a-z0-9-]+:|^networks:)",
                COMPOSE,
                re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(service_block, service)
            network_block = re.search(
                r"^    networks:\n(?P<networks>(?:      - [a-z0-9-]+\n)+)",
                service_block.group("body"),
                re.MULTILINE,
            )
            self.assertIsNotNone(network_block, service)
            self.assertEqual(
                re.findall(
                    r"^      - ([a-z0-9-]+)$",
                    network_block.group("networks"),
                    re.MULTILINE,
                ),
                expected,
                service,
            )

        self.assertEqual(
            COMPOSE.split("\nnetworks:\n", 1)[1].strip(),
            "sub2api-data:\n    internal: true\n  sub2api-egress: {}",
        )

    def test_fixed_runtime_boundary_is_not_exposed_as_env_configuration(self):
        for key in ("BIND_HOST", "SERVER_PORT", "SERVER_MODE", "RUN_MODE"):
            self.assertNotRegex(ENV_EXAMPLE, rf"(?m)^{key}=")

    def test_runtime_images_are_pinned_to_reviewed_release_manifests(self):
        sub2api_image = (
            "weishaw/sub2api@sha256:"
            "469790e0389bf31379978687149280a4e135393ad98a9a401951b6be9b1df444"
        )
        redis_image = (
            "redis@sha256:"
            "9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005"
        )
        self.assertIn(sub2api_image, COMPOSE)
        self.assertIn(redis_image, COMPOSE)
        self.assertIn(sub2api_image, NO_CONTENT_LOGGING_TEST)
        self.assertIn(redis_image, NO_CONTENT_LOGGING_TEST)
        self.assertNotIn(
            "sha256:b87cbfbe092ced8aad40f4ece8c1d1b4d7c7553a77c3c61cc2bc3c2585f90e0b",
            NO_CONTENT_LOGGING_TEST,
        )
        self.assertNotIn(
            "sha256:7aec734b2bb298a1d769fd8729f13b8514a41bf90fcdd1f38ec52267fbaa8ee6",
            NO_CONTENT_LOGGING_TEST,
        )
        self.assertIn("Sub2API 0.1.162", COMPOSE)
        self.assertIn("redis-server --version", COMPOSE)
        self.assertIn("v=8.8.0", COMPOSE)
        sync_image = "sub2api-gate/sub2api-sync:pg18.4-r1"
        self.assertIn(sync_image, COMPOSE)
        self.assertIn(sync_image, SYNC_CANARY_COMPOSE)
        self.assertIn("pull_policy: never", SYNC_CANARY_COMPOSE)
        self.assertNotIn("build:", SYNC_CANARY_COMPOSE)
        self.assertIn("psql (PostgreSQL) 18.4", SYNC_DOCKERFILE)
        self.assertNotIn('"--build"', SYNC_CANARY_TOOL)
        self.assertIn('"--no-build"', SYNC_CANARY_TOOL)
        self.assertIn("require_prebuilt_sync_image", SYNC_CANARY_TOOL)
        self.assertIn("sync image must use the reviewed offline PostgreSQL 18", PREFLIGHT)
        self.assertIn("python3 ./deploy/sync-canary.py prepare-image", DEPLOY_README)
        self.assertIn(
            "sudo python3 deploy/sync-canary.py prepare-image --apply",
            DEPLOY_README,
        )
        self.assertNotIn("build sub2api-sync", DEPLOY_README)

    def test_every_stateful_service_discards_docker_logs(self):
        for service in ("sub2api", "sub2api-sync", "postgres", "redis", "redis-nonce"):
            service_block = re.search(
                rf"^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [a-z0-9-]+:|^networks:)",
                COMPOSE,
                re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(service_block, service)
            self.assertRegex(
                service_block.group("body"),
                r"\n    logging:\n      driver: [\"']?none[\"']?\n",
                service,
            )

    def test_every_runtime_disables_core_dumps(self):
        for service in ("sub2api", "sub2api-sync", "postgres", "redis", "redis-nonce"):
            service_block = re.search(
                rf"^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [a-z0-9-]+:|^networks:)",
                COMPOSE,
                re.MULTILINE | re.DOTALL,
            )
            self.assertIsNotNone(service_block, service)
            self.assertRegex(
                service_block.group("body"),
                r"\n    ulimits:\n(?:.*\n)*?      core:\n        soft: 0\n        hard: 0\n",
                service,
            )

    def test_bare_metal_nginx_core_dump_contract_is_fail_closed(self):
        self.assertIn("worker_rlimit_core 0;", NGINX_TEST_CONFIG)
        self.assertLess(
            NGINX_TEST_CONFIG.index("worker_rlimit_core 0;"),
            NGINX_TEST_CONFIG.index("events {"),
        )
        self.assertTrue(NGINX_CORE_DROP_IN.is_file())
        self.assertEqual(
            NGINX_CORE_DROP_IN.read_text(),
            "[Service]\nLimitCORE=0\n",
        )
        self.assertIn(
            'python3 "$repo_dir/deploy/verify-nginx-core-dumps.py" verify',
            PREFLIGHT,
        )
        self.assertNotIn("systemctl", PREFLIGHT)

    def test_sub2api_runs_non_root_with_a_read_only_root_filesystem(self):
        service_block = re.search(
            r"^  sub2api:\n(?P<body>.*?)(?=^  [a-z0-9-]+:|^networks:)",
            COMPOSE,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(service_block)
        body = service_block.group("body")
        self.assertIn('user: "1000:1000"', body)
        self.assertIn("read_only: true", body)
        self.assertIn("init: true", body)
        self.assertIn("/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700", body)
        self.assertIn("cap_drop:\n      - ALL", body)
        self.assertIn("no-new-privileges:true", body)

    def test_postgres_runs_non_root_with_a_read_only_root_filesystem(self):
        service_block = re.search(
            r"^  postgres:\n(?P<body>.*?)(?=^  [a-z0-9-]+:|^networks:)",
            COMPOSE,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(service_block)
        body = service_block.group("body")
        self.assertIn('user: "70:70"', body)
        self.assertIn("read_only: true", body)
        self.assertIn(
            "/var/run/postgresql:rw,noexec,nosuid,nodev,size=8m,mode=0770,uid=70,gid=70",
            body,
        )
        self.assertIn(
            "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=0700,uid=70,gid=70",
            body,
        )
        self.assertIn("cap_drop:\n      - ALL", body)
        self.assertIn("no-new-privileges:true", body)
        self.assertRegex(
            body,
            r"source: /mnt/data/sub2api-gate/postgres\s+(?:#[^\n]*\n\s*)*target: /var/lib/postgresql\s+bind:\s+create_host_path: false",
        )
        self.assertIn("PGDATA=/var/lib/postgresql/18/docker", body)
        self.assertNotIn("target: /var/lib/postgresql/data", body)
        self.assertNotIn("PGDATA=/var/lib/postgresql/data", body)

    def test_sub2api_runtime_cannot_bootstrap_or_use_the_database_owner(self):
        body = re.search(
            r"^  sub2api:\n(?P<body>.*?)(?=^  [a-z0-9-]+:|^networks:)",
            COMPOSE,
            re.MULTILINE | re.DOTALL,
        ).group("body")
        self.assertIn("AUTO_SETUP=false", body)
        self.assertIn("DATABASE_USER=sub2api_app", body)
        self.assertIn("SUB2API_APP_DATABASE_PASSWORD", body)
        self.assertRegex(
            body,
            r"source: /mnt/data/sub2api-gate/app\s+target: /app/data\s+bind:\s+create_host_path: false",
        )
        self.assertIn("DATA_DIR=/app/data", body)
        self.assertIn("PRICING_DATA_DIR=/app/data", body)
        self.assertNotIn("DATABASE_USER=${POSTGRES_USER", body)
        self.assertNotIn("DATABASE_PASSWORD=${POSTGRES_PASSWORD", body)
        self.assertNotIn("ADMIN_EMAIL", body)
        self.assertNotIn("ADMIN_PASSWORD", body)
        app_migration = (ROOT / "deploy" / "migrate-app-metadata.py").read_text()
        self.assertIn('INSTALL_MARKER_FILENAME = ".installed"', app_migration)
        self.assertIn("0o400", app_migration)
        self.assertIn("os.fchown(descriptor, APP_UID, APP_GID)", app_migration)

    def test_compose_requires_the_mnt_data_layout_without_auto_creation(self):
        self.assertIn("SUB2API_DATA_ROOT=/mnt/data/sub2api-gate", ENV_EXAMPLE)
        self.assertIn(
            "x-required-data-root: ${SUB2API_DATA_ROOT:?SUB2API_DATA_ROOT must be /mnt/data/sub2api-gate}",
            COMPOSE,
        )
        self.assertNotIn("source: ${SUB2API_DATA_ROOT", COMPOSE)
        for source in (
            "/mnt/data/sub2api-gate/app",
            "/mnt/data/sub2api-gate/postgres",
            "/mnt/data/sub2api-gate/redis/users.acl",
            "/mnt/data/sub2api-gate/redis/nonce",
            "/mnt/data/sub2api-gate/redis/nonce-users.acl",
        ):
            self.assertRegex(
                COMPOSE,
                re.compile(
                    rf"source: {re.escape(source)}\s+target: .+?\s+(?:read_only: true\s+)?bind:\s+create_host_path: false",
                    re.MULTILINE,
                ),
            )
        for old_mount in (
            "./data:/app/data",
            "./postgres_data:/var/lib/postgresql/data",
            "./redis_data:/data",
        ):
            self.assertNotIn(old_mount, COMPOSE)

    def test_preflight_requires_exact_private_storage_and_separates_origins(self):
        self.assertIn('require_exact_data_root "/mnt/data/sub2api-gate"', PREFLIGHT)
        self.assertIn("maintenance-cutover-state.json", PREFLIGHT)
        self.assertIn("maintenance-cutover.py --recover", PREFLIGHT)
        for directory in ("app", "postgres", "redis", "safe-backup", "exports"):
            self.assertIn(f'"$data_root/{directory}"', PREFLIGHT)
        self.assertIn(
            "SUB2API_LOGIN_URL and SUB2API_PUBLIC_BASE_URL must use the same origin",
            PREFLIGHT,
        )
        self.assertIn("target: /var/lib/postgresql/data", PREFLIGHT)
        self.assertIn("PGDATA=/var/lib/postgresql/data", PREFLIGHT)
        self.assertIn(
            "public Sub2API hostname must not be present in SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS",
            PREFLIGHT,
        )
        self.assertNotIn("require_url_hostname_in_list", PREFLIGHT)
        for path, owner, mode in (
            ("app", "1000:1000", "700"),
            ("postgres", "70:70", "700"),
            ("redis", "999:1000", "700"),
            ("safe-backup", "0:0", "700"),
            ("exports", "0:0", "700"),
        ):
            self.assertIn(
                f'require_private_path "$data_root/{path}" "{owner}" "{mode}"',
                PREFLIGHT,
            )
        self.assertIn(
            'require_private_path "$data_root/redis/users.acl" "999:1000" "400"',
            PREFLIGHT,
        )
        self.assertIn(
            'require_private_path "$data_root/redis/nonce" "999:1000" "700"',
            PREFLIGHT,
        )
        self.assertIn(
            'require_private_path "$data_root/redis/nonce-users.acl" "999:1000" "400"',
            PREFLIGHT,
        )
        self.assertIn('require_private_path "$data_root" "0:0" "700"', PREFLIGHT)

    def test_preflight_requires_capacity_and_prevents_tmpfs_swap_leakage(self):
        self.assertIn("SUB2API_MIN_FREE_BYTES=10737418240", ENV_EXAMPLE)
        self.assertIn("require_storage_free_space", PREFLIGHT)
        self.assertIn("SUB2API_MIN_FREE_BYTES must be an integer of at least 10737418240", PREFLIGHT)
        self.assertIn("df --output=avail --block-size=1", PREFLIGHT)
        self.assertIn("require_no_active_swap", PREFLIGHT)
        self.assertIn("/proc/swaps", PREFLIGHT)
        self.assertIn("active host swap is forbidden", PREFLIGHT)

    def test_preflight_requires_distinct_application_and_sync_redis_passwords(self):
        self.assertIn("require_value SUB2API_SYNC_REDIS_PASSWORD 24", PREFLIGHT)
        self.assertIn("require_value SUB2API_APP_DATABASE_PASSWORD 24", PREFLIGHT)
        self.assertIn("SUB2API_SYNC_REDIS_PASSWORD", ENV_EXAMPLE)
        self.assertIn("SUB2API_SYNC_REDIS_PASSWORD", PREFLIGHT)

    def test_worker_uses_a_standalone_secret_manifest_and_exact_tool_versions(self):
        self.assertNotIn("secrets", WRANGLER_CONFIG)
        manifest_path = ROOT / "worker-allow-ip" / "required-secrets.json"
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest.get("version"), 1)
        self.assertEqual(
            set(manifest.get("required", [])),
            {
                "TURNSTILE_SECRET_KEY",
                "CLOUDFLARE_API_TOKEN",
                "ADMIN_PASSWORD_PBKDF2",
                "ADMIN_TOTP_SECRET",
                "CREDENTIAL_ENCRYPTION_KEY",
                "INVITE_ACCESS_HMAC_KEY",
                "SUB2API_SYNC_SECRET",
            },
        )
        self.assertEqual(WORKER_PACKAGE["devDependencies"]["wrangler"], "4.112.0")
        self.assertEqual(
            WORKER_PACKAGE["devDependencies"]["miniflare"],
            "4.20260714.0",
        )
        self.assertEqual(WORKER_PACKAGE["overrides"]["sharp"], "0.35.3")
        worker_deploy = (ROOT / "deploy" / "deploy-worker.sh").read_text()
        audit_command = (
            'run_publish_command "$npm_bin" --prefix "$worker_dir" '
            'audit --audit-level=high '
            "--package-lock-only --ignore-scripts"
        )
        self.assertIn(audit_command, worker_deploy)
        self.assertLess(worker_deploy.index(audit_command), worker_deploy.index("deploy --dry-run"))

    def test_safe_migration_tools_are_fail_closed_and_do_not_copy_physical_data(self):
        postgres_migration = (
            ROOT / "deploy" / "migrate-sanitized-postgres.sh"
        ).read_text()
        locked_stream = (
            ROOT / "deploy" / "locked-postgres-stream.py"
        ).read_text()
        redis_migration = (
            ROOT / "deploy" / "migrate-redis-allowlist.py"
        ).read_text()
        app_migration = (ROOT / "deploy" / "migrate-app-metadata.py").read_text()
        self.assertIn('mode="${1:-check}"', postgres_migration)
        self.assertIn("no database connection was opened", postgres_migration)
        self.assertIn("locked-postgres-stream.py", postgres_migration)
        self.assertIn("pg_dump", locked_stream)
        self.assertIn("stdout=self.target.stdin", locked_stream)
        self.assertIn("pg_control_system()", locked_stream)
        self.assertNotIn("pg_basebackup", postgres_migration + locked_stream)
        self.assertNotIn("/var/lib/postgresql/data", postgres_migration + locked_stream)
        self.assertIn("ALLOWED_KEY_PREFIXES", redis_migration)
        self.assertIn("unknown Redis key prefix", redis_migration)
        self.assertIn('expected_version = "8.8.0"', redis_migration)
        self.assertIn("validate_source_values", redis_migration)
        self.assertIn("raw OAuth tokens", redis_migration)
        self.assertIn("model_pricing.json", app_migration)
        for forbidden in ("config.yaml", "logs", "preview", "capture"):
            self.assertIn(forbidden, app_migration)

    def test_safe_export_is_snapshot_based_and_atomically_completed(self):
        safe_export = (ROOT / "deploy" / "export-safe-metadata.sh").read_text()
        self.assertIn("pg_export_snapshot()", safe_export)
        self.assertIn("SET TRANSACTION SNAPSHOT", safe_export)
        self.assertIn("REPEATABLE READ READ ONLY", safe_export)
        self.assertIn(".partial-", safe_export)
        self.assertIn("COMPLETE", safe_export)
        self.assertIn("manifest.json", safe_export)
        self.assertIn("source_postgres_database_oid", safe_export)
        self.assertIn("source_postgres_database_name_hex", safe_export)
        self.assertIn("git_head", safe_export)
        self.assertIn("deploy/locked-postgres-stream.py", safe_export)
        self.assertIn('if [ "$EUID" -ne 0 ]; then', safe_export)
        self.assertIn("sha256sum", safe_export)
        self.assertIn("verify-postgres-portability.sql", safe_export)
        self.assertIn("verify_no_conversation_content.sql", safe_export)
        self.assertIn('source_pg_exec="$repo_dir/deploy/source-postgres-exec.py"', safe_export)
        self.assertNotIn("--source-private-env-file", safe_export)
        self.assertIn('cat "$privacy_gate"', safe_export)
        self.assertIn('cat "$portability_gate"', safe_export)
        self.assertLess(
            safe_export.index('cat "$privacy_gate"'),
            safe_export.index("SELECT pg_export_snapshot()"),
        )
        self.assertLess(
            safe_export.index('cat "$portability_gate"'),
            safe_export.index("SELECT pg_export_snapshot()"),
        )
        self.assertIn("schema_fingerprint.sha256", safe_export)
        self.assertIn("snapshot_holder_stop", safe_export)
        self.assertIn("idle_in_transaction_session_timeout=600000", safe_export)
        self.assertNotIn('> "$partial_dir/schema.sql"', safe_export)
        self.assertNotIn("schema.sql\n", safe_export)
        self.assertNotIn("--format=custom", safe_export)

        postgres_migration = (
            ROOT / "deploy" / "migrate-sanitized-postgres.sh"
        ).read_text()
        locked_stream = (
            ROOT / "deploy" / "locked-postgres-stream.py"
        ).read_text()
        self.assertIn("--no-comments", locked_stream)
        self.assertIn("--no-security-labels", locked_stream)

    def test_production_apply_tools_require_a_clean_worktree(self):
        guarded_tools = (
            "deploy/run-database-migration.sh",
            "deploy/prepare-sync-role.sh",
            "deploy/prepare-app-role.sh",
            "deploy/cleanup-conversation-logs.sh",
            "deploy/export-safe-metadata.sh",
            "deploy/migrate-sanitized-postgres.sh",
            "deploy/migrate-app-metadata.py",
            "deploy/migrate-redis-allowlist.py",
            "deploy/configure-redis-acl.py",
            "deploy/configure-redis-migration-acl.py",
            "deploy/deploy-worker.sh",
            "deploy/generate-worker-secrets.py",
            "deploy/worker-runtime-attestation.py",
            "deploy/configure-cloudflare-aop.py",
            "deploy/traffic-canary.py",
            "deploy/retire-legacy-data.py",
            "deploy/install-nginx-aop.sh",
            "deploy/migrate-cloudflare-comments.mjs",
            "nginx/update-cloudflare-ips.sh",
        )
        for relative_path in guarded_tools:
            with self.subTest(path=relative_path):
                source = (ROOT / relative_path).read_text()
                self.assertIn("require-clean-worktree.sh", source)

    def test_root_release_guard_requires_a_fixed_immutable_production_tree(self):
        guard = (ROOT / "deploy" / "require-clean-worktree.sh").read_text()

        self.assertTrue(guard.startswith("#!/bin/bash\n"))
        self.assertIn('trusted_production_root="/opt/sub2api-gate-release"', guard)
        self.assertIn('if [ "$("$id_binary" -u)" -eq 0 ]; then', guard)
        self.assertIn('release actions require an in-tree Git metadata directory', guard)
        self.assertIn('rev-parse --absolute-git-dir', guard)
        self.assertIn('-c core.fsmonitor=false', guard)
        self.assertIn('-c core.hooksPath=/dev/null', guard)
        self.assertIn('ls-files -v -z', guard)
        self.assertIn('Git index has nonstandard trust flags', guard)
        self.assertIn('[ "$repo_dir" != "$trusted_production_root" ]', guard)
        self.assertIn('! -user root', guard)
        self.assertIn('-perm /022', guard)
        self.assertIn('/proc/self/mountinfo', guard)
        self.assertLess(
            guard.index('if [ "$("$id_binary" -u)" -eq 0 ]; then'),
            guard.index('git -C "$repo_dir" rev-parse'),
        )

    def test_clean_worktree_guard_rejects_external_gitdirs_and_hidden_index_changes(self):
        guard_source = ROOT / "deploy" / "require-clean-worktree.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            repo = root / "release"
            (repo / "deploy").mkdir(parents=True)
            shutil.copy2(guard_source, repo / "deploy" / "require-clean-worktree.sh")
            tracked = repo / "tracked.txt"
            tracked.write_text("trusted\n", encoding="utf-8")
            environment = os.environ.copy()
            environment.update({
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
            })
            for command in (
                ["git", "init", "--quiet"],
                ["git", "add", "deploy/require-clean-worktree.sh", "tracked.txt"],
                [
                    "git",
                    "-c",
                    "user.name=release-test",
                    "-c",
                    "user.email=release-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "initial",
                ],
            ):
                subprocess.run(command, cwd=repo, env=environment, check=True)

            subprocess.run(
                ["git", "update-index", "--assume-unchanged", "tracked.txt"],
                cwd=repo,
                env=environment,
                check=True,
            )
            tracked.write_text("tampered\n", encoding="utf-8")
            hidden_change = subprocess.run(
                ["bash", "deploy/require-clean-worktree.sh"],
                cwd=repo,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(hidden_change.returncode, 0)
            self.assertIn("nonstandard trust flags", hidden_change.stderr)

            git_directory = repo / ".git"
            external_git_directory = root / "external-git"
            git_directory.rename(external_git_directory)
            git_directory.write_text(
                f"gitdir: {external_git_directory}\n", encoding="utf-8"
            )
            external_gitdir = subprocess.run(
                ["bash", "deploy/require-clean-worktree.sh"],
                cwd=repo,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(external_gitdir.returncode, 0)
            self.assertIn("in-tree Git metadata directory", external_gitdir.stderr)

    def test_nginx_has_custom_aop_stages_and_an_unknown_host_sink(self):
        nginx = (ROOT / "nginx" / "sub2api.conf").read_text()
        optional = (ROOT / "nginx" / "snippets" / "sub2api-aop-optional.conf").read_text()
        required = (ROOT / "nginx" / "snippets" / "sub2api-aop-required.conf").read_text()
        installer = (ROOT / "deploy" / "install-nginx-aop.sh").read_text()
        self.assertIn("default_server", nginx)
        self.assertIn("return 444", nginx)
        self.assertIn("sub2api-aop-active.conf", nginx)
        self.assertIn("/etc/nginx/sub2api-gate/aop/client-ca.pem", optional)
        self.assertIn("ssl_verify_client optional", optional)
        self.assertIn("ssl_verify_client on", required)
        self.assertIn('mode="${1:-check}"', installer)
        self.assertIn("nginx -t", installer)
        self.assertIn("restore", installer)


if __name__ == "__main__":
    unittest.main()
