import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
COMPOSE = (ROOT / "docker-compose.yml").read_text()
DEPLOYMENT = (ROOT / "deploy" / "README.md").read_text()
CLEANUP = (ROOT / "deploy" / "cleanup-conversation-logs.sh").read_text()
SAFE_EXPORT_PATH = ROOT / "deploy" / "export-safe-metadata.sh"
SAFE_EXPORT = SAFE_EXPORT_PATH.read_text()
COMMENT_MIGRATION = (ROOT / "deploy" / "migrate-cloudflare-comments.mjs").read_text()
LEAST_PRIVILEGE = (ROOT / "migrations" / "003_sync_least_privilege.sql").read_text()
RESIDUE_CHECK = ROOT / "migrations" / "verify_no_conversation_content.sql"
GUARD_CHECK = ROOT / "migrations" / "verify_conversation_guards.sql"
PRIVACY_GUARDS = ROOT / "migrations" / "002_remove_conversation_capture.sql"
PG18_PRIVACY_TEST = ROOT / "deploy" / "test-privacy-migration-pg18.sh"
PG18_USAGE_TEST = ROOT / "deploy" / "test-usage-metadata-pg18.sh"
PG18_GROUP_TEST = ROOT / "deploy" / "test-default-group-migration-pg18.sh"
PG18_SYNC_ROLE_TEST = ROOT / "deploy" / "test-sync-role-least-privilege-pg18.sh"
PG18_APP_ROLE_TEST = ROOT / "deploy" / "test-app-role-least-privilege-pg18.sh"
PG18_PORTABILITY_TEST = ROOT / "deploy" / "test-postgres-portability-pg18.sh"
REDIS_NONCE_TEST = ROOT / "deploy" / "test-sync-nonce-redis.sh"
NGINX_TEST = ROOT / "deploy" / "test-nginx-config.sh"
SUB2API_LOG_TEST = ROOT / "deploy" / "test-sub2api-no-content-logging.sh"
MIGRATION_RUNNER = ROOT / "deploy" / "run-database-migration.sh"
MIGRATION_TOTP = ROOT / "deploy" / "verify-migration-totp.py"
SECRET_GENERATOR = ROOT / "deploy" / "generate-worker-secrets.py"
SECURITY_PREFLIGHT = ROOT / "deploy" / "security-preflight.sh"
CLOUDFLARE_IP_UPDATER = ROOT / "nginx" / "update-cloudflare-ips.sh"
WORKER_DEPLOY = ROOT / "deploy" / "deploy-worker.sh"
PREPARE_SYNC_ROLE = ROOT / "deploy" / "prepare-sync-role.sh"
PREPARE_SYNC_ROLE_SQL = ROOT / "migrations" / "000_prepare_sync_role.sql"
PREPARE_APP_ROLE = ROOT / "deploy" / "prepare-app-role.sh"
APP_ROLE_SQL = ROOT / "migrations" / "005_app_least_privilege.sql"
USAGE_INDEXES = ROOT / "migrations" / "004_usage_cursor_indexes.sql"


class DeploymentConfigTests(unittest.TestCase):
    def test_main_compose_cannot_override_nginx_port_or_runtime_mode(self):
        docker = shutil.which("docker")
        if docker is None:
            self.skipTest("docker CLI is unavailable")

        env = os.environ.copy()
        env.update(
            {
                "BIND_HOST": "0.0.0.0",
                "SERVER_PORT": "18080",
                "SERVER_MODE": "debug",
                "RUN_MODE": "development",
            }
        )
        result = subprocess.run(
            [
                docker,
                "compose",
                "--env-file",
                ROOT / ".env.example",
                "-f",
                ROOT / "docker-compose.yml",
                "config",
                "--format",
                "json",
            ],
            cwd=ROOT,
            env=env,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        app = json.loads(result.stdout)["services"]["sub2api"]
        self.assertEqual(
            app["ports"],
            [
                {
                    "mode": "ingress",
                    "host_ip": "127.0.0.1",
                    "target": 8080,
                    "published": "8080",
                    "protocol": "tcp",
                }
            ],
        )
        self.assertEqual(app["environment"]["SERVER_MODE"], "release")
        self.assertEqual(app["environment"]["RUN_MODE"], "standard")

    def test_sync_role_migration_creates_private_invite_ownership_mapping(self):
        self.assertIn(
            "CREATE TABLE IF NOT EXISTS public.sub2api_sync_invite_owners",
            LEAST_PRIVILEGE,
        )
        self.assertIn("invite_fingerprint char(64) NOT NULL UNIQUE", LEAST_PRIVILEGE)
        self.assertIn("CHECK (invite_fingerprint ~ '^[0-9a-f]{64}$')", LEAST_PRIVILEGE)
        self.assertIn("REFERENCES public.users(id) ON DELETE CASCADE", LEAST_PRIVILEGE)
        self.assertIn("public.sub2api_sync_invite_owners", LEAST_PRIVILEGE)
        self.assertNotIn("invite_uuid", LEAST_PRIVILEGE)

    def test_postgres_18_gates_default_to_the_reviewed_digest(self):
        digest = (
            "postgres@sha256:"
            "9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
        )
        for path in (
            PG18_PRIVACY_TEST,
            PG18_USAGE_TEST,
            PG18_GROUP_TEST,
            PG18_SYNC_ROLE_TEST,
            PG18_APP_ROLE_TEST,
            PG18_PORTABILITY_TEST,
        ):
            with self.subTest(path=path.name):
                script = path.read_text()
                self.assertIn(f"${{POSTGRES_TEST_IMAGE:-{digest}}}", script)
                self.assertIn("postgres --version", script)

    def test_sub2api_stdout_is_not_persisted_by_docker(self):
        sub2api_service = COMPOSE.split("  sub2api:\n", 1)[1].split("\n  postgres:\n", 1)[0]
        self.assertIn('logging:\n      driver: "none"', sub2api_service)
        self.assertIn("LOG_OUTPUT_TO_FILE=false", sub2api_service)
        self.assertIn("LOG_OUTPUT_TO_STDOUT=true", sub2api_service)
        self.assertIn("SECURITY_URL_ALLOWLIST_ENABLED=true", sub2api_service)
        self.assertIn("SECURITY_URL_ALLOWLIST_ALLOW_INSECURE_HTTP=false", sub2api_service)
        self.assertIn("SECURITY_URL_ALLOWLIST_ALLOW_PRIVATE_HOSTS=false", sub2api_service)
        self.assertIn("SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS=${SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS:?", sub2api_service)
        self.assertIn("SUB2API_SYNC_DATABASE_USER=sub2api_sync", COMPOSE)
        self.assertNotIn("SUB2API_SYNC_DATABASE_USER=${", COMPOSE)
        for secret in (
            "SUB2API_APP_DATABASE_PASSWORD",
            "REDIS_PASSWORD",
            "SUB2API_SYNC_REDIS_PASSWORD",
            "JWT_SECRET",
            "TOTP_ENCRYPTION_KEY",
        ):
            self.assertIn(f"${{{secret}:?{secret} is required}}", COMPOSE)
        self.assertIn("--aclfile", COMPOSE)
        self.assertNotIn("--requirepass", COMPOSE)
        self.assertIn("--appendonly\n      - \"no\"", COMPOSE)
        self.assertIn("--appendonly\n      - \"yes\"", COMPOSE)
        self.assertIn("--appendfsync\n      - \"always\"", COMPOSE)
        self.assertGreaterEqual(COMPOSE.count("--save\n      - \"\""), 2)
        self.assertIn("DATABASE_USER=sub2api_app", COMPOSE)
        self.assertIn("AUTO_SETUP=false", COMPOSE)
        self.assertNotIn("AUTO_SETUP=true", COMPOSE)

    def test_compose_uses_deployable_repo_digests_not_image_config_ids(self):
        for image in ("weishaw/sub2api@sha256:", "postgres@sha256:", "redis@sha256:"):
            self.assertIn(image, COMPOSE)
        for invalid_config_digest in (
            "8ff5c02e4baec3d7e6182f3142494cc7862a9d2cb5fa8ad29d2a55857bae89f1",
            "1b1689b20d16a014a3d195653381cf2caa75a41a92d93b255a9d6ea29fd353aa",
        ):
            self.assertNotIn(invalid_config_digest, COMPOSE)

    def test_cleanup_can_verify_logs_do_not_reappear(self):
        self.assertIn("verify", CLEANUP)
        self.assertIn("conversation-capable log files still exist", CLEANUP)
        self.assertIn("reject_broad_root", CLEANUP)
        self.assertIn("realpath -e", CLEANUP)
        self.assertIn("--legacy-container", CLEANUP)
        self.assertIn("recorded legacy Docker LogPath still exists", CLEANUP)
        self.assertIn("legacy container still exists", CLEANUP)
        for pattern in (
            "sub2api-response.log*",
            "sub2api-capture.log*",
            "*response-preview*",
            "*/logs/sub2api*.log*",
        ):
            self.assertIn(pattern, CLEANUP)

    def test_safe_export_does_not_interpolate_output_paths_into_sql(self):
        self.assertIn("TO STDOUT WITH (FORMAT CSV, HEADER true)", SAFE_EXPORT)
        self.assertNotIn("TO '$backup_dir", SAFE_EXPORT)
        self.assertNotIn("request_body", SAFE_EXPORT)
        self.assertNotIn("response_body", SAFE_EXPORT)
        self.assertNotIn('psql "$SUB2API_DATABASE_URL"', SAFE_EXPORT)
        self.assertNotIn('pg_dump "$SUB2API_DATABASE_URL"', SAFE_EXPORT)
        self.assertNotIn('PGDATABASE="$SUB2API_DATABASE_URL"', SAFE_EXPORT)
        self.assertIn(
            'source_pg_exec="$repo_dir/deploy/source-postgres-exec.py"',
            SAFE_EXPORT,
        )

    def test_safe_export_check_mode_needs_no_database_credentials(self):
        env = os.environ.copy()
        env.pop("SUB2API_DATABASE_URL", None)
        result = subprocess.run(
            [SAFE_EXPORT_PATH, "check"],
            cwd=ROOT,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("no database connection was opened", result.stdout)

    def test_comment_migration_is_read_only_unless_apply_is_explicit(self):
        self.assertIn('process.argv[2] || "check"', COMMENT_MIGRATION)
        self.assertIn('if (mode === "check")', COMMENT_MIGRATION)
        self.assertLess(
            COMMENT_MIGRATION.index('if (mode === "check")'),
            COMMENT_MIGRATION.index("process.env.CLOUDFLARE_ACCOUNT_ID"),
        )
        self.assertIn("cloudflare_comment_offline_check_failed", COMMENT_MIGRATION)
        self.assertIn('{ method: "PUT"', COMMENT_MIGRATION)
        self.assertNotIn("offset += 100", COMMENT_MIGRATION)
        self.assertIn("JSON.stringify(replacement.items)", COMMENT_MIGRATION)
        self.assertIn("assertCloudflareListSnapshot", COMMENT_MIGRATION)
        self.assertIn("readCloudflareJson(response)", COMMENT_MIGRATION)
        self.assertNotIn("response.json()", COMMENT_MIGRATION)

    def test_database_migration_runner_is_read_only_by_default(self):
        self.assertTrue(MIGRATION_RUNNER.exists())
        script = MIGRATION_RUNNER.read_text()
        self.assertIn('mode="${2:-check}"', script)
        self.assertIn('if [ "$mode" != "--apply" ]', script)
        self.assertIn("no database connection was opened", script)
        self.assertIn("every database migration --apply requires --env-file", script)
        self.assertNotIn("eval ", script)
        self.assertNotIn("SUB2API_DATABASE_URL", script)
        self.assertNotIn('--dbname="$SUB2API_DATABASE_URL"', script)
        self.assertNotIn('PGDATABASE="$SUB2API_DATABASE_URL"', script)
        self.assertIn(
            '"$PYTHON3" -I "$pg_env_exec" --target-private-env-file "$env_file"', script
        )
        self.assertIn('source_pg_exec="$repo_dir/deploy/source-postgres-exec.py"', script)
        self.assertIn("--source-app-container", script)
        self.assertIn("--source-app-id", script)
        self.assertIn("--source-postgres-container", script)
        self.assertIn("--source-postgres-id", script)
        self.assertIn("privacy_deadline_seconds=300", script)
        self.assertIn('"$TIMEOUT" --foreground -s TERM -k 5', script)
        self.assertIn("lock_timeout=5000", script)
        self.assertIn("statement_timeout=30000", script)
        self.assertIn("statement_timeout=180000", script)
        self.assertIn("idle_in_transaction_session_timeout=30000", script)
        self.assertIn('run_source_sql "$privacy_guard_options"', script)
        self.assertIn('run_source_sql "$privacy_scrub_options"', script)
        source_function = script.split("run_source_sql() {", 1)[1].split("\n}", 1)[0]
        self.assertIn('< "$repo_dir/$sql_file"', source_function)
        self.assertNotIn("--file", source_function)
        for target in ("privacy", "sync-role", "default-group", "usage-indexes"):
            self.assertIn(f"{target})", script)
        self.assertLess(
            script.index("run_sql migrations/audit_default_group.sql"),
            script.index("run_sql migrations/001_default_to_openai_default.sql"),
        )
        self.assertLess(
            script.index(
                'run_source_sql "$privacy_guard_options" '
                "migrations/002_remove_conversation_capture.sql"
            ),
            script.index(
                'run_source_sql "$privacy_read_options" '
                "migrations/verify_conversation_guards.sql"
            ),
        )
        self.assertLess(
            script.index(
                'run_source_sql "$privacy_read_options" '
                "migrations/verify_conversation_guards.sql"
            ),
            script.index(
                'run_source_sql "$privacy_scrub_options" '
                "migrations/002_scrub_conversation_history.sql"
            ),
        )
        self.assertLess(
            script.index(
                'run_source_sql "$privacy_scrub_options" '
                "migrations/002_scrub_conversation_history.sql"
            ),
            script.index(
                'run_source_sql "$privacy_read_options" '
                "migrations/verify_no_conversation_content.sql"
            ),
        )

    def test_privacy_apply_requires_totp_before_database_credentials_or_psql(self):
        script = MIGRATION_RUNNER.read_text()
        self.assertTrue(MIGRATION_TOTP.exists())
        self.assertIn("reads the administrator TOTP secret", DEPLOYMENT)
        self.assertIn("never pass either value through arguments or environment variables", DEPLOYMENT)
        self.assertIn('"$PYTHON3" -I "$repo_dir/deploy/verify-migration-totp.py"', script)
        verifier_index = script.index('"$PYTHON3" -I "$repo_dir/deploy/verify-migration-totp.py"')
        self.assertLess(
            verifier_index,
            script.index('"$PYTHON3" -I "$source_pg_exec"'),
        )

        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            psql_marker = directory_path / "psql-called"
            fake_psql = directory_path / "psql"
            fake_psql.write_text(
                "#!/bin/sh\n"
                f"touch {psql_marker}\n"
                "exit 99\n"
            )
            fake_psql.chmod(0o700)
            env = os.environ.copy()
            env["PATH"] = f"{directory_path}:{env['PATH']}"
            env["SUB2API_DATABASE_URL"] = "must-not-be-read-before-totp"
            result = subprocess.run(
                [
                    "bash",
                    MIGRATION_RUNNER,
                    "privacy",
                    "--apply",
                    "--env-file",
                    "/private/not-opened-before-totp.env",
                    "--source-app-container",
                    "legacy-app",
                    "--source-app-id",
                    "a" * 64,
                    "--source-postgres-container",
                    "legacy-postgres",
                    "--source-postgres-id",
                    "b" * 64,
                ],
                cwd=ROOT,
                env=env,
                input="",
                capture_output=True,
                text=True,
                check=False,
            )
            psql_called = psql_marker.exists()
        self.assertNotEqual(result.returncode, 0)
        # A dirty release tree is now rejected before any interactive TOTP
        # input. In a clean release tree the verifier remains the next gate.
        self.assertTrue(
            "requires root" in result.stderr
            or "interactive TTY" in result.stderr
            or "Git worktree is dirty" in result.stderr
        )
        self.assertFalse(psql_called)

    def test_privacy_apply_loads_only_the_private_source_after_totp(self):
        script = MIGRATION_RUNNER.read_text()
        totp_call = '"$PYTHON3" -I "$repo_dir/deploy/verify-migration-totp.py" verify'
        source_loader = '"$PYTHON3" -I "$source_pg_exec"'

        self.assertIn("privacy --apply requires the private file", script)
        self.assertIn(totp_call, script)
        self.assertEqual(script.count(totp_call), 1)
        self.assertIn(source_loader, script)
        self.assertLess(script.index(totp_call), script.index(source_loader))
        privacy_case = script[script.index("case \"$target\" in", script.index("run_sql()")):]
        self.assertNotIn("SUB2API_DATABASE_URL", privacy_case.split("sync-role)", 1)[0])

    def test_privacy_check_needs_no_database_or_totp_input(self):
        env = os.environ.copy()
        env.pop("SUB2API_DATABASE_URL", None)
        result = subprocess.run(
            ["bash", MIGRATION_RUNNER, "privacy", "check"],
            cwd=ROOT,
            env=env,
            input="",
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(result.stderr, "")
        self.assertIn("check only; no database connection was opened", result.stdout)
        self.assertNotIn("Migration TOTP secret:", result.stdout)
        self.assertNotIn("Migration TOTP code:", result.stdout)

    def test_every_apply_requires_an_absolute_private_environment(self):
        for target in (
            "privacy",
            "sync-role",
            "default-group",
            "usage-indexes",
            "verify-content",
            "audit-default-group",
        ):
            with self.subTest(target=target):
                result = subprocess.run(
                    ["bash", MIGRATION_RUNNER, target, "--apply"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("requires --env-file", result.stderr)

                relative = subprocess.run(
                    [
                        "bash",
                        MIGRATION_RUNNER,
                        target,
                        "--apply",
                        "--env-file",
                        "relative.env",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(relative.returncode, 2)
                self.assertIn("must be absolute", relative.stderr)

    def test_target_check_accepts_but_does_not_read_a_private_environment(self):
        missing_env = "/private/path/that-is-not-opened-in-check-mode.env"
        result = subprocess.run(
            [
                "bash",
                MIGRATION_RUNNER,
                "default-group",
                "check",
                "--env-file",
                missing_env,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no database connection was opened", result.stdout)
        self.assertIn("SUB2API_TARGET_DATABASE_URL", result.stdout)
        self.assertIn("private environment file was not read", result.stdout)

    def test_privacy_check_declares_the_private_source_database_interface(self):
        missing_env = "/private/path/that/is-not-opened-in-check-mode.env"
        result = subprocess.run(
            [
                "bash",
                MIGRATION_RUNNER,
                "privacy",
                "check",
                "--env-file",
                missing_env,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no database connection was opened", result.stdout)
        self.assertIn("SUB2API_SOURCE_DATABASE_URL", result.stdout)
        self.assertIn("private environment file was not read", result.stdout)

    def test_rollout_scrubs_source_before_safe_metadata_export(self):
        source = DEPLOYMENT
        rollout = source[source.index("## Confirmed rollout order"):]
        self.assertLess(
            rollout.index("run-database-migration.sh privacy --apply"),
            rollout.index("Only after the residue gate passes"),
        )
        self.assertIn("/etc/nginx/conf.d/sub2api.conf", source)

    def test_sync_role_preparation_is_explicit_and_keeps_password_off_argv(self):
        self.assertTrue(PREPARE_SYNC_ROLE.exists())
        self.assertTrue(PREPARE_SYNC_ROLE_SQL.exists())
        script = PREPARE_SYNC_ROLE.read_text()
        sql = PREPARE_SYNC_ROLE_SQL.read_text()
        self.assertIn('mode="${1:-check}"', script)
        self.assertIn("--env-file ABSOLUTE_PATH", script)
        self.assertIn('if [ "$mode" != "--apply" ]', script)
        self.assertIn("no database connection was opened", script)
        self.assertIn("private environment file was not read", script)
        self.assertLess(script.index('if [ "$mode" != "--apply" ]'), script.index("psql --quiet"))
        self.assertNotIn('-v sync_password', script)
        self.assertIn("base64 | tr -d", script)
        self.assertNotIn('--dbname="$SUB2API_DATABASE_URL"', script)
        self.assertNotIn('PGDATABASE="$SUB2API_DATABASE_URL"', script)
        self.assertNotIn('"$SUB2API_SYNC_DATABASE_PASSWORD"', script)
        self.assertIn('private_env_parser="$repo_dir/deploy/private_env.py"', script)
        self.assertIn('coproc PRIVATE_ENV_READER', script)
        self.assertIn('python3 "$private_env_parser" --emit-nul "$env_file"', script)
        self.assertIn('wait "$private_env_pid" || private_env_status=$?', script)
        self.assertIn(
            'python3 "$pg_env_exec" --target-private-env-file "$env_file"', script
        )
        self.assertIn("sub2api_sync_role_prepare_failed", script)
        self.assertIn(">/dev/null 2>/dev/null", script)
        self.assertIn("decode(:'sync_password_b64', 'base64')", sql)
        self.assertIn("CREATE ROLE sub2api_sync LOGIN", sql)
        self.assertIn("ALTER ROLE sub2api_sync WITH LOGIN", sql)
        for attribute in (
            "NOSUPERUSER", "NOCREATEDB", "NOCREATEROLE", "NOREPLICATION",
            "NOBYPASSRLS", "NOINHERIT",
        ):
            self.assertGreaterEqual(sql.count(attribute), 2)
        self.assertIn("ALTER ROLE sub2api_sync RESET ALL", sql)
        self.assertIn("pg_auth_members", sql)
        self.assertIn("REVOKE %I FROM sub2api_sync CASCADE", sql)
        self.assertIn("REVOKE sub2api_sync FROM %I CASCADE", sql)
        self.assertNotIn("PASSWORD '", sql)
        self.assertIn("BEGIN;", sql)
        self.assertIn("COMMIT;", sql)

    def test_app_runtime_role_is_non_owner_and_cannot_bypass_privacy_triggers(self):
        app = COMPOSE.split("  sub2api:\n", 1)[1].split(
            "\n  sub2api-sync:\n", 1
        )[0]
        self.assertIn("DATABASE_USER=sub2api_app", app)
        self.assertIn("SUB2API_APP_DATABASE_PASSWORD", app)
        self.assertNotIn("DATABASE_USER=${POSTGRES_USER", app)
        self.assertIn("AUTO_SETUP=false", app)
        self.assertNotIn("ADMIN_PASSWORD", app)
        sql = APP_ROLE_SQL.read_text()
        for attribute in (
            "NOSUPERUSER",
            "NOCREATEDB",
            "NOCREATEROLE",
            "NOREPLICATION",
            "NOBYPASSRLS",
            "NOINHERIT",
        ):
            self.assertIn(attribute, sql)
        self.assertIn("GRANT USAGE, CREATE ON SCHEMA public", sql)
        self.assertIn("sub2api_gate_guard_app_ddl", sql)
        self.assertIn("IF session_user <> 'sub2api_app' THEN", sql)
        self.assertNotIn(
            "session_user <> 'sub2api_app' AND current_user <> 'sub2api_app'",
            sql,
        )
        self.assertIn("CREATE TABLE IF NOT EXISTS schema_migrations", sql)
        self.assertIn(
            "REVOKE ALL PRIVILEGES ON TABLE public.sub2api_sync_invite_owners",
            sql,
        )
        self.assertNotIn("GRANT TRIGGER", sql)
        self.assertNotIn("GRANT TRUNCATE", sql)
        self.assertNotIn("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES", sql)
        self.assertIn("pg_default_acl", sql)
        prepare_app = PREPARE_APP_ROLE.read_text()
        self.assertIn("app_password_b64", prepare_app)
        self.assertIn("--env-file ABSOLUTE_PATH", prepare_app)
        self.assertIn("private environment file was not read", prepare_app)
        self.assertIn('coproc PRIVATE_ENV_READER', prepare_app)
        self.assertIn(
            'python3 "$private_env_parser" --emit-nul "$env_file"', prepare_app
        )
        self.assertNotIn('"$SUB2API_APP_DATABASE_PASSWORD"', prepare_app)
        self.assertNotIn('PGDATABASE="$SUB2API_DATABASE_URL"', prepare_app)
        self.assertIn(
            'python3 "$pg_env_exec" --target-private-env-file "$env_file"',
            prepare_app,
        )
        self.assertIn("sub2api_app_role_prepare_failed", prepare_app)
        self.assertIn(">/dev/null 2>/dev/null", prepare_app)
        self.assertIn("trigger-bypass", PG18_APP_ROLE_TEST.read_text())

    def test_role_apply_requires_absolute_private_environment(self):
        for path in (PREPARE_SYNC_ROLE, PREPARE_APP_ROLE):
            with self.subTest(path=path.name):
                missing = subprocess.run(
                    ["bash", path, "--apply"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(missing.returncode, 0)
                self.assertIn("requires --env-file", missing.stderr)

                relative = subprocess.run(
                    ["bash", path, "--apply", "--env-file", "relative.env"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(relative.returncode, 2)
                self.assertIn("must be absolute", relative.stderr)

                offline = subprocess.run(
                    [
                        "bash",
                        path,
                        "check",
                        "--env-file",
                        "/private/not-read-in-check-mode.env",
                    ],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(offline.returncode, 0, offline.stderr)
                self.assertIn("private environment file was not read", offline.stdout)

    def test_role_helpers_bound_parser_and_database_subprocesses(self):
        for path in (PREPARE_SYNC_ROLE, PREPARE_APP_ROLE):
            script = path.read_text()
            with self.subTest(path=path.name):
                self.assertIn(
                    "for command_name in python3 timeout base64 tr sha256sum",
                    script,
                )
                self.assertIn(
                    "timeout --foreground -s TERM -k 1 5", script
                )
                self.assertIn(
                    "timeout --foreground -s TERM -k 1 30", script
                )
                self.assertIn(
                    "sub2api_private_environment_load_failed", script
                )
                self.assertIn(">/dev/null 2>/dev/null", script)

    def test_secret_generator_requires_explicit_apply(self):
        script = SECRET_GENERATOR.read_text()
        main = script.split("def main(argv=None):", 1)[1]
        self.assertIn('else "check"', script)
        self.assertIn('mode != "--apply"', main)
        self.assertLess(
            main.index('mode != "--apply"'),
            main.index("initialize_missing_secrets("),
        )
        self.assertIn("require_production_apply_context(", main)
        self.assertLess(
            main.index("require_production_apply_context("),
            main.index("initialize_missing_secrets("),
        )
        self.assertIn("no secret was generated", script)

    def test_security_preflight_is_local_read_only_and_fail_closed(self):
        self.assertTrue(SECURITY_PREFLIGHT.exists())
        script = SECURITY_PREFLIGHT.read_text()
        self.assertIn("no service or external API was contacted", script)
        self.assertNotIn("curl ", script)
        self.assertNotIn("wrangler ", script)
        self.assertNotIn("docker ", script)
        self.assertNotIn("source ", script)
        self.assertNotIn("eval ", script)
        self.assertIn("still uses an example hostname", script)
        self.assertIn("still contains an example hostname", script)
        for key in (
            "POSTGRES_PASSWORD",
            "REDIS_PASSWORD",
            "SUB2API_SYNC_DATABASE_PASSWORD",
            "SUB2API_SYNC_SECRET",
            "JWT_SECRET",
            "TOTP_ENCRYPTION_KEY",
            "SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS",
        ):
            self.assertIn(key, script)
        self.assertIn("must use distinct values", script)
        self.assertIn("SUB2API_SYNC_DATABASE_USER must be the fixed least-privilege role", script)
        self.assertIn("require_hostname_list SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS", script)
        self.assertIn('values[BIND_HOST]-127.0.0.1', script)
        self.assertIn('values[SERVER_MODE]-release', script)
        self.assertIn('private_env_parser="$repo_dir/deploy/private_env.py"', script)
        self.assertIn('python3 "$private_env_parser" --emit-nul "$env_file"', script)
        self.assertIn('if ! wait "$private_env_pid"', script)
        self.assertIn('require_private_file "$wrangler_config" "private Wrangler config"', script)
        self.assertIn('node "$repo_dir/deploy/validate-wrangler-config.mjs"', script)
        self.assertIn('"$wrangler_config" "$secret_manifest"', script)
        self.assertIn("key ordering is not security-relevant", script)
        self.assertIn("require_storage_free_space", script)
        self.assertIn("require_no_active_swap", script)
        self.assertIn("/proc/swaps", script)
        self.assertIn("df --output=avail --block-size=1", script)

    def test_security_preflight_rejects_group_or_world_readable_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            env_path = directory_path / "deployment.env"
            env_path.write_text("POSTGRES_PASSWORD=not-used\n")
            env_path.chmod(0o644)
            wrangler_path = directory_path / "wrangler.jsonc"
            wrangler_path.write_text("{}\n")
            wrangler_path.chmod(0o600)
            result = subprocess.run(
                ["bash", SECURITY_PREFLIGHT, "check", "--env-file", env_path, "--wrangler-config", wrangler_path],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("environment file must use mode 0600", result.stderr)

    def test_security_preflight_rejects_owner_executable_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            env_path = directory_path / "deployment.env"
            env_path.write_text("POSTGRES_PASSWORD=not-used\n")
            env_path.chmod(0o700)
            wrangler_path = directory_path / "wrangler.jsonc"
            wrangler_path.write_text("{}\n")
            wrangler_path.chmod(0o600)
            result = subprocess.run(
                ["bash", SECURITY_PREFLIGHT, "check", "--env-file", env_path, "--wrangler-config", wrangler_path],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("environment file must use mode 0600", result.stderr)

    def test_security_preflight_rejects_a_public_sub2api_bind(self):
        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            env_path = directory_path / "deployment.env"
            env_path.write_text("BIND_HOST=0.0.0.0\n")
            env_path.chmod(0o600)
            wrangler_path = directory_path / "wrangler.jsonc"
            wrangler_path.write_text("{}\n")
            wrangler_path.chmod(0o600)
            result = subprocess.run(
                ["bash", SECURITY_PREFLIGHT, "check", "--env-file", env_path, "--wrangler-config", wrangler_path],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("BIND_HOST must remain 127.0.0.1", result.stderr)

    def test_security_preflight_rejects_conflicting_fixed_runtime_values(self):
        cases = {
            "BIND_HOST=0.0.0.0\n": "BIND_HOST must remain 127.0.0.1",
            "SERVER_PORT=18080\n": "SERVER_PORT must remain 8080",
            "SERVER_MODE=debug\n": "SERVER_MODE must be release",
            "RUN_MODE=development\n": "RUN_MODE must be standard",
        }
        for source, expected_error in cases.items():
            with self.subTest(source=source), tempfile.TemporaryDirectory() as directory:
                directory_path = pathlib.Path(directory)
                env_path = directory_path / "deployment.env"
                env_path.write_text(source)
                env_path.chmod(0o600)
                wrangler_path = directory_path / "wrangler.jsonc"
                wrangler_path.write_text("{}\n")
                wrangler_path.chmod(0o600)
                result = subprocess.run(
                    [
                        "bash",
                        SECURITY_PREFLIGHT,
                        "check",
                        "--env-file",
                        env_path,
                        "--wrangler-config",
                        wrangler_path,
                    ],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected_error, result.stderr)

    def test_security_preflight_accepts_a_complete_local_configuration(self):
        if os.geteuid() != 0:
            self.skipTest("exact production storage ownership requires root")
        data_root = pathlib.Path("/mnt/data/sub2api-gate")
        data_children = tuple(
            data_root / name
            for name in ("app", "postgres", "redis", "safe-backup", "exports")
        )
        created_data_root = False
        if data_root.exists():
            self.skipTest("existing /mnt/data/sub2api-gate must not be modified by a test")
        if not data_root.parent.is_dir() or not os.access(data_root.parent, os.W_OK):
            self.skipTest("test cannot create the required local /mnt/data layout")
        data_root.mkdir(mode=0o700)
        data_root.chmod(0o700)
        os.chown(data_root, 0, 0)
        created_data_root = True
        ownership = {
            "app": (1000, 1000),
            "postgres": (70, 70),
            "redis": (999, 1000),
            "safe-backup": (0, 0),
            "exports": (0, 0),
        }
        for child in data_children:
            child.mkdir(mode=0o700)
            child.chmod(0o700)
            os.chown(child, *ownership[child.name])
        nonce_dir = data_root / "redis" / "nonce"
        nonce_dir.mkdir(mode=0o700)
        nonce_dir.chmod(0o700)
        os.chown(nonce_dir, 999, 1000)
        acl_path = data_root / "redis" / "users.acl"
        acl_path.write_text(
            "user default reset on #" + "a" * 64 + " ~billing:* +@all\n"
        )
        acl_path.chmod(0o400)
        os.chown(acl_path, 999, 1000)
        nonce_acl_path = data_root / "redis" / "nonce-users.acl"
        nonce_acl_path.write_text(
            "user default off\n"
            "user sub2api_sync reset on #" + "b" * 64
            + " ~sub2api-sync:nonce:* -@all +ping +set +ttl +select\n"
        )
        nonce_acl_path.chmod(0o400)
        os.chown(nonce_acl_path, 999, 1000)
        try:
            with tempfile.TemporaryDirectory() as directory:
                directory_path = pathlib.Path(directory)
                env_path = directory_path / "deployment.env"
                env_path.write_text("\n".join((
                    "SUB2API_DATA_ROOT=/mnt/data/sub2api-gate",
                    "POSTGRES_USER=sub2api",
                    "POSTGRES_PASSWORD=postgres-password-00000001",
                    "SUB2API_APP_DATABASE_PASSWORD=app-database-password-000000002",
                    "REDIS_PASSWORD=redis-password-000000000002",
                    "SUB2API_SYNC_REDIS_PASSWORD=sync-redis-password-000000003",
                    "SUB2API_SYNC_DATABASE_USER=sub2api_sync",
                    "SUB2API_SYNC_DATABASE_PASSWORD=sync-database-password-0003",
                    "SUB2API_SYNC_SECRET=sync-hmac-secret-0000000000000004",
                    "JWT_SECRET=jwt-secret-000000000000000000000006",
                    "TOTP_ENCRYPTION_KEY=totp-key-00000000000000000000000007",
                    "SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS=api.openai.com,resource.openai.azure.com",
                    "SUB2API_LOGIN_URL=https://api.example.test",
                    "SUB2API_PUBLIC_BASE_URL=https://api.example.test/v1",
                )) + "\n")
                wrangler_path = directory_path / "wrangler.jsonc"
                wrangler_path.write_text(
                    '{"name":"sub2api-allow-ip",'
                    '"main":"src/worker-entry.js","workers_dev":false,'
                    '"compatibility_date":"2026-07-19",'
                    '"compatibility_flags":["nodejs_compat"],'
                    '"observability":{"enabled":true,"head_sampling_rate":0.1,'
                    '"logs":{"invocation_logs":false}},'
                    '"triggers":{"crons":["17 3 * * *"]},'
                    '"routes":[{"pattern":"api.example.test/allow-ip*",'
                    '"zone_name":"example.test"}],'
                    '"durable_objects":{"bindings":[{"name":"AUTH_RATE_LIMITER",'
                    '"class_name":"AuthRateLimiter"},{"name":"AUTH_STATE",'
                    '"class_name":"AuthState"}]},'
                    '"migrations":[{"tag":"v1",'
                    '"new_sqlite_classes":["AuthRateLimiter"]},{"tag":"v2",'
                    '"new_sqlite_classes":["AuthState"]}],'
                    '"kv_namespaces":[{"binding":"INVITE_STORE","id":"'
                    + "c" * 32 + '"}],'
                    '"vars":{"ALLOWED_HOSTNAMES":"api.example.test",'
                    '"PROVIDER_ALLOWED_HOSTNAMES":"provider.example.test",'
                    '"ACCOUNT_ID":"' + "a" * 32 + '","IP_LIST_ID":"' + "b" * 32 + '",'
                    '"TURNSTILE_SITE_KEY":"site",'
                    '"SUB2API_DEFAULT_BASE_URL":"https://api.example.test/v1",'
                    '"SUB2API_SYNC_URL":"https://api.example.test/_sub2api-sync/provision"}}\n'
                )
                env_path.chmod(0o600)
                wrangler_path.chmod(0o600)
                nginx_binary = directory_path / "nginx"
                shutil.copy2(shutil.which("sleep"), nginx_binary)
                nginx_process = subprocess.Popen(
                    [
                        "bash",
                        "-c",
                        'ulimit -Sc 0; ulimit -Hc 0; exec "$1" 30',
                        "nginx-core-limit-test",
                        str(nginx_binary),
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                try:
                    for _ in range(100):
                        comm_path = pathlib.Path("/proc") / str(nginx_process.pid) / "comm"
                        if comm_path.is_file() and comm_path.read_text().strip() == "nginx":
                            break
                        time.sleep(0.01)
                    else:
                        self.fail("temporary nginx process did not start")
                    result = subprocess.run(
                        ["bash", SECURITY_PREFLIGHT, "check", "--env-file", env_path, "--wrangler-config", wrangler_path],
                        cwd=ROOT,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                finally:
                    nginx_process.terminate()
                    nginx_process.wait(timeout=5)
        finally:
            if created_data_root:
                nonce_acl_path.unlink()
                acl_path.unlink()
                nonce_dir.rmdir()
                for child in reversed(data_children):
                    child.rmdir()
                data_root.rmdir()
        self.assertIn("security preflight passed", result.stdout)

    def test_sync_role_is_not_granted_every_sequence(self):
        self.assertIn("BEGIN;", LEAST_PRIVILEGE)
        self.assertTrue(LEAST_PRIVILEGE.rstrip().endswith("COMMIT;"))
        self.assertNotIn("ON ALL SEQUENCES", LEAST_PRIVILEGE)
        self.assertIn("GRANT USAGE, SELECT ON SEQUENCE", LEAST_PRIVILEGE)
        self.assertIn("GRANT SELECT, INSERT, UPDATE ON TABLE", LEAST_PRIVILEGE)
        self.assertIn("GRANT SELECT, INSERT, DELETE ON TABLE", LEAST_PRIVILEGE)
        self.assertIn("GRANT CONNECT ON DATABASE %I TO sub2api_sync", LEAST_PRIVILEGE)
        self.assertIn("GRANT EXECUTE ON FUNCTION public.crypt(text, text)", LEAST_PRIVILEGE)
        self.assertIn("GRANT EXECUTE ON FUNCTION public.gen_salt(text)", LEAST_PRIVILEGE)
        self.assertNotIn("GRANT SELECT ON TABLE usage_logs", LEAST_PRIVILEGE)
        self.assertIn("GRANT SELECT (%s) ON TABLE public.usage_logs", LEAST_PRIVILEGE)
        for column in (
            "id", "request_id", "model", "requested_model", "input_tokens",
            "output_tokens", "cache_creation_tokens", "cache_read_tokens",
            "total_cost", "actual_cost", "duration_ms", "stream",
            "request_type", "inbound_endpoint", "created_at",
        ):
            self.assertIn(f"'{column}'", LEAST_PRIVILEGE)
        self.assertIn("REVOKE ALL PRIVILEGES", LEAST_PRIVILEGE)
        self.assertIn("pg_default_acl", LEAST_PRIVILEGE)
        self.assertIn("pg_auth_members", LEAST_PRIVILEGE)
        self.assertIn("pg_shdepend", LEAST_PRIVILEGE)
        self.assertIn("unexpected readable usage_logs column", LEAST_PRIVILEGE)
        self.assertIn("sub2api_sync retains role membership", LEAST_PRIVILEGE)
        self.assertIn("sub2api_sync retains dangerous role attributes", LEAST_PRIVILEGE)
        broad_grant = LEAST_PRIVILEGE.split("GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE", 1)[1].split("TO sub2api_sync;", 1)[0]
        self.assertNotIn("groups", broad_grant)
        self.assertNotIn("subscription_plans", broad_grant)

    def test_content_residue_check_is_read_only_and_covers_known_fields(self):
        self.assertTrue(RESIDUE_CHECK.exists())
        sql = RESIDUE_CHECK.read_text()
        policy = PRIVACY_GUARDS.read_text()
        self.assertNotIn("UPDATE ", sql.upper())
        self.assertNotIn("DELETE ", sql.upper())
        for field in (
            "request_body",
            "full_prompt",
            "prompt",
            "messages",
            "input_excerpt",
            "error_body",
            "upstream_errors",
            "scanner_evidence",
            "response_captured_at",
            "debug_response_captured_at",
        ):
            self.assertTrue(field in sql or f"'{field}'" in policy)
        self.assertIn("public.conversation_content_policy()", sql)
        self.assertIn("jsonb_each(target.replacements)", sql)
        self.assertIn("unreviewed content-capable schema field", sql)
        self.assertIn("sanitize_idempotency_response_body", sql)
        self.assertIn("sanitize_idempotency_request_fingerprint", sql)
        self.assertIn("public.is_reviewed_content_metadata_column", sql)
        self.assertIn("public.is_conversation_capable_type", sql)
        self.assertIn("pg_catalog.pg_attribute", sql)
        self.assertIn("outside public schema", sql)
        self.assertIn("'usage_logs', jsonb_build_object(", policy)
        self.assertIn("'prompt', NULL", policy)
        self.assertIn("'messages', NULL", policy)
        self.assertNotIn("'prompt_tokens', NULL", policy)
        self.assertIn("field.replacement = 'null'::jsonb", sql)

    def test_guard_and_residue_checks_use_the_shared_content_policy(self):
        guard = GUARD_CHECK.read_text()
        residue = RESIDUE_CHECK.read_text()
        for sql in (guard, residue):
            self.assertIn("public.conversation_content_policy()", sql)
            self.assertIn("unreviewed content-capable schema field", sql)
            self.assertIn("sanitize_idempotency_response_body", sql)
            self.assertIn("sanitize_idempotency_request_fingerprint", sql)
            self.assertIn("is_reviewed_content_metadata_column", sql)
            self.assertIn("('payment_audit_logs', 'detail')", sql)

    def test_postgres_18_privacy_gate_covers_replay_and_trigger_writes(self):
        self.assertTrue(PG18_PRIVACY_TEST.exists())
        script = PG18_PRIVACY_TEST.read_text()
        self.assertIn(
            "postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15",
            script,
        )
        self.assertIn("POSTGRES_TEST_IMAGE", script)
        self.assertIn("postgres --version", script)
        self.assertIn("verify_conversation_guards.sql", script)
        self.assertIn("002_scrub_conversation_history.sql", script)
        self.assertIn("guard transaction rollback failed", script)
        self.assertIn("guard disappeared after scrub failure", script)
        self.assertIn("write guard did not commit before historical scrub", script)
        self.assertIn("privacy gate accepted re-enabled risk control", script)
        self.assertIn("matched_keyword varchar", script)
        self.assertIn("usage metadata was altered", script)
        self.assertIn("future_payload", script)
        self.assertIn("future_context jsonb", script)
        self.assertIn("future_attachment bytea", script)
        self.assertIn("future_markup xml", script)
        self.assertIn("future_fragments text[]", script)
        self.assertIn("unreviewed content-capable schema field", script)
        self.assertIn("privacy_guard_rollback", script)
        self.assertIn("privacy_scrub_failure", script)
        self.assertIn("conversation residue", script)
        self.assertIn("prompt_hash", script)
        self.assertIn("ops_retry_attempts", script)
        self.assertIn("image_size_breakdown", script)
        self.assertIn("generate_series(1, 2505)", script)
        self.assertIn("messages jsonb", script)
        self.assertIn(
            "ALTER TABLE usage_logs ADD COLUMN future_payload text",
            script,
        )
        self.assertIn("usage content history was not scrubbed", script)
        self.assertIn("usage content trigger did not clear writes", script)
        self.assertIn("UPDATE usage_logs", script)
        self.assertIn("migration replay rewrote already-scrubbed rows", script)
        self.assertIn("prompt_tokens TYPE text", script)
        self.assertIn("privacy_concurrent_writer", script)
        self.assertIn("global operation lock renewal", script)
        self.assertIn("usage billing dedup metadata", script)
        self.assertIn("future_fingerprint", script)
        self.assertIn("future_hash", script)
        self.assertIn("future_ref", script)

    def test_postgres_18_usage_gate_runs_smallint_cursor_queries(self):
        self.assertTrue(PG18_USAGE_TEST.exists())
        script = PG18_USAGE_TEST.read_text()
        self.assertIn("request_type smallint", script)
        self.assertIn('"cursorCreatedAt"', script)
        self.assertIn("SHOW statement_timeout", script)
        self.assertIn("PRIVATE_SENTINEL", script)

    def test_usage_index_migration_repairs_invalid_concurrent_indexes(self):
        migration = USAGE_INDEXES.read_text()
        self.assertIn("idx_usage_logs_metadata_search_trgm", migration)
        self.assertIn("gin_trgm_ops", migration)
        self.assertIn("NOT index_state.indisvalid", migration)
        self.assertIn("NOT index_state.indisready", migration)
        self.assertIn("DROP INDEX CONCURRENTLY", migration)
        self.assertIn("\\gexec", migration)
        self.assertIn("pg_get_indexdef", migration)

    def test_postgres_18_group_gate_covers_success_replay_and_rollbacks(self):
        self.assertTrue(PG18_GROUP_TEST.exists())
        script = PG18_GROUP_TEST.read_text()
        self.assertEqual(script.count("001_default_to_openai_default.sql"), 6)
        self.assertIn("group_success", script)
        self.assertIn("group_dual", script)
        self.assertIn("group_relationship_conflict", script)
        self.assertIn("group_unknown", script)
        self.assertIn("group_duplicate_source_unknown", script)
        self.assertIn("duplicate-source unknown-reference rollback failed", script)
        self.assertIn("rollback failed", script)
        migration = (ROOT / "migrations" / "001_default_to_openai_default.sql").read_text()
        self.assertIn("UPDATE channel_groups SET group_id", migration)
        self.assertIn("UPDATE subscription_plans SET group_id", migration)
        self.assertNotIn("DELETE FROM channel_groups", migration)
        self.assertNotIn("DELETE FROM subscription_plans", migration)
        self.assertIn("source group relationships were lost", script)

    def test_postgres_18_sync_role_gate_covers_pollution_and_owner_rollback(self):
        self.assertTrue(PG18_SYNC_ROLE_TEST.exists())
        script = PG18_SYNC_ROLE_TEST.read_text()
        self.assertIn(
            "postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15",
            script,
        )
        self.assertIn("POSTGRES_TEST_IMAGE", script)
        self.assertIn("postgres --version", script)
        self.assertEqual(script.count("003_sync_least_privilege.sql"), 4)
        self.assertIn("SUPERUSER CREATEDB CREATEROLE REPLICATION BYPASSRLS INHERIT", script)
        self.assertIn("000_prepare_sync_role.sql", script)
        self.assertIn("prepare role pollution survived", script)
        self.assertIn("ALTER DEFAULT PRIVILEGES", script)
        self.assertIn("PRIVATE_SENTINEL", script)
        self.assertIn("future_request_body", script)
        self.assertIn("SELECT * FROM usage_logs", script)
        self.assertIn("metadata query failed", script)
        self.assertIn("role pollution survived", script)
        self.assertIn("owner rollback failed", script)
        self.assertIn("optional-column compatibility", script)
        self.assertIn("missing core usage column", script)

    def test_redis_nonce_gate_covers_concurrency_and_restart(self):
        self.assertTrue(REDIS_NONCE_TEST.exists())
        script = REDIS_NONCE_TEST.read_text()
        self.assertIn(
            "redis@sha256:9d317178eceac8454a2284a9e6df2466b93c745529947f0cd42a0fa9609d7005",
            script,
        )
        self.assertIn("v=8.8.0", script)
        self.assertIn("ThreadPoolExecutor(max_workers=20)", script)
        self.assertIn('docker kill "$container_name"', script)
        self.assertIn("--appendfsync always", script)
        self.assertIn("nonce replay succeeded after Redis SIGKILL", script)
        self.assertIn("results.count(True) != 1", script)
        self.assertIn("SIGNATURE_MAX_SKEW_SECONDS * 2", script)
        self.assertIn("TTL\", nonce_key", script)

    def test_nginx_gate_uses_read_only_mounts_and_real_syntax_check(self):
        self.assertTrue(NGINX_TEST.exists())
        script = NGINX_TEST.read_text()
        self.assertIn(
            "nginx@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10",
            script,
        )
        self.assertIn(
            "nginx@sha256:93baf2ec1bfefd04d29eb070900dd5d79b0f79863653453397e55a5b663a6cb1",
            script,
        )
        self.assertNotIn("nginx:1.27-alpine", script)
        self.assertIn(":/workspace:ro", script)
        self.assertIn("nginx -t -c /workspace/nginx/test-nginx.conf", script)

    def test_sub2api_startup_gate_checks_file_logs_and_export_schema(self):
        self.assertTrue(SUB2API_LOG_TEST.exists())
        script = SUB2API_LOG_TEST.read_text()
        self.assertIn(
            'sub2api_expected_version="${SUB2API_TEST_EXPECTED_VERSION:-0.1.171}"',
            script,
        )
        self.assertIn('"Sub2API $sub2api_expected_version"', script)
        self.assertIn("v=8.8.0", script)
        self.assertIn("--log-driver none", script)
        self.assertIn("LOG_OUTPUT_TO_FILE=false", script)
        self.assertIn("/app/data/logs/sub2api.log", script)
        self.assertIn("safe metadata export column missing", script)
        self.assertIn("002_remove_conversation_capture.sql", script)
        self.assertIn("verify_no_conversation_content.sql", script)
        self.assertIn("became unhealthy after the privacy migration", script)
        self.assertIn(
            "recreated a forbidden log, preview, capture, or config file", script
        )
        self.assertIn("runtime Sub2API tmpfs is not owned by 1000:1000", script)
        self.assertIn("003_sync_least_privilege.sql", script)
        self.assertIn("127.0.0.1:3021/healthz", script)
        self.assertIn("--user 65532:65532 --read-only", script)

    def test_nginx_install_targets_are_explicit(self):
        for mapping in (
            "nginx/00-connection-upgrade-map.conf` -> `/etc/nginx/conf.d/00-connection-upgrade-map.conf",
            "nginx/cloudflare-source-geo.conf` -> `/etc/nginx/conf.d/00-cloudflare-source-geo.conf",
            "nginx/sub2api-sync-limit.conf` -> `/etc/nginx/conf.d/00-sub2api-sync-limit.conf",
            "nginx/snippets/cloudflare-real-ip.conf` -> `/etc/nginx/snippets/cloudflare-real-ip.conf",
            "nginx/snippets/cloudflare-only.conf` -> `/etc/nginx/snippets/cloudflare-only.conf",
            "nginx/snippets/sub2api-upstream-stable.conf` -> `/etc/nginx/snippets/sub2api-upstream-active.conf",
            "nginx/sub2api-sync-location.conf` -> `/etc/nginx/snippets/sub2api-sync-location.conf",
        ):
            self.assertIn(mapping, DEPLOYMENT)
        self.assertIn("Do not replace the live TLS vhost wholesale", DEPLOYMENT)
        self.assertIn("upstream sub2api_backend", DEPLOYMENT)
        self.assertIn("sub2api-upstream-active.conf", DEPLOYMENT)
        self.assertIn("keepalive 64;", DEPLOYMENT)
        self.assertIn("proxy_pass http://sub2api_backend;", DEPLOYMENT)

    def test_cloudflare_ip_updater_requires_explicit_apply(self):
        script = CLOUDFLARE_IP_UPDATER.read_text()
        self.assertIn('mode="${1:-check}"', script)
        self.assertIn('if [ "$mode" != "--apply" ]', script)
        self.assertIn("no network request was made and no file was changed", script)
        self.assertLess(script.index('if [ "$mode" != "--apply" ]'), script.index("curl -fsSL"))
        self.assertIn("install -m 0644", script)

    def test_worker_deployment_defaults_to_dry_run(self):
        script = WORKER_DEPLOY.read_text()
        package = (ROOT / "worker-allow-ip" / "package.json").read_text()
        self.assertIn('mode="check"', script)
        self.assertIn('rotation_stage="compatibility"', script)
        self.assertIn('if [ "$mode" != "--apply" ]', script)
        self.assertIn("deploy --dry-run", script)
        self.assertLess(script.index('if [ "$mode" != "--apply" ]'), script.index('echo "explicit --apply accepted'))
        self.assertIn('"deploy": "bash ../deploy/deploy-worker.sh check"', package)
        self.assertIn('"deploy:apply": "bash ../deploy/deploy-worker.sh --apply"', package)




if __name__ == "__main__":
    unittest.main()
