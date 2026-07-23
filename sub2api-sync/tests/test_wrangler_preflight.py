import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
PREFLIGHT = ROOT / "deploy" / "security-preflight.sh"
WORKER_DEPLOY = ROOT / "deploy" / "deploy-worker.sh"
SECRET_LIST_VERIFIER = ROOT / "deploy" / "verify-worker-secret-list.mjs"
FINAL_TOTP_SOURCE_VERIFIER = ROOT / "deploy" / "verify-final-worker-totp-source.mjs"
WRANGLER_VALIDATOR = ROOT / "deploy" / "validate-wrangler-config.mjs"
SECRET_MANIFEST = ROOT / "worker-allow-ip" / "required-secrets.json"


class WranglerPreflightTests(unittest.TestCase):
    def test_worker_deploy_wrapper_cannot_bypass_local_security_validation(self):
        script = WORKER_DEPLOY.read_text()
        validator_call = (
            'node "$repo_dir/deploy/validate-wrangler-config.mjs" '
            '"$wrangler_config" "$secret_manifest"'
        )
        preflight_call = '"$repo_dir/deploy/security-preflight.sh" check --wrangler-config "$wrangler_config"'
        self.assertIn(validator_call, script)
        self.assertIn(preflight_call, script)
        self.assertLess(script.index(validator_call), script.index("deploy --dry-run"))
        self.assertLess(script.index(preflight_call), script.index("explicit --apply accepted"))
        secret_list_call = '"$wrangler_bin" secret list --format json --config "$wrangler_config"'
        secret_verifier_call = 'node "$repo_dir/deploy/verify-worker-secret-list.mjs"'
        self.assertIn("Remote Worker Secrets were not verified in check mode", script)
        self.assertIn(secret_list_call, script)
        self.assertIn(secret_verifier_call, script)
        self.assertLess(script.index(secret_list_call), script.index("explicit --apply accepted"))
        self.assertLess(script.index(secret_verifier_call), script.index("explicit --apply accepted"))
        self.assertIn("--forbid-totp-rotation-staging", script)
        self.assertIn("--require-totp-rotation-staging", script)
        self.assertIn("verify-final-worker-totp-source.mjs", script)
        self.assertIn("set -euo pipefail", script)
        mode_branch = script.index('if [ "$mode" != "--apply" ]')
        final_source_gate = script.index("verify-final-worker-totp-source.mjs")
        node_gate = script.index("process.versions.node")
        wrangler_gate = script.index('wrangler_version="$(')
        self.assertLess(node_gate, mode_branch)
        self.assertLess(wrangler_gate, mode_branch)
        self.assertLess(node_gate, script.index(validator_call))
        self.assertLess(wrangler_gate, script.index(validator_call))
        self.assertLess(final_source_gate, mode_branch)

    def test_remote_secret_name_verifier_accepts_only_a_complete_name_set(self):
        required = (
            "TURNSTILE_SECRET_KEY", "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2", "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY", "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        )
        complete = subprocess.run(
            ["node", SECRET_LIST_VERIFIER],
            cwd=ROOT,
            input=json.dumps([
                {"name": name, "type": "secret_text"} for name in required
            ] + [{"name": "UNRELATED_SECRET", "type": "secret_text"}]),
            check=False,
            capture_output=True,
            text=True,
        )
        incomplete = subprocess.run(
            ["node", SECRET_LIST_VERIFIER],
            cwd=ROOT,
            input=json.dumps([
                {"name": name, "type": "secret_text"} for name in required[:-1]
            ]),
            check=False,
            capture_output=True,
            text=True,
        )
        malformed = subprocess.run(
            ["node", SECRET_LIST_VERIFIER],
            cwd=ROOT,
            input='{"result":[]}',
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(complete.returncode, 0)
        self.assertIn("secret names verified", complete.stdout)
        for name in required:
            self.assertNotIn(name, complete.stdout)
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertIn("required Cloudflare Worker Secrets are missing", incomplete.stderr)
        self.assertNotIn(required[-1], incomplete.stderr)
        self.assertNotEqual(malformed.returncode, 0)
        self.assertIn("invalid shape", malformed.stderr)

    def test_remote_secret_name_verifier_enforces_rotation_stage_names(self):
        required = (
            "TURNSTILE_SECRET_KEY", "CLOUDFLARE_API_TOKEN",
            "ADMIN_PASSWORD_PBKDF2", "ADMIN_TOTP_SECRET",
            "CREDENTIAL_ENCRYPTION_KEY", "INVITE_ACCESS_HMAC_KEY",
            "SUB2API_SYNC_SECRET",
        )
        staging = (
            "ADMIN_TOTP_SECRET_NEXT",
            "ADMIN_TOTP_ROTATION_PHASE",
        )

        def verify(names, *arguments):
            return subprocess.run(
                ["node", SECRET_LIST_VERIFIER, SECRET_MANIFEST, *arguments],
                cwd=ROOT,
                input=json.dumps([
                    {"name": name, "type": "secret_text"} for name in names
                ]),
                check=False,
                capture_output=True,
                text=True,
            )

        staged = verify(required + staging, "--require-totp-rotation-staging")
        missing = verify(required, "--require-totp-rotation-staging")
        forbidden = verify(required + staging)
        partial = verify(required + staging[:1])
        unsupported = verify(required, "--require-admin-totp-next")

        self.assertEqual(staged.returncode, 0)
        self.assertIn("secret names verified", staged.stdout)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn("required Cloudflare Worker Secrets are missing", missing.stderr)
        self.assertNotEqual(forbidden.returncode, 0)
        self.assertIn("rotation staging Secrets must be absent", forbidden.stderr)
        self.assertNotEqual(partial.returncode, 0)
        self.assertIn("rotation staging Secrets must be absent", partial.stderr)
        self.assertNotEqual(unsupported.returncode, 0)
        self.assertIn("unsupported Worker Secret rotation requirement", unsupported.stderr)

    def test_final_worker_source_gate_rejects_rotation_secret_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            source_dir = pathlib.Path(directory) / "src"
            source_dir.mkdir()
            source = source_dir / "worker-entry.js"
            source.write_text("export default { fetch() { return new Response('ok'); } };\n")
            clean = subprocess.run(
                ["node", FINAL_TOTP_SOURCE_VERIFIER, source_dir],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            source.write_text("const phase = env.ADMIN_TOTP_ROTATION_PHASE;\n")
            phase = subprocess.run(
                ["node", FINAL_TOTP_SOURCE_VERIFIER, source_dir],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            source.write_text("const next = env.ADMIN_TOTP_SECRET_NEXT;\n")
            next_secret = subprocess.run(
                ["node", FINAL_TOTP_SOURCE_VERIFIER, source_dir],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            source.write_text("export default { fetch() { return new Response('ok'); } };\n")
            nested = source_dir / "nested"
            nested.mkdir()
            nested_secret_source = nested / "rotation.ts"
            nested_secret_source.write_text("const next = env.ADMIN_TOTP_SECRET_NEXT;\n")
            nested_secret = subprocess.run(
                ["node", FINAL_TOTP_SOURCE_VERIFIER, source_dir],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            nested_secret_source.write_text("export const safe = true;\n")
            source.write_text('const property = env["unrelated"];\n')
            dynamic_env = subprocess.run(
                ["node", FINAL_TOTP_SOURCE_VERIFIER, source_dir],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            source.write_text("export default { fetch() { return new Response('ok'); } };\n")
            (nested / "import.ts").write_text(
                'import { escaped } from "../escape.js";\nexport { escaped };\n'
            )
            escaping_import = subprocess.run(
                ["node", FINAL_TOTP_SOURCE_VERIFIER, source_dir],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(clean.returncode, 0)
        self.assertNotEqual(phase.returncode, 0)
        self.assertIn("still reads TOTP rotation Secrets", phase.stderr)
        self.assertNotEqual(next_secret.returncode, 0)
        self.assertIn("still reads TOTP rotation Secrets", next_secret.stderr)

        self.assertNotEqual(nested_secret.returncode, 0)
        self.assertIn("still reads TOTP rotation Secrets", nested_secret.stderr)
        self.assertNotEqual(dynamic_env.returncode, 0)
        self.assertIn("dynamic environment access", dynamic_env.stderr)
        self.assertNotEqual(escaping_import.returncode, 0)
        self.assertIn("unsupported module import", escaping_import.stderr)

    def test_validator_rejects_experimental_secret_declarations_and_secret_vars(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env_path = self.make_env(root)
            config = self.make_config(
                root,
                invocation_logs=False,
                include_rate_limiter=True,
            )
            payload = json.loads(config.read_text())
            payload["secrets"] = {"required": ["CLOUDFLARE_API_TOKEN"]}
            config.write_text(json.dumps(payload))
            unsupported = self.run_preflight(env_path, config)

            payload.pop("secrets")
            payload["vars"]["CLOUDFLARE_API_TOKEN"] = "must-not-be-in-config"
            config.write_text(json.dumps(payload))
            leaked = self.run_preflight(env_path, config)

        self.assertNotEqual(unsupported.returncode, 0)
        self.assertIn("unsupported secrets.required", unsupported.stderr)
        self.assertNotEqual(leaked.returncode, 0)
        self.assertIn("secret must not be stored in vars", leaked.stderr)

    def test_validator_rejects_rotation_secret_vars_and_unsafe_overrides(self):
        cases = (
            ("next-seed-var", "vars", "ADMIN_TOTP_SECRET_NEXT", "not-a-secret", "secret must not be stored in vars"),
            ("phase-var", "vars", "ADMIN_TOTP_ROTATION_PHASE", "stage", "secret must not be stored in vars"),
            ("keep-vars", None, "keep_vars", True, "leave keep_vars disabled"),
            ("unsafe", None, "unsafe", {}, "must not use unsafe bindings"),
            ("alias", None, "alias", {"x": "./x.js"}, "must not use module aliases"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            for name, section, key, value, expected_error in cases:
                with self.subTest(name=name):
                    config = self.make_config(
                        root,
                        invocation_logs=False,
                        include_rate_limiter=True,
                    )
                    payload = json.loads(config.read_text())
                    if section == "vars":
                        payload[section][key] = value
                    else:
                        payload[key] = value
                    config.write_text(json.dumps(payload))
                    result = self.run_validator(config)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected_error, result.stderr)

    def make_env(
        self,
        directory,
        *,
        upstream_hosts="api.openai.com,resource.openai.azure.com",
        login_url="https://api.example.test",
        public_base_url="https://api.example.test/v1",
    ):
        path = directory / "deployment.env"
        path.write_text("\n".join((
            "POSTGRES_USER=sub2api",
            "POSTGRES_PASSWORD=postgres-password-00000001",
            "SUB2API_APP_DATABASE_PASSWORD=app-database-password-000000002",
            "REDIS_PASSWORD=redis-password-000000000002",
            "SUB2API_SYNC_REDIS_PASSWORD=sync-redis-password-00000000003",
            "SUB2API_SYNC_DATABASE_USER=sub2api_sync",
            "SUB2API_SYNC_DATABASE_PASSWORD=sync-database-password-0003",
            "SUB2API_SYNC_SECRET=sync-hmac-secret-0000000000000004",
            "JWT_SECRET=jwt-secret-000000000000000000000006",
            "TOTP_ENCRYPTION_KEY=totp-key-00000000000000000000000007",
            f"SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS={upstream_hosts}",
            f"SUB2API_LOGIN_URL={login_url}",
            f"SUB2API_PUBLIC_BASE_URL={public_base_url}",
            "SUB2API_DATA_ROOT=/mnt/data/sub2api-gate",
        )) + "\n")
        path.chmod(0o600)
        return path

    def make_config(
        self,
        directory,
        *,
        invocation_logs,
        include_rate_limiter,
        include_auth_state=True,
        include_auth_state_migration=True,
        route_pattern="api.example.test/allow-ip*",
        route_zone_name="example.test",
        custom_domain=False,
        main="src/worker-entry.js",
        worker_name="sub2api-allow-ip",
        compatibility_date="2026-07-19",
        crons=("17 3 * * *",),
        allowed_hostnames="api.example.test",
        provider_hostnames="provider.example.test",
        default_base_url="https://api.example.test/v1",
        sync_url="https://api.example.test/_sub2api-sync/provision",
        account_id="a" * 32,
        list_id="b" * 32,
        kv_namespace_id="c" * 32,
    ):
        bindings = []
        migrations = []
        if include_rate_limiter:
            bindings.append({"name": "AUTH_RATE_LIMITER", "class_name": "AuthRateLimiter"})
            migrations.append({"tag": "v1", "new_sqlite_classes": ["AuthRateLimiter"]})
        if include_auth_state:
            bindings.append({"name": "AUTH_STATE", "class_name": "AuthState"})
        if include_auth_state_migration:
            migrations.append({"tag": "v2", "new_sqlite_classes": ["AuthState"]})
        path = directory / "wrangler.jsonc"
        route = {"pattern": route_pattern, "zone_name": route_zone_name}
        if custom_domain:
            route["custom_domain"] = True
        payload = {
            "name": worker_name,
            "main": main,
            "compatibility_date": compatibility_date,
            "compatibility_flags": ["nodejs_compat"],
            "workers_dev": False,
            "observability": {
                "enabled": True,
                "head_sampling_rate": 0.1,
                "logs": {"invocation_logs": invocation_logs},
            },
            "routes": [route],
            "triggers": {"crons": list(crons)},
            "kv_namespaces": [{"binding": "INVITE_STORE", "id": kv_namespace_id}],
            "vars": {
                "ALLOWED_HOSTNAMES": allowed_hostnames,
                "PROVIDER_ALLOWED_HOSTNAMES": provider_hostnames,
                "ACCOUNT_ID": account_id,
                "IP_LIST_ID": list_id,
                "TURNSTILE_SITE_KEY": "site",
                "SUB2API_DEFAULT_BASE_URL": default_base_url,
                "SUB2API_SYNC_URL": sync_url,
            },
        }
        if bindings:
            payload["durable_objects"] = {"bindings": bindings}
            payload["migrations"] = migrations
        path.write_text(json.dumps(payload) + "\n")
        path.chmod(0o600)
        return path

    def run_validator(self, config_path, expected_public_hostname="api.example.test"):
        return subprocess.run(
            ["node", WRANGLER_VALIDATOR, config_path, SECRET_MANIFEST,
             expected_public_hostname],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def run_worker_deploy_with_fake_runtime(
        self,
        *,
        node_major=22,
        wrangler_version="4.112.0",
        npm_audit_exit=0,
    ):
        temporary = tempfile.TemporaryDirectory()
        root = pathlib.Path(temporary.name)
        (root / "deploy").mkdir()
        (root / "worker-allow-ip" / "node_modules" / ".bin").mkdir(parents=True)
        (root / "fake-bin").mkdir()
        shutil.copy2(WORKER_DEPLOY, root / "deploy" / "deploy-worker.sh")
        (root / "worker-allow-ip" / "wrangler.private.jsonc").write_text("{}\n")
        (root / "worker-allow-ip" / "required-secrets.json").write_text("{}\n")

        fake_node = root / "fake-bin" / "node"
        fake_node.write_text(
            "#!/bin/sh\n"
            "if [ \"${1-}\" = \"-e\" ]; then\n"
            "  [ \"${FAKE_NODE_MAJOR-0}\" -ge 22 ]\n"
            "  exit $?\n"
            "fi\n"
            "exit 0\n"
        )
        fake_node.chmod(0o700)

        fake_npm = root / "fake-bin" / "npm"
        fake_npm.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$FAKE_NPM_LOG\"\n"
            "exit \"${FAKE_NPM_AUDIT_EXIT-1}\"\n"
        )
        fake_npm.chmod(0o700)

        fake_wrangler = root / "worker-allow-ip" / "node_modules" / ".bin" / "wrangler"
        fake_wrangler.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$*\" >> \"$FAKE_WRANGLER_LOG\"\n"
            "if [ \"${1-}\" = \"--version\" ]; then\n"
            "  printf '%s\\n' \"${FAKE_WRANGLER_VERSION-}\"\n"
            "  exit 0\n"
            "fi\n"
            "exit 0\n"
        )
        fake_wrangler.chmod(0o700)
        log_path = root / "wrangler.log"
        npm_log_path = root / "npm.log"
        environment = os.environ.copy()
        environment.update({
            "PATH": f"{root / 'fake-bin'}:{environment['PATH']}",
            "FAKE_NODE_MAJOR": str(node_major),
            "FAKE_WRANGLER_VERSION": wrangler_version,
            "FAKE_WRANGLER_LOG": str(log_path),
            "FAKE_NPM_AUDIT_EXIT": str(npm_audit_exit),
            "FAKE_NPM_LOG": str(npm_log_path),
        })
        result = subprocess.run(
            ["bash", root / "deploy" / "deploy-worker.sh", "check"],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        calls = log_path.read_text().splitlines() if log_path.exists() else []
        npm_calls = (
            npm_log_path.read_text().splitlines() if npm_log_path.exists() else []
        )
        temporary.cleanup()
        return result, calls, npm_calls

    def run_preflight(self, env_path, config_path):
        return subprocess.run(
            ["bash", PREFLIGHT, "check", "--env-file", env_path,
             "--wrangler-config", config_path],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_rejects_enabled_invocation_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(root),
                self.make_config(root, invocation_logs=True, include_rate_limiter=True),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invocation logs must be disabled", result.stderr)

    def test_validator_pins_worker_identity_compatibility_date_and_cron(self):
        cases = (
            ({"worker_name": "other-worker"}, "Worker name must remain sub2api-allow-ip"),
            (
                {"compatibility_date": "2026-07-18"},
                "compatibility_date must remain fixed at 2026-07-19",
            ),
            ({"crons": ()}, "cron schedule must be exactly 17 3 * * *"),
            (
                {"crons": ("17 3 * * *", "18 3 * * *")},
                "cron schedule must be exactly 17 3 * * *",
            ),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as directory:
                config = self.make_config(
                    pathlib.Path(directory),
                    invocation_logs=False,
                    include_rate_limiter=True,
                    **overrides,
                )
                result = self.run_validator(config)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

    def test_validator_requires_real_cloudflare_identifier_shapes(self):
        cases = (
            ({"account_id": "a" * 31}, "ACCOUNT_ID"),
            ({"account_id": "A" * 32}, "ACCOUNT_ID"),
            ({"list_id": "g" * 32}, "IP_LIST_ID"),
            ({"kv_namespace_id": "YOUR_KV_NAMESPACE_ID"}, "INVITE_STORE"),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as directory:
                config = self.make_config(
                    pathlib.Path(directory),
                    invocation_logs=False,
                    include_rate_limiter=True,
                    **overrides,
                )
                result = self.run_validator(config)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)
            self.assertIn("32-character lowercase hexadecimal", result.stderr)

    def test_validator_requires_zone_suffix_and_target_public_route(self):
        cases = (
            (
                {"route_zone_name": "other.test"},
                "routes must be limited to approved /allow-ip* hostnames",
            ),
            (
                {"route_zone_name": "test"},
                "routes must be limited to approved /allow-ip* hostnames",
            ),
            (
                {
                    "allowed_hostnames": "api.example.test,other.example.test",
                    "route_pattern": "other.example.test/allow-ip*",
                },
                "routes must include the configured public Sub2API hostname",
            ),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as directory:
                config = self.make_config(
                    pathlib.Path(directory),
                    invocation_logs=False,
                    include_rate_limiter=True,
                    **overrides,
                )
                result = self.run_validator(config)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

        with tempfile.TemporaryDirectory() as directory:
            config = self.make_config(
                pathlib.Path(directory),
                invocation_logs=False,
                include_rate_limiter=True,
                route_zone_name="api.example.test",
            )
            valid = self.run_validator(config)
        self.assertEqual(valid.returncode, 0, valid.stderr)

    def test_worker_deploy_rejects_old_node_before_running_wrangler(self):
        result, calls, npm_calls = self.run_worker_deploy_with_fake_runtime(
            node_major=21,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Node.js 22 or newer is required", result.stderr)
        self.assertEqual(calls, [])
        self.assertEqual(npm_calls, [])

    def test_worker_deploy_rejects_wrong_wrangler_before_dry_run(self):
        result, calls, npm_calls = self.run_worker_deploy_with_fake_runtime(
            wrangler_version="4.111.0",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("locked local Wrangler 4.112.0 is required", result.stderr)
        self.assertEqual(calls, ["--version"])
        self.assertEqual(npm_calls, [])

    def test_worker_deploy_rejects_failed_dependency_audit_before_dry_run(self):
        result, calls, npm_calls = self.run_worker_deploy_with_fake_runtime(
            npm_audit_exit=1,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, ["--version"])
        self.assertEqual(
            npm_calls,
            [
                "--prefix "
                + str(pathlib.Path(result.args[1]).parents[1] / "worker-allow-ip")
                + " audit --audit-level=high --package-lock-only --ignore-scripts"
            ],
        )

    def test_worker_deploy_accepts_pinned_local_runtime_for_offline_dry_run(self):
        result, calls, npm_calls = self.run_worker_deploy_with_fake_runtime()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls[0], "--version")
        self.assertEqual(
            calls[1],
            "deploy --dry-run --config " + str(
                pathlib.Path(result.args[1]).parents[1]
                / "worker-allow-ip"
                / "wrangler.private.jsonc"
            ),
        )
        self.assertEqual(
            npm_calls,
            [
                "--prefix "
                + str(pathlib.Path(result.args[1]).parents[1] / "worker-allow-ip")
                + " audit --audit-level=high --package-lock-only --ignore-scripts"
            ],
        )
        self.assertIn("no Worker will be published", result.stdout)

    def test_accepts_pretty_printed_valid_worker_config_before_storage_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env_path = self.make_env(root)
            config = self.make_config(
                root,
                invocation_logs=False,
                include_rate_limiter=True,
            )
            config.write_text(json.dumps(json.loads(config.read_text()), indent=2) + "\n")
            validator = subprocess.run(
                ["node", WRANGLER_VALIDATOR, config, SECRET_MANIFEST,
                 "api.example.test"],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            result = self.run_preflight(env_path, config)

        self.assertEqual(validator.returncode, 0, validator.stderr)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "required private storage path is missing or is a symlink",
            result.stderr,
        )
        self.assertNotIn("Wrangler", result.stderr)

    def test_rejects_missing_strong_rate_limiter_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(root),
                self.make_config(root, invocation_logs=False, include_rate_limiter=False),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AUTH_RATE_LIMITER", result.stderr)

    def test_rejects_missing_strong_auth_state_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(root),
                self.make_config(
                    root,
                    invocation_logs=False,
                    include_rate_limiter=True,
                    include_auth_state=False,
                ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AUTH_STATE", result.stderr)

    def test_rejects_missing_auth_state_sqlite_migration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(root),
                self.make_config(
                    root,
                    invocation_logs=False,
                    include_rate_limiter=True,
                    include_auth_state_migration=False,
                ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("AuthState SQLite migration v2", result.stderr)

    def test_rejects_route_that_can_intercept_v1_traffic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(root),
                self.make_config(
                    root,
                    invocation_logs=False,
                    include_rate_limiter=True,
                    route_pattern="api.example.test/v1*",
                ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("routes must be limited to approved /allow-ip* hostnames", result.stderr)

    def test_rejects_custom_domain_route(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(root),
                self.make_config(
                    root,
                    invocation_logs=False,
                    include_rate_limiter=True,
                    custom_domain=True,
                ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("routes must be limited to approved /allow-ip* hostnames", result.stderr)

    def test_rejects_entrypoint_that_does_not_export_rate_limiter(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(root),
                self.make_config(
                    root,
                    invocation_logs=False,
                    include_rate_limiter=True,
                    main="src/index.js",
                ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("main must export AuthRateLimiter", result.stderr)

    def test_rejects_ip_literals_and_local_names_in_environment_allowlist(self):
        for hostname in (
            "127.0.0.1",
            "169.254.169.254",
            "localhost",
            "service.local",
            "[::1]",
        ):
            with self.subTest(hostname=hostname), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                result = self.run_preflight(
                    self.make_env(root, upstream_hosts=hostname),
                    self.make_config(
                        root,
                        invocation_logs=False,
                        include_rate_limiter=True,
                    ),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("contains an invalid hostname", result.stderr)

    def test_rejects_ip_literals_and_local_names_in_worker_allowlist(self):
        for hostname in (
            "127.0.0.1",
            "169.254.169.254",
            "localhost",
            "service.local",
            "[::1]",
        ):
            with self.subTest(hostname=hostname), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                result = self.run_preflight(
                    self.make_env(root),
                    self.make_config(
                        root,
                        invocation_logs=False,
                        include_rate_limiter=True,
                        allowed_hostnames=hostname,
                        route_pattern=f"{hostname}/allow-ip*",
                        default_base_url=f"https://{hostname}/v1",
                        sync_url=f"https://{hostname}/_sub2api-sync/provision",
                    ),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("explicit fully qualified hostnames", result.stderr)

    def test_environment_login_and_base_urls_must_be_same_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(
                    root,
                    login_url="https://other.example.test",
                ),
                self.make_config(
                    root,
                    invocation_logs=False,
                    include_rate_limiter=True,
                ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "SUB2API_LOGIN_URL and SUB2API_PUBLIC_BASE_URL must use the same origin",
            result.stderr,
        )

    def test_public_gateway_must_not_be_a_provider_upstream(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_preflight(
                self.make_env(
                    root,
                    upstream_hosts="api.openai.com,api.example.test",
                ),
                self.make_config(
                    root,
                    invocation_logs=False,
                    include_rate_limiter=True,
                ),
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "public Sub2API hostname must not be present in "
            "SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS",
            result.stderr,
        )

    def test_worker_urls_must_use_allowed_hostname_and_exact_sync_path(self):
        cases = (
            (
                {"default_base_url": "https://other.example.test/v1"},
                "SUB2API_DEFAULT_BASE_URL hostname must be in ALLOWED_HOSTNAMES",
            ),
            (
                {"sync_url": "https://other.example.test/_sub2api-sync/provision"},
                "SUB2API_SYNC_URL must use an approved hostname",
            ),
            (
                {"sync_url": "https://api.example.test/_sub2api-sync/other"},
                "exact /_sub2api-sync/provision path",
            ),
        )
        for overrides, expected in cases:
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                result = self.run_preflight(
                    self.make_env(root),
                    self.make_config(
                        root,
                        invocation_logs=False,
                        include_rate_limiter=True,
                        **overrides,
                    ),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

    def test_worker_provider_allowlist_must_be_valid_and_disjoint_from_public_hosts(self):
        cases = (
            ("", "must contain at least one explicit fully qualified hostname"),
            ("   ", "must contain at least one explicit fully qualified hostname"),
            ("api.example.test", "must not overlap ALLOWED_HOSTNAMES"),
            ("127.0.0.1", "explicit fully qualified hostnames"),
            ("api.openai.com,", "explicit fully qualified hostnames"),
        )
        for provider_hostnames, expected in cases:
            with self.subTest(provider_hostnames=provider_hostnames), tempfile.TemporaryDirectory() as directory:
                root = pathlib.Path(directory)
                result = self.run_validator(
                    self.make_config(
                        root,
                        invocation_logs=False,
                        include_rate_limiter=True,
                        provider_hostnames=provider_hostnames,
                    ),
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(expected, result.stderr)

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            config = self.make_config(
                root,
                invocation_logs=False,
                include_rate_limiter=True,
            )
            payload = json.loads(config.read_text())
            payload["vars"].pop("PROVIDER_ALLOWED_HOSTNAMES")
            config.write_text(json.dumps(payload))
            missing = self.run_validator(config)
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn(
            "must contain at least one explicit fully qualified hostname",
            missing.stderr,
        )


if __name__ == "__main__":
    unittest.main()
