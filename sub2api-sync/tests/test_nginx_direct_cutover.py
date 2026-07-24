import fcntl
import importlib.util
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
CUTOVER = ROOT / "deploy" / "install-nginx-direct-v1.py"
PREFLIGHT = ROOT / "deploy" / "security-preflight.sh"


def load_cutover():
    spec = importlib.util.spec_from_file_location("nginx_direct_cutover", CUTOVER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


OLD_CONFIG = """upstream sub2api_backend {
    include /etc/nginx/snippets/sub2api-upstream-active.conf;
    keepalive 64;
}

server {
    listen 80;
    server_name gateway.example.test;
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    server_name other.example.test;
    location / { proxy_pass http://127.0.0.1:9090; }
}

server {
    listen 443 ssl;
    server_name gateway.example.test;

    location = /v1/responses {
        mirror /_response-capture;
        proxy_pass http://127.0.0.1:3021;
    }
    location ^~ /v1/ {
        mirror /_response-capture;
        proxy_pass http://127.0.0.1:3021;
    }
    location = /_response-capture {
        internal;
        proxy_pass http://127.0.0.1:3021/capture;
    }
    location / {
        proxy_pass http://127.0.0.1:8080;
    }
}
"""


class NginxDirectCutoverTests(unittest.TestCase):
    def setUp(self):
        self.module = load_cutover()

    def make_executable(self, path, body):
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def fixture(self, directory, *, fail_nginx=False, fail_reload=False, fail_canary=False):
        root = pathlib.Path(directory) / "nginx"
        (root / "conf.d").mkdir(parents=True)
        (root / "snippets").mkdir()
        (root / "sites-available").mkdir()
        (root / "sites-enabled").mkdir()
        for managed_directory in (
            root,
            root / "conf.d",
            root / "snippets",
            root / "sites-available",
            root / "sites-enabled",
        ):
            managed_directory.chmod(0o755)
        cloudflare_only = root / "snippets" / "cloudflare-only.conf"
        cloudflare_only.write_text("allow all;\n", encoding="utf-8")
        cloudflare_only.chmod(0o640)
        site_target = root / "sites-available" / "gateway.conf"
        site_target.write_text(OLD_CONFIG, encoding="utf-8")
        site_target.chmod(0o640)
        site = root / "sites-enabled" / "gateway.conf"
        site.symlink_to(site_target)

        bin_dir = pathlib.Path(directory) / "bin"
        bin_dir.mkdir()
        nginx_calls = pathlib.Path(directory) / "nginx-calls"
        reload_calls = pathlib.Path(directory) / "reload-calls"
        canary_calls = pathlib.Path(directory) / "canary-calls"
        lock_path = root / "sub2api-gate" / "nginx-operation.lock"
        require_lock = (
            f'lock_path="{lock_path}"\n'
            'if /usr/bin/flock -n "$lock_path" -c true; then\n'
            '  echo "shared Nginx lock was not held" >&2\n'
            '  exit 90\n'
            'fi\n'
        )

        self.make_executable(
            bin_dir / "nginx",
            require_lock
            + f'calls="{nginx_calls}"\ncount=0\n[ ! -f "$calls" ] || count=$(cat "$calls")\n'
            'count=$((count + 1))\nprintf "%s\\n" "$count" > "$calls"\n'
            + ('[ "$count" -ne 1 ]\n' if fail_nginx else 'exit 0\n'),
        )
        self.make_executable(
            bin_dir / "systemctl",
            require_lock
            + f'calls="{reload_calls}"\ncount=0\n[ ! -f "$calls" ] || count=$(cat "$calls")\n'
            'count=$((count + 1))\nprintf "%s\\n" "$count" > "$calls"\n'
            + ('[ "$count" -ne 1 ]\n' if fail_reload else 'exit 0\n'),
        )
        self.make_executable(
            bin_dir / "canary",
            require_lock
            + f'printf "%s\\n" "$*" >> "{canary_calls}"\n'
            + ('exit 1\n' if fail_canary else 'exit 0\n'),
        )
        self.make_executable(bin_dir / "release-guard", "exit 0\n")
        env = {
            **os.environ,
            "SUB2API_NGINX_CUTOVER_TEST_MODE": "1",
            "SUB2API_NGINX_ROOT": str(root),
            "SUB2API_NGINX_BIN": str(bin_dir / "nginx"),
            "SUB2API_SYSTEMCTL_BIN": str(bin_dir / "systemctl"),
            "SUB2API_NGINX_CANARY_RUNNER": str(bin_dir / "canary"),
            "SUB2API_RELEASE_GUARD": str(bin_dir / "release-guard"),
            "SUB2API_NGINX_SKIP_HEALTH_TEST": "1",
        }
        return env, site, site_target, nginx_calls, reload_calls, canary_calls

    @staticmethod
    def apply_args(site):
        return (
            "--apply",
            "--site-config", str(site),
            "--server-name", "gateway.example.test",
            "--verify-url", "https://gateway.example.test/v1/responses",
            "--model", "model-test",
        )

    def test_rewrite_removes_old_mirror_and_capture_and_preserves_other_server(self):
        rewritten = self.module.rewrite_direct_v1(OLD_CONFIG, "gateway.example.test")
        target = rewritten.split("server_name gateway.example.test;", 1)[1]
        self.assertNotIn("mirror", target)
        self.assertNotIn("/_response-capture", target)
        self.assertNotIn("127.0.0.1:3021", target)
        self.assertEqual(target.count("location ^~ /v1/"), 1)
        self.assertIn("proxy_pass http://sub2api_backend;", target)
        self.assertIn("proxy_set_header Connection $connection_upgrade;", target)
        self.assertIn("proxy_intercept_errors off;", target)
        self.assertEqual(
            target.count(
                "include /etc/nginx/snippets/cloudflare-only.conf;"
            ),
            2,
        )
        self.assertIn("server_name other.example.test;", rewritten)
        self.assertIn("127.0.0.1:9090", rewritten)
        self.assertIn("listen 80;", rewritten)
        self.assertIn("return 301 https://$host$request_uri;", rewritten)

    def test_rewrite_rejects_ambiguous_server_and_v1_regex(self):
        with self.assertRaisesRegex(self.module.CutoverError, "exactly one"):
            self.module.rewrite_direct_v1(OLD_CONFIG, "missing.example.test")
        regex = OLD_CONFIG.replace(
            "location ^~ /v1/ {",
            "location ~* ^/v1/.*$ {",
        )
        with self.assertRaisesRegex(self.module.CutoverError, "regex locations"):
            self.module.rewrite_direct_v1(regex, "gateway.example.test")

        lua_block = OLD_CONFIG.replace(
            "    location = /v1/responses {",
            "    log_by_lua_block { }\n    location = /v1/responses {",
        )
        with self.assertRaisesRegex(self.module.CutoverError, "server-wide request capture"):
            self.module.rewrite_direct_v1(lua_block, "gateway.example.test")

        lua_file = OLD_CONFIG.replace(
            "    location = /v1/responses {",
            "    access_by_lua_file /etc/nginx/request-hook.lua;\n    location = /v1/responses {",
        )
        with self.assertRaisesRegex(self.module.CutoverError, "server-wide request capture"):
            self.module.rewrite_direct_v1(lua_file, "gateway.example.test")

    def test_rewrite_creates_or_validates_the_switchable_named_upstream(self):
        missing = OLD_CONFIG.replace(
            "upstream sub2api_backend {\n"
            "    include /etc/nginx/snippets/sub2api-upstream-active.conf;\n"
            "    keepalive 64;\n"
            "}\n\n",
            "",
            1,
        )
        rewritten = self.module.rewrite_direct_v1(missing, "gateway.example.test")
        self.assertEqual(rewritten.count("upstream sub2api_backend {"), 1)
        self.assertIn(
            "include /etc/nginx/snippets/sub2api-upstream-active.conf;",
            rewritten,
        )
        unmanaged = OLD_CONFIG.replace(
            "include /etc/nginx/snippets/sub2api-upstream-active.conf;",
            "server 127.0.0.1:8080;",
            1,
        )
        with self.assertRaisesRegex(self.module.CutoverError, "reviewed active include"):
            self.module.rewrite_direct_v1(unmanaged, "gateway.example.test")

    def test_rewrite_repairs_and_verifier_requires_location_level_cloudflare_gate(self):
        rewritten = self.module.rewrite_direct_v1(
            OLD_CONFIG,
            "gateway.example.test",
        )
        target = rewritten.split("server_name gateway.example.test;", 1)[1]
        self.assertEqual(
            target.count(
                "include /etc/nginx/snippets/cloudflare-only.conf;"
            ),
            2,
        )

        tampered = rewritten.replace(
            "    location ^~ /v1/ {\n"
            "        include /etc/nginx/snippets/cloudflare-only.conf;\n",
            "    location ^~ /v1/ {\n",
            1,
        )
        with self.assertRaisesRegex(
            self.module.CutoverError,
            "every proxy location must explicitly include",
        ):
            self.module.verify_rewritten_config(
                tampered,
                "gateway.example.test",
            )

    def test_sync_location_requires_its_own_cloudflare_gate(self):
        sync = (ROOT / "nginx/sub2api-sync-location.conf").read_text()
        self.module.verify_sync_location_config(sync)
        inherited_only = sync.replace(
            "        include /etc/nginx/snippets/cloudflare-only.conf;\n",
            "",
            1,
        )
        with self.assertRaisesRegex(
            self.module.CutoverError,
            "sync proxy location must explicitly include",
        ):
            self.module.verify_sync_location_config(inherited_only)

    def test_check_mode_is_offline_and_needs_no_live_config(self):
        result = subprocess.run(
            [CUTOVER, "check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("check only", result.stdout)

    def test_command_validation_never_echoes_an_accidental_api_key(self):
        sentinel = "sk-accidental-command-line-secret"
        result = subprocess.run(
            [CUTOVER, f"--api-key={sentinel}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(sentinel, result.stdout)
        self.assertNotIn(sentinel, result.stderr)
        self.assertIn("command validation failed", result.stderr)

    def test_test_mode_rejects_root_before_running_environment_selected_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, _, nginx_calls, reload_calls, canary_calls = self.fixture(directory)
            arguments = self.module.parse_arguments(self.apply_args(site))
            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                self.module.os, "geteuid", return_value=0
            ):
                with self.assertRaisesRegex(
                    self.module.CutoverError, "test mode may not run as root"
                ):
                    self.module.install_cutover(arguments)

            self.assertFalse((pathlib.Path(directory) / "nginx/sub2api-gate").exists())
            for calls in (nginx_calls, reload_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_test_mode_rejects_a_canonical_alias_of_the_production_nginx_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            production_root = root / "production-nginx"
            production_root.mkdir()
            alias = root / "nginx-alias"
            alias.symlink_to(production_root, target_is_directory=True)
            env = {
                "SUB2API_NGINX_CUTOVER_TEST_MODE": "1",
                "SUB2API_NGINX_ROOT": str(alias),
            }

            with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(
                self.module, "DEFAULT_NGINX_ROOT", production_root
            ), mock.patch.object(self.module.os, "geteuid", return_value=1000):
                with self.assertRaisesRegex(
                    self.module.CutoverError,
                    "test mode may not target the production Nginx root",
                ):
                    self.module.install_cutover(self.module.argparse.Namespace())

    def test_production_apply_rejects_an_untrusted_controller_before_nginx_access(self):
        class PrivateTty:
            @staticmethod
            def isatty():
                return True

        arguments = self.module.parse_arguments(
            self.apply_args(pathlib.Path("/etc/nginx/conf.d/sub2api.conf"))
        )
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
            self.module.os, "geteuid", return_value=0
        ), mock.patch.object(self.module.sys, "stdin", PrivateTty()), mock.patch.object(
            self.module.sys, "stdout", PrivateTty()
        ), mock.patch.object(self.module.sys, "stderr", PrivateTty()), mock.patch.object(
            self.module,
            "validate_managed_directory",
            side_effect=AssertionError("Nginx validation ran before the release gate"),
        ) as nginx_directory, mock.patch.object(
            self.module,
            "ensure_managed_directory",
            side_effect=AssertionError("Nginx state creation ran before the release gate"),
        ) as nginx_state, mock.patch.object(
            self.module,
            "command_ok",
            side_effect=AssertionError("a child command ran before the release gate"),
        ) as command:
            with self.assertRaisesRegex(
                self.module.CutoverError,
                "trusted production release tree",
            ):
                self.module.install_cutover(arguments)

        nginx_directory.assert_not_called()
        nginx_state.assert_not_called()
        command.assert_not_called()

    def test_trusted_release_gate_checks_controller_and_transitive_sources(self):
        trusted_root = ROOT
        controller = trusted_root / self.module.CUTOVER_SOURCE_RELATIVE_PATH
        with mock.patch.object(self.module, "_require_trusted_release_path") as path_gate:
            self.module.require_trusted_release_tree(
                repo_dir=trusted_root,
                source_path=controller,
                trusted_root=trusted_root,
                expected_uid=os.geteuid(),
            )

        expected_entries = (
            (pathlib.Path("/"), True, False),
            (trusted_root.parent, True, False),
            (trusted_root, True, False),
            *(
                (trusted_root / relative_path, True, False)
                for relative_path in self.module.TRUSTED_RELEASE_DIRECTORIES
            ),
            *(
                (trusted_root / relative_path, False, expects_executable)
                for relative_path, expects_executable in self.module.TRUSTED_RELEASE_FILES
            ),
        )
        self.assertEqual(
            path_gate.call_args_list,
            [
                mock.call(
                    path,
                    expects_directory=expects_directory,
                    expects_executable=expects_executable,
                    expected_uid=os.geteuid(),
                )
                for path, expects_directory, expects_executable in expected_entries
            ],
        )

        with self.assertRaisesRegex(self.module.CutoverError, "controller is outside"):
            self.module.require_trusted_release_tree(
                repo_dir=trusted_root,
                source_path=trusted_root / self.module.CANARY_RUNNER_RELATIVE_PATH,
                trusted_root=trusted_root,
                expected_uid=os.geteuid(),
            )


    def test_live_gate_rejects_inline_http_mirror_without_capture_marker(self):

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "nginx"
            conf_dir = root / "conf.d"
            conf_dir.mkdir(parents=True)
            root.chmod(0o755)
            conf_dir.chmod(0o755)
            root.joinpath("nginx.conf").write_text(
                "events {}\n"
                "http {\n"
                "    include /etc/nginx/conf.d/*.conf;\n"
                "}\n",
                encoding="utf-8",
            )
            root.joinpath("nginx.conf").chmod(0o644)
            # Nginx permits multiple directives on one line. The mirror target
            # deliberately avoids capture-related text, so only parser-level
            # directive inspection can identify this request-body mirror.
            conf_dir.joinpath("00-inline-policy.conf").write_text(
                "map $host $ignored { default 0; } mirror /_sink;\n",
                encoding="utf-8",
            )
            conf_dir.joinpath("00-inline-policy.conf").chmod(0o644)

            with self.assertRaisesRegex(self.module.CutoverError, "mirror or capture"):
                self.module.verify_no_capture_config(root)

    def test_live_gate_rejects_a_writable_included_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "nginx"
            conf_dir = root / "conf.d"
            conf_dir.mkdir(parents=True)
            root.chmod(0o755)
            conf_dir.chmod(0o755)
            root.joinpath("nginx.conf").write_text(
                "events {}\n"
                "http {\n"
                "    include /etc/nginx/conf.d/*.conf;\n"
                "}\n",
                encoding="utf-8",
            )
            root.joinpath("nginx.conf").chmod(0o644)
            included = conf_dir / "10-site.conf"
            included.write_text("server { listen 8080; }\n", encoding="utf-8")
            included.chmod(0o664)

            with self.assertRaisesRegex(self.module.CutoverError, "unsafe permissions"):
                self.module.verify_no_capture_config(root)

    def test_production_child_commands_use_a_minimal_environment(self):
        completed = subprocess.CompletedProcess([], 0)
        with mock.patch.object(
            self.module.subprocess,
            "run",
            return_value=completed,
        ) as run:
            self.assertTrue(self.module.command_ok(["/usr/bin/true"], production=True))

        self.assertEqual(
            run.call_args.kwargs["env"],
            self.module.PRODUCTION_COMMAND_ENV,
        )
        self.assertNotIn("PYTHONPATH", run.call_args.kwargs["env"])
        self.assertNotIn("HTTP_PROXY", run.call_args.kwargs["env"])

    def test_security_preflight_resets_path_before_running_repo_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            malicious_bin = root / "bin"
            malicious_bin.mkdir()
            invoked = root / "malicious-dirname-ran"
            fake_dirname = malicious_bin / "dirname"
            fake_dirname.write_text(
                "#!/bin/sh\n"
                f": > {invoked}\n"
                "exit 99\n",
                encoding="ascii",
            )
            fake_dirname.chmod(0o755)
            result = subprocess.run(
                ["/bin/bash", PREFLIGHT, "--invalid-option"],
                cwd=ROOT,
                env={"PATH": str(malicious_bin)},
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("usage:", result.stderr)
            self.assertFalse(invoked.exists())

    def test_security_preflight_isolates_python_from_caller_module_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            module_dir = root / "modules"
            module_dir.mkdir()
            invoked = root / "malicious-python-module-ran"
            module_dir.joinpath("argparse.py").write_text(
                "from pathlib import Path\n"
                f"Path({str(invoked)!r}).touch()\n"
                "raise RuntimeError('unexpected module import')\n",
                encoding="ascii",
            )
            private_env = root / "private.env"
            private_env.write_text("VALUE=literal\n", encoding="ascii")
            private_env.chmod(0o600)
            private_config = root / "wrangler.private.jsonc"
            private_config.write_text("{}\n", encoding="ascii")
            private_config.chmod(0o600)

            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(module_dir)
            result = subprocess.run(
                [
                    "/bin/bash",
                    PREFLIGHT,
                    "--env-file",
                    private_env,
                    "--wrangler-config",
                    private_config,
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(invoked.exists())

    def test_live_gate_scans_active_config_without_a_conf_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "nginx"
            snippets = root / "snippets"
            sites = root / "sites-enabled"
            snippets.mkdir(parents=True)
            sites.mkdir()
            for path in (root, snippets, sites):
                path.chmod(0o755)
            capture = snippets / "legacy-capture"
            capture.write_text("mirror /_response-capture;\n", encoding="utf-8")
            capture.chmod(0o640)
            active_upstream = snippets / "sub2api-upstream-active.conf"
            active_upstream.write_text("server 127.0.0.1:8080;\n", encoding="utf-8")
            active_upstream.chmod(0o640)
            cloudflare_only = snippets / "cloudflare-only.conf"
            cloudflare_only.write_text("allow all;\n", encoding="utf-8")
            cloudflare_only.chmod(0o640)
            site = sites / "gateway"
            site.write_text(
                self.module.rewrite_direct_v1(OLD_CONFIG, "gateway.example.test")
                + f"include {capture};\n",
                encoding="utf-8",
            )
            site.chmod(0o640)

            with self.assertRaisesRegex(self.module.CutoverError, "mirror or capture"):
                self.module.verify_live_direct_v1(
                    root,
                    site,
                    "gateway.example.test",
                    production=False,
                )

    def test_apply_ignores_inactive_capture_backup_outside_include_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, target, _, _, _ = self.fixture(directory)
            inactive = pathlib.Path(directory) / "nginx/conf.d/sub2api.conf.bak-capture"
            inactive.write_text("mirror /_response-capture;\n", encoding="utf-8")
            inactive.chmod(0o640)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(inactive.read_text(), "mirror /_response-capture;\n")
            self.assertNotIn("mirror", target.read_text())

    def test_apply_rewrites_symlink_target_installs_map_and_runs_canary(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, target, nginx_calls, reload_calls, canary_calls = self.fixture(directory)
            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rendered = target.read_text()
            self.assertNotIn("mirror", rendered)
            self.assertNotIn("3021/capture", rendered)
            self.assertIn("proxy_pass http://sub2api_backend;", rendered)
            self.assertEqual(
                rendered.split("server_name gateway.example.test;", 1)[1].count(
                    "include /etc/nginx/snippets/cloudflare-only.conf;"
                ),
                2,
            )
            self.assertTrue((pathlib.Path(directory) / "nginx/conf.d/00-connection-upgrade-map.conf").is_file())
            self.assertEqual(
                (pathlib.Path(directory) / "nginx/snippets/sub2api-upstream-active.conf").read_text(),
                "server 127.0.0.1:8080;\n",
            )
            self.assertEqual(
                (pathlib.Path(directory) / "nginx/snippets/sub2api-sync-location.conf").read_text(),
                (ROOT / "nginx/sub2api-sync-location.conf").read_text(),
            )
            self.assertEqual(nginx_calls.read_text().strip(), "1")
            self.assertEqual(reload_calls.read_text().strip(), "1")
            self.assertIn("--approved-hostname gateway.example.test", canary_calls.read_text())

    def test_apply_rejects_site_symlink_that_resolves_outside_nginx_root(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, _, nginx_calls, reload_calls, _ = self.fixture(directory)
            external = pathlib.Path(directory) / "external-site.conf"
            external.write_text(OLD_CONFIG, encoding="utf-8")
            external.chmod(0o640)
            site.unlink()
            site.symlink_to(external)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("below the Nginx root", result.stderr)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_rejects_writable_existing_state_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, _, nginx_calls, reload_calls, _ = self.fixture(directory)
            state_root = pathlib.Path(directory) / "nginx/sub2api-gate"
            state_root.mkdir(mode=0o700)
            state_root.chmod(0o770)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("state directory has unsafe ownership or permissions", result.stderr)
            self.assertEqual(stat.S_IMODE(state_root.stat().st_mode), 0o770)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_rejects_writable_site_target_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, _, nginx_calls, reload_calls, _ = self.fixture(directory)
            site.parent.parent.joinpath("sites-available").chmod(0o775)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("site configuration directory has unsafe ownership or permissions", result.stderr)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_rejects_writable_existing_backup_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, _, nginx_calls, reload_calls, _ = self.fixture(directory)
            backup_root = pathlib.Path(directory) / "nginx/sub2api-gate/backups"
            backup_root.mkdir(parents=True, mode=0o700)
            backup_root.parent.chmod(0o700)
            backup_root.chmod(0o770)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("backup root has unsafe ownership or permissions", result.stderr)
            self.assertEqual(stat.S_IMODE(backup_root.stat().st_mode), 0o770)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_rejects_writable_nginx_root_parent_before_creating_state(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, target, nginx_calls, reload_calls, _ = self.fixture(directory)
            original = target.read_text()
            pathlib.Path(directory).chmod(0o770)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("root parent has unsafe ownership or permissions", result.stderr)
            self.assertEqual(target.read_text(), original)
            self.assertFalse((pathlib.Path(directory) / "nginx/sub2api-gate").exists())
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_rejects_writable_shared_lock_before_nginx_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, target, nginx_calls, reload_calls, _ = self.fixture(directory)
            original = target.read_text()
            state_root = pathlib.Path(directory) / "nginx/sub2api-gate"
            state_root.mkdir(mode=0o700)
            state_root.chmod(0o700)
            lock_path = state_root / "nginx-operation.lock"
            lock_path.write_text("", encoding="ascii")
            lock_path.chmod(0o660)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("operation lock has unsafe ownership or permissions", result.stderr)
            self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o660)
            self.assertEqual(target.read_text(), original)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_fails_closed_while_shared_nginx_lock_is_held(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, target, nginx_calls, reload_calls, canary_calls = self.fixture(directory)
            original = target.read_text()
            state_root = pathlib.Path(directory) / "nginx/sub2api-gate"
            state_root.mkdir(mode=0o700)
            state_root.chmod(0o700)
            lock_path = state_root / "nginx-operation.lock"
            with lock_path.open("a+") as held_lock:
                lock_path.chmod(0o600)
                held_lock.flush()
                fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = subprocess.run(
                    [CUTOVER, *self.apply_args(site)],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already in progress", result.stderr)
            self.assertEqual(target.read_text(), original)
            self.assertFalse((state_root / "backups").exists())
            for calls in (nginx_calls, reload_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_apply_rejects_symlinked_shared_lock_before_nginx_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, target, nginx_calls, reload_calls, canary_calls = self.fixture(directory)
            original = target.read_text()
            state_root = pathlib.Path(directory) / "nginx/sub2api-gate"
            state_root.mkdir(mode=0o700)
            state_root.chmod(0o700)
            external_lock = pathlib.Path(directory) / "external.lock"
            external_lock.write_text("", encoding="ascii")
            external_lock.chmod(0o600)
            (state_root / "nginx-operation.lock").symlink_to(external_lock)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("regular non-symlink", result.stderr)
            self.assertEqual(target.read_text(), original)
            for calls in (nginx_calls, reload_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_apply_restores_when_config_tree_contains_external_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            env, site, target, nginx_calls, reload_calls, _ = self.fixture(directory)
            original = target.read_text()
            external = pathlib.Path(directory) / "external-include.conf"
            external.write_text("map $host $safe_value { default 1; }\n", encoding="utf-8")
            (pathlib.Path(directory) / "nginx/conf.d/external.conf").symlink_to(external)

            result = subprocess.run(
                [CUTOVER, *self.apply_args(site)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("configuration tree contains an unsafe entry", result.stderr)
            self.assertEqual(target.read_text(), original)
            self.assertEqual(nginx_calls.read_text().strip(), "1")
            self.assertEqual(reload_calls.read_text().strip(), "1")
            self.assertIn("restored and reloaded", result.stderr)

    def test_syntax_reload_and_canary_failures_restore_every_changed_file(self):
        for failure in ("nginx", "reload", "canary"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                env, site, target, nginx_calls, reload_calls, _ = self.fixture(
                    directory,
                    fail_nginx=failure == "nginx",
                    fail_reload=failure == "reload",
                    fail_canary=failure == "canary",
                )
                original = target.read_text()
                result = subprocess.run(
                    [CUTOVER, *self.apply_args(site)],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(target.read_text(), original)
                self.assertFalse((pathlib.Path(directory) / "nginx/conf.d/00-connection-upgrade-map.conf").exists())
                self.assertFalse((pathlib.Path(directory) / "nginx/snippets/sub2api-upstream-active.conf").exists())
                self.assertFalse((pathlib.Path(directory) / "nginx/snippets/sub2api-sync-location.conf").exists())
                self.assertEqual(nginx_calls.read_text().strip(), "2")
                self.assertGreaterEqual(int(reload_calls.read_text().strip()), 1)
                self.assertIn("restored and reloaded", result.stderr)


if __name__ == "__main__":
    unittest.main()
