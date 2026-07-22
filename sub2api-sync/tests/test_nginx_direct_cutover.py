import fcntl
import importlib.util
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
CUTOVER = ROOT / "deploy" / "install-nginx-direct-v1.py"


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
        (root / "sites-available").mkdir()
        (root / "sites-enabled").mkdir()
        for managed_directory in (
            root,
            root / "conf.d",
            root / "sites-available",
            root / "sites-enabled",
        ):
            managed_directory.chmod(0o755)
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

    def test_rewrite_requires_the_switchable_named_upstream(self):
        missing = OLD_CONFIG.replace(
            "upstream sub2api_backend {\n"
            "    include /etc/nginx/snippets/sub2api-upstream-active.conf;\n"
            "    keepalive 64;\n"
            "}\n\n",
            "",
            1,
        )
        with self.assertRaisesRegex(self.module.CutoverError, "one reviewed Sub2API upstream"):
            self.module.rewrite_direct_v1(missing, "gateway.example.test")
        unmanaged = OLD_CONFIG.replace(
            "include /etc/nginx/snippets/sub2api-upstream-active.conf;",
            "server 127.0.0.1:8080;",
            1,
        )
        with self.assertRaisesRegex(self.module.CutoverError, "reviewed active include"):
            self.module.rewrite_direct_v1(unmanaged, "gateway.example.test")

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

    def test_live_gate_scans_active_config_without_a_conf_suffix(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory) / "nginx"
            snippets = root / "snippets"
            sites = root / "sites-enabled"
            snippets.mkdir(parents=True)
            sites.mkdir()
            for path in (root, snippets, sites):
                path.chmod(0o755)
            site = sites / "gateway"
            site.write_text(
                self.module.rewrite_direct_v1(OLD_CONFIG, "gateway.example.test"),
                encoding="utf-8",
            )
            site.chmod(0o640)
            capture = snippets / "legacy-capture"
            capture.write_text("mirror /_response-capture;\n", encoding="utf-8")
            capture.chmod(0o640)

            with self.assertRaisesRegex(self.module.CutoverError, "mirror or capture"):
                self.module.verify_live_direct_v1(
                    root,
                    site,
                    "gateway.example.test",
                    production=False,
                )

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
            self.assertTrue((pathlib.Path(directory) / "nginx/conf.d/00-connection-upgrade-map.conf").is_file())
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
                self.assertEqual(nginx_calls.read_text().strip(), "2")
                self.assertGreaterEqual(int(reload_calls.read_text().strip()), 1)
                self.assertIn("restored and reloaded", result.stderr)


if __name__ == "__main__":
    unittest.main()
