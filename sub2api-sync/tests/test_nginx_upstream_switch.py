import fcntl
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SWITCH = ROOT / "deploy" / "switch-nginx-upstream.sh"
NGINX = ROOT / "nginx" / "sub2api.conf"
STABLE = ROOT / "nginx" / "snippets" / "sub2api-upstream-stable.conf"
CANARY = ROOT / "nginx" / "snippets" / "sub2api-upstream-canary.conf"


class NginxUpstreamSwitchTests(unittest.TestCase):
    def make_command(self, path, body):
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def fixture(
        self,
        root,
        *,
        fail_nginx=False,
        fail_reload=False,
        fail_canary=False,
        fail_traffic_verifier=False,
    ):
        nginx_root = root / "nginx"
        snippets = nginx_root / "snippets"
        snippets.mkdir(parents=True)
        nginx_root.chmod(0o755)
        snippets.chmod(0o755)
        active = snippets / "sub2api-upstream-active.conf"
        active.write_bytes(STABLE.read_bytes())
        active.chmod(0o644)

        bin_dir = root / "bin"
        bin_dir.mkdir()
        nginx_calls = root / "nginx-calls"
        reload_calls = root / "reload-calls"
        curl_calls = root / "curl-calls"
        canary_calls = root / "canary-calls"
        traffic_verifier_calls = root / "traffic-verifier-calls"
        lock_path = nginx_root / "sub2api-gate" / "nginx-operation.lock"
        require_lock = (
            f'lock_path="{lock_path}"\n'
            'if /usr/bin/flock -n "$lock_path" -c true; then\n'
            '  echo "shared Nginx lock was not held" >&2\n'
            '  exit 90\n'
            'fi\n'
        )

        self.make_command(
            bin_dir / "nginx",
            require_lock
            + f'calls="{nginx_calls}"\n'
            'count=0\n[ ! -f "$calls" ] || count=$(cat "$calls")\n'
            'count=$((count + 1))\nprintf "%s\\n" "$count" > "$calls"\n'
            + ('[ "$count" -ne 1 ]\n' if fail_nginx else 'exit 0\n'),
        )
        self.make_command(
            bin_dir / "systemctl",
            require_lock
            + f'calls="{reload_calls}"\n'
            'count=0\n[ ! -f "$calls" ] || count=$(cat "$calls")\n'
            'count=$((count + 1))\nprintf "%s\\n" "$count" > "$calls"\n'
            + ('[ "$count" -ne 1 ]\n' if fail_reload else 'exit 0\n'),
        )
        self.make_command(
            bin_dir / "curl",
            f'printf "%s\\n" "$*" >> "{curl_calls}"\nexit 0\n',
        )
        self.make_command(
            bin_dir / "canary-runner",
            require_lock
            + f'printf "%s\\n" "$*" >> "{canary_calls}"\n'
            + ('exit 1\n' if fail_canary else 'exit 0\n'),
        )
        self.make_command(
            bin_dir / "traffic-canary-verifier",
            require_lock
            + f'printf "%s\\n" "$*" >> "{traffic_verifier_calls}"\n'
            + ('exit 1\n' if fail_traffic_verifier else 'exit 0\n'),
        )
        release_guard = bin_dir / "release-guard"
        self.make_command(release_guard, "exit 0\n")
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "SUB2API_UPSTREAM_TEST_MODE": "1",
            "SUB2API_NGINX_ROOT": str(nginx_root),
            "SUB2API_RELEASE_GUARD": str(release_guard),
            "SUB2API_UPSTREAM_CANARY_RUNNER": str(bin_dir / "canary-runner"),
            "SUB2API_TRAFFIC_CANARY_VERIFIER": str(
                bin_dir / "traffic-canary-verifier"
            ),
        }
        return env, active, nginx_calls, reload_calls, curl_calls, canary_calls

    def run_switch(self, env, *args):
        return subprocess.run(
            ["bash", SWITCH, *args],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )

    @staticmethod
    def apply_args(stage="canary"):
        return (
            "--apply",
            "--stage",
            stage,
            "--verify-url",
            "https://gateway.example.test/v1/responses",
            "--model",
            "model-test",
            "--approved-hostname",
            "gateway.example.test",
            "--legacy-sub2api-container",
            "legacy-sub2api",
            "--legacy-postgres-container",
            "legacy-postgres",
            "--legacy-redis-container",
            "legacy-redis",
        )

    def test_check_is_offline_and_does_not_change_active_target(self):
        with tempfile.TemporaryDirectory() as directory:
            env, active, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(
                pathlib.Path(directory)
            )
            before = active.read_bytes()
            result = self.run_switch(env, "check", "--stage", "canary")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(active.read_bytes(), before)
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_success_switches_only_to_fixed_canary_and_runs_end_to_end_check(self):
        with tempfile.TemporaryDirectory() as directory:
            env, active, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(
                pathlib.Path(directory)
            )
            result = self.run_switch(env, *self.apply_args())
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(active.read_bytes(), CANARY.read_bytes())
            self.assertEqual(nginx_calls.read_text().strip(), "1")
            self.assertEqual(reload_calls.read_text().strip(), "1")
            self.assertIn("http://127.0.0.1:8081/health", curl_calls.read_text())
            invocation = canary_calls.read_text()
            self.assertIn("--apply", invocation)
            self.assertIn("https://gateway.example.test/v1/responses", invocation)
            verifier_invocation = (pathlib.Path(directory) / "traffic-verifier-calls").read_text()
            self.assertIn("verify", verifier_invocation)
            self.assertIn("--legacy-sub2api-container legacy-sub2api", verifier_invocation)
            self.assertIn("--legacy-postgres-container legacy-postgres", verifier_invocation)
            self.assertIn("--legacy-redis-container legacy-redis", verifier_invocation)

    def test_canary_identity_failure_does_not_touch_nginx_or_health_endpoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env, active, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(
                root, fail_traffic_verifier=True
            )

            result = self.run_switch(env, *self.apply_args())

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(active.read_bytes(), STABLE.read_bytes())
            self.assertTrue((root / "traffic-verifier-calls").exists())
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_canary_apply_requires_explicit_legacy_container_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            env, active, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(
                pathlib.Path(directory)
            )
            args = list(self.apply_args())
            del args[-6:]

            result = self.run_switch(env, *args)

            self.assertEqual(result.returncode, 2)
            self.assertIn("all three legacy container identities", result.stderr)
            self.assertEqual(active.read_bytes(), STABLE.read_bytes())
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_syntax_reload_and_canary_failures_each_restore_stable(self):
        for failure in ("nginx", "reload", "canary"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                env, active, nginx_calls, reload_calls, _, _ = self.fixture(
                    pathlib.Path(directory),
                    fail_nginx=failure == "nginx",
                    fail_reload=failure == "reload",
                    fail_canary=failure == "canary",
                )
                result = self.run_switch(env, *self.apply_args())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(active.read_bytes(), STABLE.read_bytes())
                self.assertEqual(nginx_calls.read_text().strip(), "2")
                self.assertGreaterEqual(int(reload_calls.read_text().strip()), 1)
                self.assertIn("restored and reloaded", result.stderr)

    def test_unreviewed_active_target_is_rejected_before_health_or_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            env, active, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(
                pathlib.Path(directory)
            )
            active.write_text("server attacker.example:9999;\n")
            result = self.run_switch(env, *self.apply_args())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unreviewed target", result.stderr)
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_untrusted_snippets_directory_is_rejected_before_health(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env, active, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(
                root
            )
            active.parent.chmod(0o775)

            result = self.run_switch(env, *self.apply_args())

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe ownership or permissions", result.stderr)
            self.assertFalse((root / "nginx/sub2api-gate").exists())
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_untrusted_active_file_is_rejected_before_health(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env, active, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(
                root
            )
            active.chmod(0o664)

            result = self.run_switch(env, *self.apply_args())

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe ownership or permissions", result.stderr)
            self.assertFalse((root / "nginx/sub2api-gate").exists())
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_untrusted_backup_directory_is_not_repaired_or_used(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env, _, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(root)
            state_root = root / "nginx/sub2api-gate"
            backup_root = state_root / "backups"
            backup_root.mkdir(parents=True)
            state_root.chmod(0o700)
            backup_root.chmod(0o770)

            result = self.run_switch(env, *self.apply_args())

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe ownership or permissions", result.stderr)
            self.assertEqual(stat.S_IMODE(backup_root.stat().st_mode), 0o770)
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_apply_fails_closed_while_shared_nginx_lock_is_held(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env, _, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(root)
            state_root = root / "nginx/sub2api-gate"
            state_root.mkdir(mode=0o700)
            state_root.chmod(0o700)
            lock_path = state_root / "nginx-operation.lock"
            with lock_path.open("a+") as held_lock:
                lock_path.chmod(0o600)
                held_lock.flush()
                fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = self.run_switch(env, *self.apply_args())

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already in progress", result.stderr)
            self.assertFalse((state_root / "backups").exists())
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_symlinked_state_is_rejected_before_health_or_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            env, _, nginx_calls, reload_calls, curl_calls, canary_calls = self.fixture(root)
            external_state = root / "external-state"
            external_state.mkdir(mode=0o700)
            external_state.chmod(0o700)
            (root / "nginx/sub2api-gate").symlink_to(external_state)

            result = self.run_switch(env, *self.apply_args())

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing or unsafe", result.stderr)
            self.assertFalse((external_state / "backups").exists())
            for calls in (nginx_calls, reload_calls, curl_calls, canary_calls):
                self.assertFalse(calls.exists())

    def test_template_and_switcher_have_no_sync_or_arbitrary_upstream_path(self):
        upstream = NGINX.read_text().split("upstream sub2api_backend {", 1)[1].split("}", 1)[0]
        source = SWITCH.read_text()
        self.assertIn("sub2api-upstream-active.conf", upstream)
        self.assertNotIn("3021", upstream)
        self.assertEqual(STABLE.read_text().strip(), "server 127.0.0.1:8080;")
        self.assertEqual(CANARY.read_text().strip(), "server 127.0.0.1:8081;")
        self.assertIn('case "$stage" in', source)
        self.assertIn('"$repo_dir/deploy/require-clean-worktree.sh" check', source)
        self.assertNotIn("eval ", source)


if __name__ == "__main__":
    unittest.main()
