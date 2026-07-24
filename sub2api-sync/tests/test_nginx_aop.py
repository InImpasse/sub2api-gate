import fcntl
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).parents[2]
INSTALLER = ROOT / "deploy" / "install-nginx-aop.sh"
NGINX = ROOT / "nginx" / "sub2api.conf"
SOURCE_GEO = ROOT / "nginx" / "cloudflare-source-geo.conf"
REAL_IP = ROOT / "nginx" / "snippets" / "cloudflare-real-ip.conf"
CLOUDFLARE_ONLY = ROOT / "nginx" / "snippets" / "cloudflare-only.conf"
SYNC_LOCATION = ROOT / "nginx" / "sub2api-sync-location.conf"
SYNC_LIMIT = ROOT / "nginx" / "sub2api-sync-limit.conf"
STABLE_UPSTREAM = ROOT / "nginx" / "snippets" / "sub2api-upstream-stable.conf"
OPTIONAL = ROOT / "nginx" / "snippets" / "sub2api-aop-optional.conf"
REQUIRED = ROOT / "nginx" / "snippets" / "sub2api-aop-required.conf"
HOSTNAME = "api.example.com"
TEST_BOOT_ID = "11111111-2222-4333-8444-555555555555"


class NginxAopConfigTests(unittest.TestCase):
    def test_template_is_nginx_118_compatible_and_rejects_unknown_hosts(self):
        config = NGINX.read_text()
        self.assertNotIn("http2 on;", config)
        self.assertIn("listen 443 ssl http2 default_server;", config)
        self.assertIn("listen 443 ssl http2;", config)
        self.assertGreaterEqual(config.count("return 444;"), 2)
        self.assertGreaterEqual(
            config.count(
                "include /etc/nginx/snippets/sub2api-aop-active.conf;"
            ),
            2,
        )

    def test_aop_stages_use_only_the_project_specific_ca(self):
        optional = OPTIONAL.read_text()
        required = REQUIRED.read_text()
        expected_ca = "/etc/nginx/sub2api-gate/aop/client-ca.pem"
        self.assertIn(f"ssl_client_certificate {expected_ca};", optional)
        self.assertIn(f"ssl_client_certificate {expected_ca};", required)
        self.assertIn("ssl_verify_client optional;", optional)
        self.assertIn("ssl_verify_client on;", required)
        self.assertNotIn("cloudflare-origin-pull-ca.pem", optional + required)
        for config in (optional, required):
            self.assertIn("location = /.well-known/sub2api-aop-probe", config)
            self.assertIn("X-Sub2API-AOP-Verify $ssl_client_verify", config)
            self.assertIn('Cache-Control "no-store"', config)
            self.assertIn("return 204;", config)
        self.assertIn("$ssl_client_verify != SUCCESS", optional)

    def test_v1_remains_direct_and_has_no_capture_path(self):
        config = NGINX.read_text()
        upstream = config.split("upstream sub2api_backend {", 1)[1].split("}", 1)[0]
        v1 = config.split("location ^~ /v1/ {", 1)[1].split("}", 1)[0]
        general = config.rsplit("location / {", 1)[1].split("}", 1)[0]
        self.assertIn(
            "include /etc/nginx/snippets/sub2api-upstream-active.conf;", upstream
        )
        self.assertEqual(STABLE_UPSTREAM.read_text().strip(), "server 127.0.0.1:8080;")
        self.assertIn("proxy_pass http://sub2api_backend;", v1)
        self.assertIn("proxy_set_header Connection $connection_upgrade;", v1)
        self.assertNotIn("3021", v1)
        self.assertNotIn("mirror", v1.lower())
        self.assertNotIn("capture", v1.lower())
        for proxy_location in (v1, general, SYNC_LOCATION.read_text()):
            self.assertIn(
                "include /etc/nginx/snippets/cloudflare-only.conf;",
                proxy_location,
            )

    def test_cloudflare_peer_check_survives_real_ip_restoration(self):
        config = NGINX.read_text()
        source_geo = SOURCE_GEO.read_text()
        cloudflare_only = CLOUDFLARE_ONLY.read_text()
        self.assertEqual(
            config.count(
                "include /etc/nginx/snippets/cloudflare-real-ip.conf;"
            ),
            2,
        )
        self.assertIn(
            "geo $realip_remote_addr $cloudflare_source_allowed", source_geo
        )
        self.assertIn("default 0;", source_geo)
        self.assertIn("if ($cloudflare_source_allowed = 0)", cloudflare_only)
        self.assertNotIn("allow 103.", cloudflare_only)

    def test_sync_rate_limit_uses_restored_visitor_ip(self):
        config = NGINX.read_text()
        sync = SYNC_LOCATION.read_text()
        self.assertIn("limit_req_zone $binary_remote_addr", SYNC_LIMIT.read_text())
        self.assertIn("limit_req_status 429;", sync)
        self.assertIn("proxy_set_header X-Real-IP $remote_addr;", sync)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", sync)
        self.assertNotIn("$http_cf_connecting_ip", sync)
        self.assertLess(
            config.index("include /etc/nginx/snippets/cloudflare-real-ip.conf;"),
            config.index("include /etc/nginx/snippets/sub2api-sync-location.conf;"),
        )

    def test_api_vhost_disables_access_logs_and_bounds_slow_clients(self):
        config = NGINX.read_text()
        tls_vhost = config.split("server_name api.example.com;", 2)[2]
        for directive in (
            "access_log off;",
            "error_log /dev/null crit;",
            "client_header_timeout 15s;",
            "client_body_timeout 30s;",
            "proxy_connect_timeout 5s;",
        ):
            self.assertIn(directive, tls_vhost)


class NginxAopInstallerTests(unittest.TestCase):
    def test_apply_uses_the_shared_clean_worktree_release_guard(self):
        installer = INSTALLER.read_text()
        self.assertIn(
            '"$repo_dir/deploy/require-clean-worktree.sh" check', installer
        )
        self.assertIn(
            "production AOP CA must already reside at $dest_ca", installer
        )

    def test_openssl_uses_a_fixed_binary_and_empty_environment(self):
        installer = INSTALLER.read_text()
        self.assertIn('openssl_bin="/usr/bin/openssl"', installer)
        self.assertGreaterEqual(
            installer.count('"$env_bin" -i PATH=/usr/bin:/bin LC_ALL=C'), 5
        )
        self.assertNotIn("LC_ALL=C openssl", installer)
        self.assertNotIn("$(openssl ", installer)

    def test_test_mode_root_guard_precedes_path_selected_executables(self):
        installer = INSTALLER.read_text()
        root_guard = 'if [ "$test_mode" = "1" ] && [ "$EUID" -eq 0 ]; then'
        self.assertIn(root_guard, installer)
        for executable_lookup in (
            'env_bin="$(command -v env)"',
            'openssl_bin="$(command -v openssl)"',
            'nginx_bin="$(command -v nginx)"',
            'systemctl_bin="$(command -v systemctl)"',
            'flock_bin="$(command -v flock)"',
            'curl_bin="$(command -v curl)"',
        ):
            self.assertLess(installer.index(root_guard), installer.index(executable_lookup))

    def test_test_mode_rejects_root_or_canonical_production_nginx_root(self):
        env = {
            "PATH": "/usr/bin:/bin",
            "SUB2API_AOP_TEST_MODE": "1",
            "SUB2API_NGINX_ROOT": "/etc/../etc/nginx",
        }
        result = subprocess.run(
            ["bash", str(INSTALLER), "check"],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        expected_error = (
            "test mode may not run as root"
            if os.geteuid() == 0
            else "test mode may not target the production Nginx root"
        )
        self.assertIn(expected_error, result.stderr)

    def make_fake_commands(
        self,
        root,
        *,
        fail_first_test=False,
        fail_first_reload=False,
        fail_probe=False,
    ):
        bin_dir = root / "bin"
        bin_dir.mkdir(exist_ok=True)
        nginx_calls = root / "nginx-calls"
        reload_calls = root / "reload-calls"
        probe_calls = root / "probe-calls"
        curl_args = root / "curl-args"
        curl_env = root / "curl-env"
        lock_path = root / "nginx" / "sub2api-gate" / "nginx-operation.lock"
        require_lock = (
            f'lock_path="{lock_path}"\n'
            'if /usr/bin/flock -n "$lock_path" -c true; then\n'
            '  echo "shared Nginx lock was not held" >&2\n'
            '  exit 90\n'
            'fi\n'
        )

        nginx = bin_dir / "nginx"
        nginx.write_text(
            "#!/bin/sh\n"
            + require_lock
            + f"calls={nginx_calls!s}\n"
            "count=0\n"
            "[ ! -f \"$calls\" ] || count=$(cat \"$calls\")\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > \"$calls\"\n"
            + ("[ \"$count\" -ne 1 ]\n" if fail_first_test else "exit 0\n")
        )
        nginx.chmod(nginx.stat().st_mode | stat.S_IXUSR)

        systemctl = bin_dir / "systemctl"
        systemctl.write_text(
            "#!/bin/sh\n"
            + require_lock
            + f"calls={reload_calls!s}\n"
            "count=0\n"
            "[ ! -f \"$calls\" ] || count=$(cat \"$calls\")\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > \"$calls\"\n"
            + ("[ \"$count\" -ne 1 ]\n" if fail_first_reload else "exit 0\n")
        )
        systemctl.chmod(systemctl.stat().st_mode | stat.S_IXUSR)

        curl = bin_dir / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            + require_lock
            + f"calls={probe_calls!s}\n"
            + f"args_file={curl_args!s}\n"
            + f"env_file={curl_env!s}\n"
            "count=0\n"
            "[ ! -f \"$calls\" ] || count=$(cat \"$calls\")\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > \"$calls\"\n"
            "printf '%s\\n' \"$@\" > \"$args_file\"\n"
            "printf '%s\\n' \"${ALL_PROXY-unset}|${CURL_CA_BUNDLE-unset}|${SSL_CERT_FILE-unset}|${SSL_CERT_DIR-unset}\" > \"$env_file\"\n"
            + ("exit 22\n" if fail_probe else "")
            + "headers=\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --dump-header) headers=$2; shift 2 ;;\n"
            "    *) shift ;;\n"
            "  esac\n"
            "done\n"
            "[ -n \"$headers\" ] || exit 91\n"
            "printf 'HTTP/2 204\\r\\nX-Sub2API-AOP-Verify: SUCCESS\\r\\n\\r\\n' > \"$headers\"\n"
            "printf '204'\n"
        )
        curl.chmod(curl.stat().st_mode | stat.S_IXUSR)

        release_guard = bin_dir / "release-guard"
        release_guard.write_text("#!/bin/sh\nexit 0\n")
        release_guard.chmod(release_guard.stat().st_mode | stat.S_IXUSR)
        return bin_dir, nginx_calls, reload_calls, release_guard

    def run_installer(
        self,
        root,
        *args,
        fail_first_test=False,
        fail_first_reload=False,
        fail_probe=False,
        preserve_snippets_mode=False,
        test_now=1000,
        test_uptime=100,
    ):
        nginx_root = root / "nginx"
        (nginx_root / "snippets").mkdir(parents=True, exist_ok=True)
        nginx_root.chmod(0o755)
        runtime_parent = root / "run"
        runtime_parent.mkdir(mode=0o755, exist_ok=True)
        runtime_parent.chmod(0o755)
        if not preserve_snippets_mode:
            (nginx_root / "snippets").chmod(0o755)
        bin_dir, nginx_calls, reload_calls, release_guard = self.make_fake_commands(
            root,
            fail_first_test=fail_first_test,
            fail_first_reload=fail_first_reload,
            fail_probe=fail_probe,
        )
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ.get('PATH', '')}",
            "SUB2API_AOP_TEST_MODE": "1",
            "SUB2API_NGINX_ROOT": str(nginx_root),
            "SUB2API_AOP_RUNTIME_ROOT": str(runtime_parent / "sub2api-gate"),
            "SUB2API_AOP_TEST_NOW": str(test_now),
            "SUB2API_AOP_TEST_UPTIME": str(test_uptime),
            "SUB2API_AOP_TEST_BOOT_ID": TEST_BOOT_ID,
            "SUB2API_RELEASE_GUARD": str(release_guard),
            "ALL_PROXY": "http://untrusted-proxy.invalid:8080",
            "CURL_CA_BUNDLE": "/untrusted/curl-ca.pem",
            "SSL_CERT_FILE": "/untrusted/ssl-cert.pem",
            "SSL_CERT_DIR": "/untrusted/ssl-certs",
            "OPENSSL_CONF": "/untrusted/openssl.cnf",
            "OPENSSL_MODULES": "/untrusted/openssl-modules",
        }
        result = subprocess.run(
            ["bash", str(INSTALLER), *args],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
        )
        return result, nginx_root, nginx_calls, reload_calls

    def prepare_optional_and_proof(self, root, ca, *, now=1000, uptime=100):
        optional, nginx_root, nginx_calls, reload_calls = self.run_installer(
            root,
            "--apply",
            "--stage",
            "optional",
            "--hostname",
            HOSTNAME,
            "--ca-file",
            str(ca),
            test_now=now,
            test_uptime=uptime,
        )
        self.assertEqual(optional.returncode, 0, optional.stderr)
        probe, _, _, _ = self.run_installer(
            root,
            "--apply",
            "--stage",
            "probe",
            "--hostname",
            HOSTNAME,
            test_now=now,
            test_uptime=uptime,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)
        for path in (
            nginx_calls,
            reload_calls,
            root / "probe-calls",
            root / "curl-args",
            root / "curl-env",
        ):
            path.unlink(missing_ok=True)
        return nginx_root

    def test_check_is_read_only_and_does_not_call_nginx(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            result, nginx_root, nginx_calls, reload_calls = self.run_installer(
                root, "check", "--stage", "optional"
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((nginx_root / "sub2api-gate").exists())
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())
            self.assertIn("no file was changed", result.stdout)

    def test_apply_installs_optional_stage_and_public_ca(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            result, nginx_root, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            active = nginx_root / "snippets" / "sub2api-aop-active.conf"
            installed_ca = nginx_root / "sub2api-gate" / "aop" / "client-ca.pem"
            install_state = nginx_root / "sub2api-gate" / "aop" / "install-state"
            self.assertIn("ssl_verify_client optional;", active.read_text())
            self.assertIn("BEGIN CERTIFICATE", installed_ca.read_text())
            self.assertNotIn("PRIVATE KEY", installed_ca.read_text())
            self.assertEqual(installed_ca.stat().st_mode & 0o777, 0o644)
            self.assertIn("stage=optional\n", install_state.read_text())
            self.assertIn(f"hostname={HOSTNAME}\n", install_state.read_text())
            self.assertEqual(install_state.stat().st_mode & 0o777, 0o600)
            self.assertFalse((root / "run" / "sub2api-gate" / "aop-proof").exists())
            self.assertEqual(nginx_calls.read_text().strip(), "1")
            self.assertEqual(reload_calls.read_text().strip(), "1")

    def test_probe_readiness_with_ca_file_requires_the_installed_ca(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            other_ca = root / "other-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            self.make_test_ca(other_ca, root / "other-ca.key")
            optional, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
            )
            self.assertEqual(optional.returncode, 0, optional.stderr)
            nginx_calls.unlink()
            reload_calls.unlink()

            mismatch, _, _, _ = self.run_installer(
                root,
                "check",
                "--stage",
                "probe",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(other_ca),
            )

            self.assertNotEqual(mismatch.returncode, 0)
            self.assertIn("reuse the installed CA", mismatch.stderr)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())
            self.assertFalse((root / "probe-calls").exists())

    def test_failed_syntax_check_restores_previous_active_stage_and_ca(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            nginx_root = root / "nginx"
            snippets = nginx_root / "snippets"
            aop = nginx_root / "sub2api-gate" / "aop"
            snippets.mkdir(parents=True)
            aop.mkdir(parents=True)
            snippets.chmod(0o755)
            aop.parent.chmod(0o700)
            aop.chmod(0o700)
            active = snippets / "sub2api-aop-active.conf"
            installed_ca = aop / "client-ca.pem"
            active.write_text("previous active config\n")
            installed_ca.write_text("previous public ca\n")
            active.chmod(0o640)
            installed_ca.chmod(0o640)

            ca = root / "replacement-ca.pem"
            self.make_test_ca(ca, root / "replacement-ca.key")
            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
                fail_first_test=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(active.read_text(), "previous active config\n")
            self.assertEqual(installed_ca.read_text(), "previous public ca\n")
            self.assertEqual(nginx_calls.read_text().strip(), "2")
            self.assertEqual(reload_calls.read_text().strip(), "1")
            self.assertIn("restored", result.stderr)

    def test_failed_reload_also_restores_previous_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            nginx_root = root / "nginx"
            snippets = nginx_root / "snippets"
            aop = nginx_root / "sub2api-gate" / "aop"
            snippets.mkdir(parents=True)
            aop.mkdir(parents=True)
            snippets.chmod(0o755)
            aop.parent.chmod(0o700)
            aop.chmod(0o700)
            active = snippets / "sub2api-aop-active.conf"
            installed_ca = aop / "client-ca.pem"
            active.write_text("previous active config\n")
            installed_ca.write_text("previous public ca\n")
            active.chmod(0o640)
            installed_ca.chmod(0o640)

            ca = root / "replacement-ca.pem"
            self.make_test_ca(ca, root / "replacement-ca.key")
            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
                fail_first_reload=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(active.read_text(), "previous active config\n")
            self.assertEqual(installed_ca.read_text(), "previous public ca\n")
            self.assertEqual(nginx_calls.read_text().strip(), "2")
            self.assertEqual(reload_calls.read_text().strip(), "2")

    def test_apply_rejects_a_private_key_as_the_ca_input(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            key = root / "client-ca.key"
            self.make_test_ca(ca, key)
            result, nginx_root, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(key),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("private key", result.stderr.lower())
            self.assertFalse((nginx_root / "sub2api-gate").exists())
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_rejects_untrusted_snippets_before_creating_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            snippets = root / "nginx" / "snippets"
            snippets.mkdir(parents=True)
            snippets.parent.chmod(0o755)
            snippets.chmod(0o775)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")

            result, nginx_root, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
                preserve_snippets_mode=True,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe ownership or permissions", result.stderr)
            self.assertFalse((nginx_root / "sub2api-gate").exists())
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_rejects_untrusted_managed_file_before_creating_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            snippets = root / "nginx" / "snippets"
            snippets.mkdir(parents=True)
            active = snippets / "sub2api-aop-active.conf"
            active.write_text("previous active config\n")
            active.chmod(0o664)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")

            result, nginx_root, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe ownership or permissions", result.stderr)
            self.assertFalse((nginx_root / "sub2api-gate").exists())
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_fails_closed_while_shared_nginx_lock_is_held(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            nginx_root = root / "nginx"
            (nginx_root / "snippets").mkdir(parents=True)
            state_root = nginx_root / "sub2api-gate"
            state_root.mkdir(mode=0o700)
            nginx_root.chmod(0o755)
            (nginx_root / "snippets").chmod(0o755)
            state_root.chmod(0o700)
            lock_path = state_root / "nginx-operation.lock"
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")

            with lock_path.open("a+") as held_lock:
                lock_path.chmod(0o600)
                held_lock.flush()
                fcntl.flock(held_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result, _, nginx_calls, reload_calls = self.run_installer(
                    root,
                    "--apply",
                    "--stage",
                    "optional",
                    "--hostname",
                    HOSTNAME,
                    "--ca-file",
                    str(ca),
                )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("already in progress", result.stderr)
            self.assertFalse((state_root / "backups").exists())
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_apply_rejects_symlinked_state_before_backup_or_nginx_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            nginx_root = root / "nginx"
            snippets = nginx_root / "snippets"
            snippets.mkdir(parents=True)
            nginx_root.chmod(0o755)
            snippets.chmod(0o755)
            external_state = root / "external-state"
            external_state.mkdir(mode=0o700)
            external_state.chmod(0o700)
            (nginx_root / "sub2api-gate").symlink_to(external_state)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")

            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing or unsafe", result.stderr)
            self.assertFalse((external_state / "backups").exists())
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_ca_input_rejects_multiple_certificates_and_near_expiry(self):
        for case in ("multiple", "near-expiry"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                ca = root / "client-ca.pem"
                key = root / "client-ca.key"
                if case == "near-expiry":
                    self.make_test_ca(ca, key, days=1)
                else:
                    second = root / "second-ca.pem"
                    self.make_test_ca(ca, key)
                    self.make_test_ca(second, root / "second-ca.key")
                    ca.write_text(ca.read_text() + second.read_text())
                result, nginx_root, nginx_calls, reload_calls = self.run_installer(
                    root,
                    "--apply",
                    "--stage",
                    "optional",
                    "--hostname",
                    HOSTNAME,
                    "--ca-file",
                    str(ca),
                )
                self.assertNotEqual(result.returncode, 0)
                expected = "exactly one" if case == "multiple" else "at least 30 days"
                self.assertIn(expected, result.stderr)
                self.assertFalse((nginx_root / "sub2api-gate").exists())
                self.assertFalse(nginx_calls.exists())
                self.assertFalse(reload_calls.exists())

    def test_required_cannot_skip_optional_or_probe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "required",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())
            self.assertFalse((root / "probe-calls").exists())

    def test_failed_public_probe_writes_no_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            optional, _, _, _ = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
            )
            self.assertEqual(optional.returncode, 0, optional.stderr)
            result, _, _, _ = self.run_installer(
                root,
                "--apply",
                "--stage",
                "probe",
                "--hostname",
                HOSTNAME,
                fail_probe=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("public Cloudflare AOP HTTPS probe failed", result.stderr)
            self.assertFalse((root / "run" / "sub2api-gate" / "aop-proof").exists())

    def test_public_probe_is_exact_https_bounded_and_writes_private_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            optional, _, _, _ = self.run_installer(
                root,
                "--apply",
                "--stage",
                "optional",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
            )
            self.assertEqual(optional.returncode, 0, optional.stderr)
            result, _, _, _ = self.run_installer(
                root,
                "--apply",
                "--stage",
                "probe",
                "--hostname",
                HOSTNAME,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            args = (root / "curl-args").read_text().splitlines()
            self.assertEqual(args[0], "--disable")
            for option, value in (
                ("--noproxy", "*"),
                ("--proto", "=https"),
                ("--connect-timeout", "5"),
                ("--max-time", "10"),
                ("--max-redirs", "0"),
                ("--output", "/dev/null"),
            ):
                index = args.index(option)
                self.assertEqual(args[index + 1], value)
            self.assertNotIn("--location", args)
            self.assertEqual(
                (root / "curl-env").read_text().strip(),
                "unset|unset|unset|unset",
            )
            self.assertRegex(
                args[-1],
                rf"^https://{HOSTNAME}/\.well-known/sub2api-aop-probe\?nonce=[0-9a-f]{{32}}$",
            )
            proof = root / "run" / "sub2api-gate" / "aop-proof"
            self.assertEqual(proof.stat().st_mode & 0o777, 0o600)
            proof_text = proof.read_text()
            self.assertIn(f"hostname={HOSTNAME}\n", proof_text)
            self.assertIn(f"boot_id={TEST_BOOT_ID}\n", proof_text)
            self.assertRegex(proof_text, r"ca_sha256=[0-9a-f]{64}\n")
            self.assertRegex(proof_text, r"optional_sha256=[0-9a-f]{64}\n")

    def test_required_rejects_expired_probe_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            self.prepare_optional_and_proof(root, ca)
            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "required",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
                test_now=1301,
                test_uptime=401,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expired", result.stderr)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    def test_required_rejects_ca_or_hostname_change(self):
        for case in ("ca", "hostname"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                ca = root / "client-ca.pem"
                self.make_test_ca(ca, root / "client-ca.key")
                nginx_root = self.prepare_optional_and_proof(root, ca)
                requested_ca = ca
                requested_hostname = HOSTNAME
                if case == "ca":
                    requested_ca = root / "other-ca.pem"
                    self.make_test_ca(requested_ca, root / "other-ca.key")
                else:
                    requested_hostname = "other.example.com"
                result, _, nginx_calls, reload_calls = self.run_installer(
                    root,
                    "--apply",
                    "--stage",
                    "required",
                    "--hostname",
                    requested_hostname,
                    "--ca-file",
                    str(requested_ca),
                )
                self.assertNotEqual(result.returncode, 0)
                expected_error = "reuse the installed CA" if case == "ca" else "same hostname"
                self.assertIn(expected_error, result.stderr)
                self.assertIn(
                    "ssl_verify_client optional;",
                    (nginx_root / "snippets" / "sub2api-aop-active.conf").read_text(),
                )
                self.assertFalse(nginx_calls.exists())
                self.assertFalse(reload_calls.exists())

    def test_required_success_consumes_proof_and_reuses_installed_ca(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            nginx_root = self.prepare_optional_and_proof(root, ca)
            installed_ca = nginx_root / "sub2api-gate" / "aop" / "client-ca.pem"
            ca_identity = (installed_ca.stat().st_ino, installed_ca.read_bytes())
            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "required",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
                test_now=1100,
                test_uptime=200,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "ssl_verify_client on;",
                (nginx_root / "snippets" / "sub2api-aop-active.conf").read_text(),
            )
            self.assertIn(
                "stage=required\n",
                (nginx_root / "sub2api-gate" / "aop" / "install-state").read_text(),
            )
            self.assertFalse((root / "run" / "sub2api-gate" / "aop-proof").exists())
            self.assertEqual(
                (installed_ca.stat().st_ino, installed_ca.read_bytes()), ca_identity
            )
            self.assertEqual(nginx_calls.read_text().strip(), "1")
            self.assertEqual(reload_calls.read_text().strip(), "1")
            self.assertEqual((root / "probe-calls").read_text().strip(), "1")

    def test_required_post_reload_probe_failure_restores_optional(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            nginx_root = self.prepare_optional_and_proof(root, ca)
            state = nginx_root / "sub2api-gate" / "aop" / "install-state"
            previous_state = state.read_bytes()
            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "required",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
                fail_probe=True,
                test_now=1100,
                test_uptime=200,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("post-reload public probe", result.stderr)
            self.assertIn(
                "ssl_verify_client optional;",
                (nginx_root / "snippets" / "sub2api-aop-active.conf").read_text(),
            )
            self.assertEqual(state.read_bytes(), previous_state)
            self.assertFalse((root / "run" / "sub2api-gate" / "aop-proof").exists())
            self.assertEqual(nginx_calls.read_text().strip(), "2")
            self.assertEqual(reload_calls.read_text().strip(), "2")

    def test_required_reload_failure_restores_optional_without_post_probe(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            nginx_root = self.prepare_optional_and_proof(root, ca)
            state = nginx_root / "sub2api-gate" / "aop" / "install-state"
            previous_state = state.read_bytes()
            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "required",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
                fail_first_reload=True,
                test_now=1100,
                test_uptime=200,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(state.read_bytes(), previous_state)
            self.assertIn(
                "ssl_verify_client optional;",
                (nginx_root / "snippets" / "sub2api-aop-active.conf").read_text(),
            )
            self.assertFalse((root / "probe-calls").exists())
            self.assertEqual(nginx_calls.read_text().strip(), "2")
            self.assertEqual(reload_calls.read_text().strip(), "2")

    def test_required_rejects_symlinked_or_wide_probe_proof(self):
        for case in ("symlink", "wide"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                ca = root / "client-ca.pem"
                self.make_test_ca(ca, root / "client-ca.key")
                self.prepare_optional_and_proof(root, ca)
                proof = root / "run" / "sub2api-gate" / "aop-proof"
                if case == "wide":
                    proof.chmod(0o644)
                else:
                    external = root / "external-proof"
                    external.write_bytes(proof.read_bytes())
                    proof.unlink()
                    proof.symlink_to(external)
                result, _, nginx_calls, reload_calls = self.run_installer(
                    root,
                    "--apply",
                    "--stage",
                    "required",
                    "--hostname",
                    HOSTNAME,
                    "--ca-file",
                    str(ca),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(nginx_calls.exists())
                self.assertFalse(reload_calls.exists())

    def test_apply_rejects_ip_like_hostnames(self):
        for invalid_hostname in ("127.0.0.1", "api.123"):
            with self.subTest(hostname=invalid_hostname), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp)
                ca = root / "client-ca.pem"
                self.make_test_ca(ca, root / "client-ca.key")
                result, nginx_root, nginx_calls, reload_calls = self.run_installer(
                    root,
                    "--apply",
                    "--stage",
                    "optional",
                    "--hostname",
                    invalid_hostname,
                    "--ca-file",
                    str(ca),
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("IP address", result.stderr)
                self.assertFalse((nginx_root / "sub2api-gate").exists())
                self.assertFalse(nginx_calls.exists())
                self.assertFalse(reload_calls.exists())

    def test_required_rejects_oversized_probe_proof(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            ca = root / "client-ca.pem"
            self.make_test_ca(ca, root / "client-ca.key")
            self.prepare_optional_and_proof(root, ca)
            proof = root / "run" / "sub2api-gate" / "aop-proof"
            proof.write_text("x" * 4097)
            proof.chmod(0o600)
            result, _, nginx_calls, reload_calls = self.run_installer(
                root,
                "--apply",
                "--stage",
                "required",
                "--hostname",
                HOSTNAME,
                "--ca-file",
                str(ca),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("4 KiB", result.stderr)
            self.assertFalse(nginx_calls.exists())
            self.assertFalse(reload_calls.exists())

    @staticmethod
    def make_test_ca(cert, key, *, days=60):
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key),
                "-out",
                str(cert),
                "-subj",
                "/CN=Sub2API Gate test AOP CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-days",
                str(days),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    unittest.main()
