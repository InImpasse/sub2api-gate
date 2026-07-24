import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "nginx" / "validate_cloudflare_cidrs.py"
UPDATER_PATH = ROOT / "nginx" / "update-cloudflare-ips.sh"
SOURCE_GEO_PATH = ROOT / "nginx" / "cloudflare-source-geo.conf"
REAL_IP_PATH = ROOT / "nginx" / "snippets" / "cloudflare-real-ip.conf"
ONLY_PATH = ROOT / "nginx" / "snippets" / "cloudflare-only.conf"


def load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_cloudflare_cidrs", VALIDATOR_PATH
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CloudflareCidrValidatorTests(unittest.TestCase):
    def run_root_apply_fixture(
        self,
        directory,
        *,
        arguments=(),
        bypass_source_gate=False,
        bypass_target_directory_gate=False,
        unsafe_target=False,
    ):
        root = pathlib.Path(directory)
        nginx = root / "nginx"
        production_nginx = root / "etc" / "nginx"
        snippets = production_nginx / "snippets"
        conf_d = production_nginx / "conf.d"
        production_tmp_root = root / "run" / "sub2api-gate"
        deploy = root / "deploy"
        fake_bin = root / "bin"
        for path in (nginx, snippets, conf_d, production_tmp_root, deploy, fake_bin):
            path.mkdir(parents=True, exist_ok=True)

        source = UPDATER_PATH.read_text(encoding="utf-8").replace(
            '"$(/usr/bin/id -u)"',
            '"$(printf 0)"',
            1,
        ).replace(
            'trusted_release_root="/opt/sub2api-gate-release"',
            f'trusted_release_root="{root}"',
            1,
        ).replace(
            'production_out_dir="/etc/nginx/snippets"',
            f'production_out_dir="{snippets}"',
            1,
        ).replace(
            'production_geo_file="/etc/nginx/conf.d/00-cloudflare-source-geo.conf"',
            f'production_geo_file="{conf_d / "00-cloudflare-source-geo.conf"}"',
            1,
        ).replace(
            'production_tmp_root="/run/sub2api-gate"',
            f'production_tmp_root="{production_tmp_root}"',
            1,
        ).replace(
            "/usr/bin/curl --disable",
            f"{fake_bin / 'curl'} --disable",
            1,
        )
        if bypass_source_gate:
            for check in (
                '  require_root_safe_directory_chain "$trusted_release_root"\n',
                '  require_root_safe_directory_chain "$script_dir"\n',
                '  require_root_safe_metadata "$script_dir/update-cloudflare-ips.sh" file "Cloudflare updater source"\n',
                '  require_root_safe_metadata "$validator" file "Cloudflare CIDR validator source"\n',
                '  require_root_safe_metadata "$repo_dir/deploy/require-clean-worktree.sh" file "release guard source"\n',
            ):
                source = source.replace(check, "  :\n", 1)
        if bypass_target_directory_gate:
            source = source.replace(
                '  require_root_safe_directory_chain "$out_dir"\n',
                "  :\n",
                1,
            ).replace(
                '  require_root_safe_directory_chain "$geo_dir"\n',
                "  :\n",
                1,
            ).replace(
                '  require_root_safe_directory_chain "$production_tmp_root"\n',
                "  :\n",
                1,
            )
        updater = nginx / "update-cloudflare-ips.sh"
        updater.write_text(source, encoding="utf-8")
        updater.chmod(0o755)
        (nginx / "validate_cloudflare_cidrs.py").write_text("raise SystemExit(99)\n")

        targets = (
            snippets / "cloudflare-only.conf",
            snippets / "cloudflare-real-ip.conf",
            conf_d / "00-cloudflare-source-geo.conf",
        )
        for target in targets:
            target.write_text(f"original:{target.name}\n", encoding="utf-8")
            target.chmod(0o644)
        if unsafe_target:
            targets[0].chmod(0o664)
        original = {target: target.read_bytes() for target in targets}

        guard_marker = root / "guard-called"
        guard = deploy / "require-clean-worktree.sh"
        guard.write_text(
            "#!/bin/sh\n"
            f": > {guard_marker}\n"
            "exit 99\n",
            encoding="utf-8",
        )
        guard.chmod(0o755)
        curl_marker = root / "curl-called"
        curl = fake_bin / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            f": > {curl_marker}\n"
            "exit 99\n",
            encoding="utf-8",
        )
        curl.chmod(0o755)

        environment = os.environ.copy()
        environment["PATH"] = f"{fake_bin}:/usr/bin:/bin"
        result = subprocess.run(
            ["/bin/sh", updater, "--apply", *arguments],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertFalse(curl_marker.exists())
        self.assertFalse(guard_marker.exists())
        self.assertEqual(
            {target: target.read_bytes() for target in targets},
            original,
        )
        return result

    def test_accepts_canonical_networks_for_the_declared_family(self):
        validator = load_validator()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            ipv4 = root / "ips-v4"
            ipv6 = root / "ips-v6"
            ipv4.write_text("198.51.100.0/24\n203.0.113.0/24\n", encoding="ascii")
            ipv6.write_text("2001:db8::/32\n", encoding="ascii")

            self.assertEqual(validator.validate_file(ipv4, 4), 2)
            self.assertEqual(validator.validate_file(ipv6, 6), 1)

    def test_rejects_invalid_wrong_family_duplicate_and_noncanonical_networks(self):
        validator = load_validator()
        invalid_inputs = (
            ("999.999.999.999/999\n", 4),
            ("2001:db8::/32\n", 4),
            ("198.51.100.4/24\n", 4),
            ("198.51.100.0/24\n198.51.100.0/24\n", 4),
            ("198.51.100.0/24\n<script>\n", 4),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "cidrs"
            for contents, family in invalid_inputs:
                with self.subTest(contents=contents, family=family):
                    path.write_text(contents, encoding="ascii")
                    with self.assertRaises(ValueError):
                        validator.validate_file(path, family)

    def test_rejects_empty_and_oversized_lists(self):
        validator = load_validator()
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "cidrs"
            path.write_bytes(b"")
            with self.assertRaises(ValueError):
                validator.validate_file(path, 4)

            path.write_bytes(b"1" * (validator.MAX_LIST_BYTES + 1))
            with self.assertRaises(ValueError):
                validator.validate_file(path, 4)

    def test_generated_boundary_uses_original_peer_and_preserves_loopback_health(self):
        updater = UPDATER_PATH.read_text(encoding="utf-8")
        source_geo = SOURCE_GEO_PATH.read_text(encoding="utf-8")
        self.assertIn("geo $realip_remote_addr $cloudflare_source_allowed", source_geo)
        self.assertIn("127.0.0.1/32 1;", source_geo)
        self.assertIn("::1/128 1;", source_geo)
        self.assertIn("cloudflare-source-geo.conf", updater)
        self.assertIn("if ($cloudflare_source_allowed = 0)", updater)
        self.assertIn('mode="${1:-check}"', updater)
        self.assertIn("no network request was made and no file was changed", updater)
        self.assertEqual(updater.count("--proto-redir '=https'"), 2)
        self.assertTrue(updater.startswith("#!/bin/sh\nset -eu\n"))
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin\nexport PATH", updater)
        self.assertIn("unset ENV BASH_ENV CDPATH", updater)
        self.assertIn("LD_PRELOAD LD_LIBRARY_PATH PYTHONHOME PYTHONPATH", updater)
        self.assertIn("TMPDIR TMP TEMP CURL_HOME CURL_CA_BUNDLE", updater)
        self.assertLess(updater.index("PATH=/usr/sbin"), updater.index('mode="${1:-check}"'))
        self.assertGreaterEqual(updater.count("/usr/bin/env -i PATH="), 3)
        self.assertIn('/usr/bin/python3 -I "$validator"', updater)
        self.assertIn("/usr/bin/curl --disable", updater)
        self.assertIn('production_tmp_root="/run/sub2api-gate"', updater)
        self.assertIn(
            'tmp_dir="$(/usr/bin/mktemp -d "$production_tmp_root/cloudflare-ips.XXXXXXXXXX")"',
            updater,
        )
        self.assertIn('trusted_release_root="/opt/sub2api-gate-release"', updater)
        self.assertIn('production_out_dir="/etc/nginx/snippets"', updater)
        self.assertIn(
            'production_geo_file="/etc/nginx/conf.d/00-cloudflare-source-geo.conf"',
            updater,
        )
        apply_gate = updater.index(
            'if [ "$root_apply" -eq 1 ]; then',
            updater.index('if [ "$mode" != "--apply" ]; then'),
        )
        self.assertLess(
            apply_gate,
            updater.index("\nrun_release_guard\n"),
        )
        validator = load_validator()
        self.assertGreaterEqual(
            validator.validate_installed_boundary(
                REAL_IP_PATH, SOURCE_GEO_PATH, ONLY_PATH
            ),
            15,
        )

    def test_root_apply_rejects_custom_output_paths_before_guard_network_or_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            result = self.run_root_apply_fixture(
                directory,
                arguments=(str(root / "custom-snippets"), str(root / "custom-geo")),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("does not accept Cloudflare updater output overrides", result.stderr)
            self.assertFalse((root / "custom-snippets").exists())
            self.assertFalse((root / "custom-geo").exists())

    def test_root_apply_rejects_unsafe_source_ancestor_before_guard_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_root_apply_fixture(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "production path directory must be root-owned and not group/world writable",
                result.stderr,
            )

    def test_root_apply_rejects_unsafe_target_ancestor_before_guard_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_root_apply_fixture(
                directory,
                bypass_source_gate=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "production path directory must be root-owned and not group/world writable",
                result.stderr,
            )

    def test_root_apply_rejects_unsafe_final_target_before_guard_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_root_apply_fixture(
                directory,
                bypass_source_gate=True,
                bypass_target_directory_gate=True,
                unsafe_target=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "cloudflare-only target must be root-owned and not group/world writable",
                result.stderr,
            )

    def test_installed_boundary_rejects_mismatched_or_broad_trust(self):
        validator = load_validator()
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            real_ip = root / "real.conf"
            geo = root / "geo.conf"
            only = root / "only.conf"
            real_ip.write_bytes(REAL_IP_PATH.read_bytes())
            geo.write_bytes(SOURCE_GEO_PATH.read_bytes())
            only.write_bytes(ONLY_PATH.read_bytes())

            geo.write_text(
                geo.read_text(encoding="ascii").replace(
                    "    103.21.244.0/22 1;\n", ""
                ),
                encoding="ascii",
            )
            with self.assertRaisesRegex(ValueError, "do not match"):
                validator.validate_installed_boundary(real_ip, geo, only)

            geo.write_bytes(SOURCE_GEO_PATH.read_bytes())
            real_ip.write_text(
                real_ip.read_text(encoding="ascii")
                + "set_real_ip_from 0.0.0.0/0;\n",
                encoding="ascii",
            )
            with self.assertRaisesRegex(ValueError, "unsafe broad"):
                validator.validate_installed_boundary(real_ip, geo, only)

if __name__ == "__main__":
    unittest.main()
