import importlib.util
import pathlib
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
        validator = load_validator()
        self.assertGreaterEqual(
            validator.validate_installed_boundary(
                REAL_IP_PATH, SOURCE_GEO_PATH, ONLY_PATH
            ),
            15,
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
