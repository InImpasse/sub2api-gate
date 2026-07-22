import importlib.util
import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
PARSER = ROOT / "deploy" / "private_env.py"
PREFLIGHT = ROOT / "deploy" / "security-preflight.sh"
ACL_TOOL = ROOT / "deploy" / "configure-redis-acl.py"


def load_python_script(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PrivateEnvironmentTests(unittest.TestCase):
    def write_environment(self, directory, source, mode=0o600):
        path = pathlib.Path(directory) / "private.env"
        path.write_text(source, encoding="utf-8")
        path.chmod(mode)
        return path

    def test_literal_environment_is_shared_by_preflight_and_redis_acl(self):
        parser = load_python_script(PARSER, "private_env_shared")
        acl = load_python_script(ACL_TOOL, "redis_acl_shared_env")
        source = (
            "# full-line comments are allowed\n"
            "POSTGRES_PASSWORD=Abcdefghijklmnopqrstuvwxyz_123456\n"
            "REDIS_PASSWORD=redis-password_0123456789-ABCDE\n"
            "SUB2API_LOGIN_URL=https://api.example.test/login\n"
            "SECURITY_URL_ALLOWLIST_UPSTREAM_HOSTS=one.example.test,two.example.test\n"
            "VALUE_WITH_EQUALS=alpha=beta\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, source)
            expected = parser.read_private_environment(path)
            self.assertEqual(acl.read_private_environment(path), expected)
            result = subprocess.run(
                [PARSER, "--emit-nul", path],
                check=True,
                capture_output=True,
            )
        fields = result.stdout.split(b"\0")
        self.assertEqual(fields[-1], b"")
        self.assertEqual(dict(zip(fields[0::2], fields[1::2])), {
            key.encode("ascii"): value.encode("ascii")
            for key, value in expected.items()
        })

    def test_ambiguous_or_invalid_environment_syntax_is_rejected_without_echo(self):
        parser = load_python_script(PARSER, "private_env_rejections")
        sentinel = "PRIVATE_ENV_SENTINEL"
        invalid_sources = (
            f'VALUE="{sentinel}"\n',
            f"VALUE='{sentinel}'\n",
            f"VALUE={sentinel}\\n\n",
            f"VALUE={sentinel} # trailing comment\n",
            f"VALUE={sentinel}#comment\n",
            f"VALUE=${{{sentinel}}}\n",
            f"VALUE={sentinel}\nVALUE=duplicate\n",
            f"lowercase={sentinel}\n",
            f"BAD-KEY={sentinel}\n",
            f" KEY={sentinel}\n",
            f"DOCKER_HOST={sentinel}\n",
            f"COMPOSE_FILE={sentinel}\n",
        )
        for index, source in enumerate(invalid_sources):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                path = self.write_environment(directory, source)
                with self.assertRaises(parser.PrivateEnvironmentError):
                    parser.read_private_environment(path)
                result = subprocess.run(
                    [PARSER, "--emit-nul", path],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_private_environment_requires_mode_0600_and_rejects_symlinks(self):
        parser = load_python_script(PARSER, "private_env_file_boundary")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, "VALUE=literal\n", 0o640)
            with self.assertRaisesRegex(parser.PrivateEnvironmentError, "0600"):
                parser.read_private_environment(path)
            path.chmod(0o600)
            alias = pathlib.Path(directory) / "alias.env"
            alias.symlink_to(path)
            with self.assertRaisesRegex(parser.PrivateEnvironmentError, "non-symlink"):
                parser.read_private_environment(alias)

    def test_security_preflight_consumes_nul_records_and_checks_parser_status(self):
        source = PREFLIGHT.read_text(encoding="utf-8")
        self.assertIn('private_env_parser="$repo_dir/deploy/private_env.py"', source)
        self.assertIn('python3 "$private_env_parser" --emit-nul "$env_file"', source)
        self.assertIn('if ! wait "$private_env_pid"', source)
        self.assertIn('require_private_file "$wrangler_config"', source)
        self.assertNotIn('require_private_file "$env_file"', source)
        self.assertNotIn('done < "$env_file"', source)


if __name__ == "__main__":
    unittest.main()
