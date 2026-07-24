import importlib.util
import os
import pathlib
import pty
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


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

    def test_private_environment_rejects_noncanonical_line_separators(self):
        parser = load_python_script(PARSER, "private_env_line_separators")
        invalid_payloads = {
            "vertical-tab": b"FIRST=literal\x0bSECOND=literal\n",
            "form-feed": b"FIRST=literal\x0cSECOND=literal\n",
            "next-line": "FIRST=literal\u0085SECOND=literal\n".encode("utf-8"),
            "line-separator": "FIRST=literal\u2028SECOND=literal\n".encode("utf-8"),
            "paragraph-separator": "FIRST=literal\u2029SECOND=literal\n".encode("utf-8"),
            "lone-carriage-return": b"FIRST=literal\rSECOND=literal\n",
            "terminal-carriage-return": b"FIRST=literal\r",
        }
        for name, payload in invalid_payloads.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "private.env"
                path.write_bytes(payload)
                path.chmod(0o600)
                with self.assertRaises(parser.PrivateEnvironmentError):
                    parser.read_private_environment(path)

    def test_private_environment_rejects_controls_and_non_ascii_before_parsing(self):
        parser = load_python_script(PARSER, "private_env_raw_character_boundary")
        invalid_fragments = [
            bytes([value]) for value in range(0x20) if value not in {0x0A, 0x0D}
        ] + [b"\x7f", b"\x80", "\u00e4".encode("utf-8")]
        for fragment in invalid_fragments:
            with self.subTest(fragment=fragment.hex()), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "private.env"
                path.write_bytes(b"# ignored" + fragment + b"text\nVALUE=literal\n")
                path.chmod(0o600)
                with self.assertRaises(parser.PrivateEnvironmentError):
                    parser.read_private_environment(path)

    def test_private_environment_accepts_lf_and_verified_crlf(self):
        parser = load_python_script(PARSER, "private_env_canonical_line_endings")
        payloads = (
            b"  # comment\n\nFIRST=literal\nSECOND=alpha=beta\n",
            b"  # comment\r\n\r\nFIRST=literal\r\nSECOND=alpha=beta\r\n",
        )
        for payload in payloads:
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                path = pathlib.Path(directory) / "private.env"
                path.write_bytes(payload)
                path.chmod(0o600)
                self.assertEqual(
                    parser.read_private_environment(path),
                    {"FIRST": "literal", "SECOND": "alpha=beta"},
                )

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

    def test_private_environment_requires_an_absolute_path(self):
        sentinel = "RELATIVE_PRIVATE_ENV_SENTINEL"
        with tempfile.TemporaryDirectory() as directory:
            self.write_environment(directory, f"VALUE={sentinel}\n")
            result = subprocess.run(
                [PARSER, "--emit-nul", "private.env"],
                cwd=directory,
                check=False,
                capture_output=True,
                text=True,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("absolute", result.stderr)
        self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_root_private_environment_requires_the_fixed_production_path(self):
        parser = load_python_script(PARSER, "private_env_root_path")
        with mock.patch.object(parser.os, "geteuid", return_value=0), \
             mock.patch.object(parser.os, "open", side_effect=AssertionError("must not open")):
            with self.assertRaisesRegex(
                parser.PrivateEnvironmentError,
                "fixed root private environment path",
            ):
                parser.read_private_environment("/tmp/private.env")

    def test_emit_nul_rejects_a_regular_output_file_before_emitting_secrets(self):
        sentinel = "PRIVATE_ENV_REGULAR_OUTPUT_SENTINEL"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, f"VALUE={sentinel}\n")
            output_path = pathlib.Path(directory) / "captured.env"
            with output_path.open("wb") as output:
                result = subprocess.run(
                    [PARSER, "--emit-nul", path],
                    check=False,
                    stdout=output,
                    stderr=subprocess.PIPE,
                    text=True,
                )

            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output_path.read_bytes(), b"")
            self.assertIn("protected pipe", result.stderr)
            self.assertNotIn(sentinel, result.stderr)

    def test_emit_nul_rejects_a_directory_output_descriptor(self):
        sentinel = "PRIVATE_ENV_DIRECTORY_OUTPUT_SENTINEL"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, f"VALUE={sentinel}\n")
            output_descriptor = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                result = subprocess.run(
                    [PARSER, "--emit-nul", path],
                    check=False,
                    stdout=output_descriptor,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            finally:
                os.close(output_descriptor)

            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(sentinel, result.stderr)

    def test_emit_nul_rejects_a_tty_output_descriptor(self):
        sentinel = "PRIVATE_ENV_TTY_OUTPUT_SENTINEL"
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, f"VALUE={sentinel}\n")
            master_descriptor, slave_descriptor = pty.openpty()
            try:
                result = subprocess.run(
                    [PARSER, "--emit-nul", path],
                    check=False,
                    stdout=slave_descriptor,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            finally:
                os.close(slave_descriptor)
                os.close(master_descriptor)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("protected pipe", result.stderr)
            self.assertNotIn(sentinel, result.stderr)

    def test_private_environment_rejects_symlinked_ancestor_directories(self):
        parser = load_python_script(PARSER, "private_env_ancestor_boundary")
        with tempfile.TemporaryDirectory() as directory:
            directory_path = pathlib.Path(directory)
            real_directory = directory_path / "real"
            real_directory.mkdir()
            path = self.write_environment(real_directory, "VALUE=literal\n")
            alias_directory = directory_path / "alias"
            alias_directory.symlink_to(real_directory, target_is_directory=True)
            aliased_path = alias_directory / path.name

            with self.assertRaisesRegex(
                parser.PrivateEnvironmentError, "non-symlink"
            ):
                parser.read_private_environment(aliased_path)

    def test_root_private_environment_checks_every_ancestor_directory(self):
        parser = load_python_script(PARSER, "private_env_root_ancestor_boundary")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            parent = root / "private"
            parent.mkdir(mode=0o700)
            path = self.write_environment(parent, "VALUE=literal\n")
            real_fstat = os.fstat

            for name in ("uid", "gid", "group_writable", "world_writable"):
                directory_calls = [0]

                def root_owned_stat(descriptor, case=name):
                    metadata = real_fstat(descriptor)
                    fields = list(metadata)
                    if stat.S_ISDIR(metadata.st_mode):
                        directory_calls[0] += 1
                        fields[0] = stat.S_IFDIR | 0o700
                        fields[4] = 0
                        fields[5] = 0
                        if directory_calls[0] == 2:
                            if case == "uid":
                                fields[4] = 1
                            elif case == "gid":
                                fields[5] = 1
                            elif case == "group_writable":
                                fields[0] = stat.S_IFDIR | 0o720
                            else:
                                fields[0] = stat.S_IFDIR | 0o702
                    elif stat.S_ISREG(metadata.st_mode):
                        fields[0] = stat.S_IFREG | 0o600
                        fields[3] = 1
                        fields[4] = 0
                        fields[5] = 0
                    return os.stat_result(fields)

                with self.subTest(case=name), \
                     mock.patch.object(parser, "PRODUCTION_PRIVATE_ENV_PATH", path), \
                     mock.patch.object(parser.os, "geteuid", return_value=0), \
                     mock.patch.object(parser.os, "getegid", return_value=0), \
                     mock.patch.object(parser.os, "fstat", side_effect=root_owned_stat):
                    with self.assertRaisesRegex(
                        parser.PrivateEnvironmentError,
                        "ancestor directory",
                    ):
                        parser.read_private_environment(path)

    def test_private_environment_rejects_multiply_linked_files(self):
        parser = load_python_script(PARSER, "private_env_hardlink_boundary")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, "VALUE=literal\n")
            hardlink = pathlib.Path(directory) / "hardlink.env"
            os.link(path, hardlink)

            with self.assertRaisesRegex(
                parser.PrivateEnvironmentError, "single filesystem link"
            ):
                parser.read_private_environment(path)

    def test_private_environment_requires_the_expected_operator_owner(self):
        parser = load_python_script(PARSER, "private_env_owner_boundary")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, "VALUE=literal\n")
            real_fstat = os.fstat

            for stat_index, wrong_value in (
                (4, os.geteuid() + 1),
                (5, os.getegid() + 1),
            ):
                def wrong_file_owner(descriptor, index=stat_index, value=wrong_value):
                    file_stat = real_fstat(descriptor)
                    if not stat.S_ISREG(file_stat.st_mode):
                        return file_stat
                    changed_fields = list(file_stat)
                    changed_fields[index] = value
                    return os.stat_result(changed_fields)

                with self.subTest(stat_index=stat_index), mock.patch.object(
                    parser.os, "fstat", side_effect=wrong_file_owner
                ):
                    with self.assertRaisesRegex(
                        parser.PrivateEnvironmentError, "expected operator"
                    ):
                        parser.read_private_environment(path)

    def test_private_environment_rejects_a_file_changed_during_read(self):
        parser = load_python_script(PARSER, "private_env_stable_read")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, "VALUE=literal\n")
            initial_stat = os.stat(path)
            changed_fields = list(initial_stat)
            changed_fields[6] = initial_stat.st_size + 1
            changed_stat = os.stat_result(changed_fields)
            real_fstat = os.fstat
            file_stat_calls = 0

            def changed_after_first_file_stat(descriptor):
                nonlocal file_stat_calls
                file_stat = real_fstat(descriptor)
                if not stat.S_ISREG(file_stat.st_mode):
                    return file_stat
                file_stat_calls += 1
                return initial_stat if file_stat_calls == 1 else changed_stat

            with mock.patch.object(
                parser.os, "fstat", side_effect=changed_after_first_file_stat
            ):
                with self.assertRaisesRegex(
                    parser.PrivateEnvironmentError, "changed while being read"
                ):
                    parser.read_private_environment(path)

    def test_private_environment_reads_values_and_identity_from_one_descriptor(self):
        parser = load_python_script(PARSER, "private_env_read_identity")
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_environment(directory, "VALUE=literal\n")
            with mock.patch.object(
                parser,
                "private_environment_identity",
                side_effect=AssertionError("must not reopen the private environment"),
            ):
                values, identity = parser.read_private_environment_with_identity(path)

            metadata = path.stat()
            self.assertEqual(values, {"VALUE": "literal"})
            self.assertEqual(identity["device"], metadata.st_dev)
            self.assertEqual(identity["inode"], metadata.st_ino)
            self.assertEqual(identity["mode"], metadata.st_mode)

    def test_private_environment_rejects_a_writable_parent_directory(self):
        parser = load_python_script(PARSER, "private_env_parent_mode")
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory) / "private"
            parent.mkdir(mode=0o700)
            path = self.write_environment(parent, "VALUE=literal\n")

            for mode in (0o720, 0o702):
                parent.chmod(mode)
                with self.subTest(mode=oct(mode)), self.assertRaisesRegex(
                    parser.PrivateEnvironmentError, "parent directory"
                ):
                    parser.read_private_environment(path)

    def test_private_environment_parent_must_belong_to_the_operator(self):
        parser = load_python_script(PARSER, "private_env_parent_owner")
        with tempfile.TemporaryDirectory() as directory:
            parent = pathlib.Path(directory) / "private"
            parent.mkdir(mode=0o700)
            path = self.write_environment(parent, "VALUE=literal\n")
            real_fstat = os.fstat

            def parent_owned_by_another_user(descriptor):
                file_stat = real_fstat(descriptor)
                if not stat.S_ISDIR(file_stat.st_mode):
                    return file_stat
                changed_fields = list(file_stat)
                changed_fields[4] = os.geteuid() + 1
                return os.stat_result(changed_fields)

            with mock.patch.object(
                parser.os, "fstat", side_effect=parent_owned_by_another_user
            ):
                with self.assertRaisesRegex(
                    parser.PrivateEnvironmentError, "parent directory"
                ):
                    parser.read_private_environment(path)

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
