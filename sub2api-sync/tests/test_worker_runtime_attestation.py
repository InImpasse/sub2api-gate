import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "worker-runtime-attestation.py"
DEPLOY_WORKER = ROOT / "deploy" / "deploy-worker.sh"
SECRET_INITIALIZER = ROOT / "deploy" / "generate-worker-secrets.py"
DEPLOY_README = ROOT / "deploy" / "README.md"
SPEC = importlib.util.spec_from_file_location("worker_runtime_attestation", TOOL_PATH)
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


class WorkerRuntimeAttestationTests(unittest.TestCase):
    def test_totp_rotation_runbook_uses_the_attested_direct_wrangler_entry(self):
        readme = DEPLOY_README.read_text(encoding="utf-8")
        section = readme.split("## Administrator TOTP rotation", 1)[1].split(
            "## Per-hostname Authenticated Origin Pull", 1
        )[0]

        self.assertNotIn("node_modules/.bin/wrangler", section)
        self.assertNotIn("wrangler_bin=", section)
        self.assertIn("node_bin=/usr/bin/node", section)
        self.assertIn(
            'wrangler_cmd=("$node_bin" "$worker_dir/node_modules/wrangler/bin/wrangler.js")',
            section,
        )
        for operation in ("put", "list", "delete"):
            self.assertIn(
                f'"${{wrangler_cmd[@]}}" secret {operation}',
                section,
            )

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.worker = self.root / "worker-allow-ip"
        self.node_modules = self.worker / "node_modules"
        self.entry = self.node_modules / "wrangler" / "bin" / "wrangler.js"
        self.entry.parent.mkdir(parents=True)
        self.entry.write_text("console.log('4.112.0');\n", encoding="ascii")
        self.dependency = self.node_modules / "dependency" / "index.js"
        self.dependency.parent.mkdir()
        self.dependency.write_text("module.exports = 1;\n", encoding="ascii")
        self.package_lock = self.worker / "package-lock.json"
        self.package_lock.write_text(
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "node_modules/wrangler": {
                            "version": TOOL.WRANGLER_VERSION,
                            "integrity": "sha512-test-only",
                            "bin": {"wrangler": "bin/wrangler.js"},
                        }
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="ascii",
        )
        self.package_lock.chmod(0o644)
        TOOL.secure_runtime_permissions(
            self.node_modules,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )
        self.state_directory = self.root / "state"
        self.state_directory.mkdir(mode=0o700)
        self.state_path = self.state_directory / "worker-runtime.json"
        self.uid = os.geteuid()
        self.gid = os.getegid()
        self.git_head = "a" * 40
        self.node_version = "v22.14.0"
        self.write_attestation()

    def tearDown(self):
        self.temporary.cleanup()

    def write_attestation(self):
        document = TOOL.build_attestation(
            self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
            git_head=self.git_head,
            node_version=self.node_version,
        )
        TOOL.write_state(
            self.state_path,
            document,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        return document

    def verify(self, *, git_head=None):
        return TOOL.verify_attestation(
            self.root,
            self.state_path,
            expected_uid=self.uid,
            expected_gid=self.gid,
            git_head=self.git_head if git_head is None else git_head,
            node_version=self.node_version,
        )

    def test_exact_tree_and_private_atomic_state_verify(self):
        expected = self.write_attestation()
        self.assertEqual(self.verify(), expected)
        metadata = self.state_path.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_nlink, 1)
        self.state_path.chmod(0o644)
        with self.assertRaisesRegex(TOOL.WorkerRuntimeError, "unsafe"):
            self.verify()

    def test_content_addition_and_deletion_are_detected(self):
        for mutation in ("content", "addition", "deletion"):
            with self.subTest(mutation=mutation):
                self.write_attestation()
                if mutation == "content":
                    self.dependency.write_text("module.exports = 2;\n", encoding="ascii")
                elif mutation == "addition":
                    (self.node_modules / "unexpected.js").write_text(
                        "unexpected\n", encoding="ascii"
                    )
                else:
                    self.dependency.unlink()
                with self.assertRaises(TOOL.WorkerRuntimeError):
                    self.verify()
                if mutation == "content":
                    self.dependency.write_text("module.exports = 1;\n", encoding="ascii")
                elif mutation == "addition":
                    (self.node_modules / "unexpected.js").unlink()
                else:
                    self.dependency.write_text("module.exports = 1;\n", encoding="ascii")

    def test_symlink_and_hardlink_are_rejected(self):
        outside = self.root / "outside"
        outside.write_text("outside\n", encoding="ascii")
        symlink = self.node_modules / "symlink"
        symlink.symlink_to(outside)
        with self.assertRaisesRegex(TOOL.WorkerRuntimeError, "symlink"):
            TOOL.runtime_tree_sha256(
                self.node_modules,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        symlink.unlink()
        hardlink = self.node_modules / "hardlink"
        os.link(self.dependency, hardlink)
        with self.assertRaisesRegex(TOOL.WorkerRuntimeError, "single-link"):
            TOOL.runtime_tree_sha256(
                self.node_modules,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_writable_file_or_directory_mode_is_rejected(self):
        for path in (self.dependency, self.dependency.parent):
            original = stat.S_IMODE(path.stat().st_mode)
            path.chmod(original | 0o022)
            with self.subTest(path=path), self.assertRaisesRegex(
                TOOL.WorkerRuntimeError, "unsafe"
            ):
                TOOL.runtime_tree_sha256(
                    self.node_modules,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                )
            path.chmod(original)

    def test_package_lock_or_git_head_drift_is_rejected(self):
        self.package_lock.write_text(
            self.package_lock.read_text(encoding="ascii") + "\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(
            TOOL.WorkerRuntimeError, "does not match"
        ):
            self.verify()
        self.package_lock.write_text(
            self.package_lock.read_text(encoding="ascii").rstrip() + "\n",
            encoding="ascii",
        )
        self.write_attestation()
        with self.assertRaisesRegex(
            TOOL.WorkerRuntimeError, "does not match"
        ):
            self.verify(git_head="b" * 40)

    def test_package_lock_is_parsed_from_the_stable_file_descriptor(self):
        with mock.patch.object(
            pathlib.Path,
            "read_bytes",
            side_effect=AssertionError("package lock path was reopened"),
        ):
            lock_hash = TOOL.validate_package_lock(
                self.package_lock,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        self.assertRegex(lock_hash, r"[0-9a-f]{64}\Z")

    def test_bin_links_are_removed_without_following_targets(self):
        bin_directory = self.node_modules / ".bin"
        bin_directory.mkdir()
        target = self.root / "target"
        target.write_text("keep\n", encoding="ascii")
        (bin_directory / "wrangler").symlink_to(target)
        TOOL.remove_bin_links(self.node_modules)
        self.assertFalse(bin_directory.exists())
        self.assertEqual(target.read_text(encoding="ascii"), "keep\n")

    def test_operation_lock_refuses_a_concurrent_writer(self):
        lock_path = self.state_directory / TOOL.LOCK_PATH.name
        with TOOL.runtime_lock(
            self.state_directory,
            expected_uid=self.uid,
            expected_gid=self.gid,
            exclusive=True,
            create=True,
        ):
            with self.assertRaisesRegex(
                TOOL.WorkerRuntimeError, "already|in progress"
            ):
                with TOOL.runtime_lock(
                    self.state_directory,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                    exclusive=True,
                ):
                    self.fail("a second exclusive lock must not be acquired")
        self.assertEqual(stat.S_IMODE(lock_path.stat().st_mode), 0o600)

    def test_npm_user_configuration_is_distinct_empty_and_sealed(self):
        user_config = TOOL.prepare_empty_npm_user_config(
            self.state_directory,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        metadata = user_config.stat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
        self.assertEqual(metadata.st_size, 0)

        environment = TOOL.minimal_environment(npm_userconfig=user_config)
        self.assertEqual(environment["NPM_CONFIG_USERCONFIG"], str(user_config))
        self.assertEqual(environment["NPM_CONFIG_GLOBALCONFIG"], "/dev/null")
        self.assertNotEqual(
            environment["NPM_CONFIG_USERCONFIG"],
            environment["NPM_CONFIG_GLOBALCONFIG"],
        )
        result = subprocess.run(
            [TOOL.NPM_BINARY, "config", "list", "--json"],
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        user_config.write_text("unexpected\n", encoding="ascii")
        with self.assertRaisesRegex(TOOL.WorkerRuntimeError, "unsafe"):
            TOOL.prepare_empty_npm_user_config(
                self.state_directory,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_controllers_are_interpreter_only_and_use_attested_direct_entry(self):
        for path in (TOOL_PATH, DEPLOY_WORKER, SECRET_INITIALIZER):
            with self.subTest(path=path):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        deploy_source = DEPLOY_WORKER.read_text(encoding="utf-8")
        secret_source = SECRET_INITIALIZER.read_text(encoding="utf-8")
        for source in (deploy_source, secret_source):
            self.assertNotIn("node_modules/.bin/wrangler", source)
            self.assertIn("node_modules/wrangler/bin/wrangler.js", source)
            self.assertIn("worker-runtime-attestation.py", source)
        self.assertLess(
            deploy_source.index('"$TRUSTED_RUNTIME_ATTESTOR" verify'),
            deploy_source.index('wrangler_version="$('),
        )
        main = secret_source.split("def main(argv=None):", 1)[1]
        self.assertLess(
            main.index('runtime_attestor, "verify"'),
            main.index("version = subprocess.run"),
        )
        attestor_main = TOOL_PATH.read_text(encoding="utf-8").split(
            "def main(argv=None):", 1
        )[1]
        self.assertLess(
            attestor_main.index("verify_attestation("),
            attestor_main.index("current_node_version()"),
        )


if __name__ == "__main__":
    unittest.main()
