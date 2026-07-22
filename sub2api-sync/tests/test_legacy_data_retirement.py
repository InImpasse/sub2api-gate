import importlib.util
import inspect
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = ROOT / "deploy" / "retire-legacy-data.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("legacy_data_retirement", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TtyBuffer(io.StringIO):
    def isatty(self):
        return True


class LegacyDataRetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool = load_tool()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.paths = self.tool.LegacyPaths(
            app=self.root / "legacy-app",
            postgres=self.root / "legacy-postgres",
            redis=self.root / "legacy-redis",
            nginx_logs=self.root / "legacy-nginx",
        )
        for path in (*[item[1] for item in self.paths.data_items()], self.paths.nginx_logs):
            path.mkdir(mode=0o700)
            (path / "data.bin").write_bytes(path.name.encode("ascii"))
        self.names = self.tool.LegacyNames(
            app="legacy-sub2api",
            postgres="legacy-postgres",
            redis="legacy-redis",
        )
        self.record_path = self.root / "legacy-data-retirement.json"
        self.policy = self.tool.PathPolicy(test_root=self.root)
        self.legacy_identity = {
            "app": "a" * 64,
            "postgres": "7612345678901234567",
            "redis": "b" * 40,
        }
        self.target_identity = {
            "app": "c" * 64,
            "postgres": "8612345678901234567",
            "redis": "d" * 40,
        }
        self.filesystem = {
            "target": str(self.root),
            "source": "/dev/mock-retirement",
            "fstype": "ext4",
            "major_minor": "8:99",
        }
        self.uid = os.getuid()

    def tearDown(self):
        self.temporary.cleanup()

    def forbidden_runner(self, *args, **kwargs):
        raise AssertionError(f"unexpected external command: {args!r} {kwargs!r}")

    def container_snapshot(self, _paths, names, *, runner):
        return {
            "app": {"name": names.app, "id": self.legacy_identity["app"]},
            "postgres": {"name": names.postgres, "id": "e" * 64},
            "redis": {"name": names.redis, "id": "f" * 64},
        }

    def filesystem_probe(self, _path, *, runner):
        return dict(self.filesystem)

    def create_record(self):
        return self.tool.create_record(
            self.paths,
            self.names,
            record_path=self.record_path,
            expected_uid=self.uid,
            policy=self.policy,
            runner=self.forbidden_runner,
            legacy_gate=lambda _names, *, runner: dict(self.legacy_identity),
            filesystem_probe=self.filesystem_probe,
            mountpoints_reader=lambda: (),
            stable_gate=lambda: None,
            container_probe=self.container_snapshot,
            daemon_probe=lambda *, runner: "TEST:DAEMON:IDENTITY:0001",
        )

    def retire(self, **overrides):
        arguments = {
            "record_path": self.record_path,
            "expected_uid": self.uid,
            "policy": self.policy,
            "runner": self.forbidden_runner,
            "target_gate": lambda *, runner: dict(self.target_identity),
            "filesystem_probe": self.filesystem_probe,
            "mountpoint_probe": self.filesystem_probe,
            "mountpoints_reader": lambda: (),
            "nginx_gate": lambda: None,
            "container_gate": lambda _record, *, runner: None,
            "cleanup_gate": lambda _paths, _names, *, runner: None,
            "trimmer": lambda _filesystem, *, runner: None,
            "stdin": TtyBuffer(self.tool.FORWARD_ONLY_PHRASE + "\n"),
            "stderr": TtyBuffer(),
        }
        arguments.update(overrides)
        return self.tool.retire_recorded_data(self.paths, self.names, **arguments)

    def test_default_check_is_offline_and_does_not_resolve_runtime_paths(self):
        stdout = io.StringIO()
        result = self.tool.main(
            [],
            runner=self.forbidden_runner,
            stdin=io.StringIO(),
            stderr=io.StringIO(),
            stdout=stdout,
        )
        self.assertEqual(result, 0)
        self.assertIn("no path was resolved", stdout.getvalue())
        self.assertIn("no Docker or health gate ran", stdout.getvalue())
        for _, path in self.paths.data_items():
            self.assertTrue(path.is_dir())

    def test_parser_requires_explicit_absolute_non_target_paths_and_confirmation(self):
        base = [
            "--apply",
            "--stage",
            "retire",
            "--legacy-app-path",
            "relative/app",
            "--legacy-postgres-path",
            "/srv/legacy/postgres",
            "--legacy-redis-path",
            "/srv/legacy/redis",
            "--legacy-nginx-log-path",
            "/var/log/nginx",
            "--legacy-sub2api-container",
            "legacy-app",
            "--legacy-postgres-container",
            "legacy-postgres",
            "--legacy-redis-container",
            "legacy-redis",
            "--confirm-forward-only",
        ]
        with self.assertRaisesRegex(self.tool.UsageError, "explicit normalized absolute"):
            self.tool.parse_arguments(base)

        for unsafe in (
            "/mnt/data",
            "/mnt/data/sub2api-gate",
            "/mnt/data/sub2api-gate/postgres",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(self.tool.UsageError):
                self.tool.validate_path_shape(
                    pathlib.Path(unsafe), "legacy path", self.tool.PathPolicy()
                )

        without_confirmation = [item for item in base if item != "--confirm-forward-only"]
        without_confirmation[without_confirmation.index("relative/app")] = "/srv/legacy/app"
        with self.assertRaisesRegex(self.tool.UsageError, "requires --confirm-forward-only"):
            self.tool.parse_arguments(without_confirmation)

    def test_record_stage_binds_exact_paths_containers_and_filesystems(self):
        self.assertNotIn("target_gate", inspect.signature(self.tool.create_record).parameters)
        record = self.create_record()
        self.assertEqual(record["status"], "recorded")
        self.assertNotIn("target_runtime_identity", record)
        self.assertEqual(record["legacy_runtime_identity"], self.legacy_identity)
        self.assertEqual(self.record_path.stat().st_mode & 0o777, 0o600)
        persisted = json.loads(self.record_path.read_text(encoding="ascii"))
        for component, path in self.paths.data_items():
            self.assertEqual(persisted["legacy"][component]["path"], str(path))
            self.assertGreater(persisted["legacy"][component]["directory"]["inode"], 0)
            self.assertEqual(persisted["legacy"][component]["filesystem"], self.filesystem)
        self.assertTrue(all(path.exists() for _, path in self.paths.data_items()))

    def test_apply_removes_only_three_exact_directories_and_trims_once(self):
        self.create_record()
        outside = self.root / "unrelated"
        outside.mkdir()
        sentinel = outside / "keep.txt"
        sentinel.write_text("keep", encoding="ascii")
        trims = []

        result = self.retire(
            trimmer=lambda filesystem, *, runner: trims.append(dict(filesystem))
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(set(result["retired_components"]), {"app", "postgres", "redis"})
        self.assertEqual(trims, [self.filesystem])
        self.assertEqual(sentinel.read_text(encoding="ascii"), "keep")
        for _, path in self.paths.data_items():
            self.assertFalse(os.path.lexists(path))
        self.assertTrue(self.paths.nginx_logs.is_dir())

    def test_every_gate_fails_before_any_directory_is_deleted(self):
        scenarios = (
            (
                "target",
                {"target_gate": lambda *, runner: (_ for _ in ()).throw(
                    self.tool.RetirementError("target failed")
                )},
            ),
            (
                "container",
                {"container_gate": lambda _record, *, runner: (_ for _ in ()).throw(
                    self.tool.RetirementError("legacy still present")
                )},
            ),
            (
                "cleanup",
                {"cleanup_gate": lambda _paths, _names, *, runner: (_ for _ in ()).throw(
                    self.tool.RetirementError("logs remain")
                )},
            ),
        )
        for name, overrides in scenarios:
            with self.subTest(name=name):
                if self.record_path.exists():
                    self.record_path.unlink()
                for _, path in self.paths.data_items():
                    path.mkdir(exist_ok=True)
                    (path / "data.bin").write_bytes(b"data")
                self.create_record()
                with self.assertRaises(self.tool.RetirementError):
                    self.retire(**overrides)
                self.assertTrue(all(path.is_dir() for _, path in self.paths.data_items()))

    def test_tampered_directory_identity_is_rejected_before_delete(self):
        record = self.create_record()
        record["legacy"]["postgres"]["directory"]["inode"] += 1
        self.tool.write_record(self.record_path, record, expected_uid=self.uid)
        with self.assertRaisesRegex(self.tool.RetirementError, "recorded identity"):
            self.retire()
        self.assertTrue(all(path.is_dir() for _, path in self.paths.data_items()))

    def test_nested_mount_is_rejected_before_delete(self):
        self.create_record()
        nested = self.paths.postgres / "external-volume"
        with self.assertRaisesRegex(self.tool.RetirementError, "mount boundary"):
            self.retire(mountpoints_reader=lambda: (nested,))
        self.assertTrue(all(path.is_dir() for _, path in self.paths.data_items()))

    def test_partial_directory_failure_is_recorded_and_resumable(self):
        self.create_record()
        real_delete = self.tool.delete_exact_directory
        failed = {"value": False}
        cleanup_calls = []

        def cleanup(_paths, _names, *, runner):
            cleanup_calls.append("verified")

        def fail_once(path, identity):
            if path == self.paths.redis and not failed["value"]:
                failed["value"] = True
                raise self.tool.RetirementError("injected removal failure")
            real_delete(path, identity)

        with self.assertRaisesRegex(self.tool.RetirementError, "injected"):
            self.retire(delete_directory=fail_once, cleanup_gate=cleanup)
        progress = json.loads(self.record_path.read_text(encoding="ascii"))
        self.assertEqual(progress["retired_components"], ["postgres"])
        self.assertFalse(self.paths.postgres.exists())
        self.assertTrue(self.paths.redis.exists())
        self.assertTrue(self.paths.app.exists())

        result = self.retire(cleanup_gate=cleanup)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(cleanup_calls, ["verified", "verified"])
        self.assertTrue(all(not path.exists() for _, path in self.paths.data_items()))

    def test_fstrim_failure_leaves_a_resumable_forward_only_record(self):
        self.create_record()

        def fail_trim(_filesystem, *, runner):
            raise self.tool.RetirementError("injected trim failure")

        with self.assertRaisesRegex(self.tool.RetirementError, "injected trim"):
            self.retire(trimmer=fail_trim)
        progress = json.loads(self.record_path.read_text(encoding="ascii"))
        self.assertEqual(progress["status"], "retiring")
        self.assertEqual(set(progress["retired_components"]), {"app", "postgres", "redis"})
        self.assertEqual(progress["trimmed_filesystems"], [])

        trims = []
        result = self.retire(
            trimmer=lambda filesystem, *, runner: trims.append(dict(filesystem))
        )
        self.assertEqual(result["status"], "complete")
        self.assertEqual(trims, [self.filesystem])

    def test_verify_record_is_read_only_and_does_not_require_a_target(self):
        self.create_record()
        before = self.record_path.read_bytes()
        record = self.tool.verify_recorded_identity(
            self.paths,
            self.names,
            record_path=self.record_path,
            expected_uid=self.uid,
            policy=self.policy,
            runner=self.forbidden_runner,
            legacy_gate=lambda _names, *, runner: dict(self.legacy_identity),
            filesystem_probe=self.filesystem_probe,
            mountpoints_reader=lambda: (),
            stable_gate=lambda: None,
            container_probe=self.container_snapshot,
            daemon_probe=lambda *, runner: "TEST:DAEMON:IDENTITY:0001",
        )
        self.assertEqual(record["legacy_runtime_identity"], self.legacy_identity)
        self.assertEqual(self.record_path.read_bytes(), before)

    def test_verify_record_cli_has_no_stage_and_uses_only_the_fixed_record(self):
        arguments = [
            "verify-record",
            "--legacy-app-path",
            "/srv/legacy/app",
            "--legacy-postgres-path",
            "/srv/legacy/postgres",
            "--legacy-redis-path",
            "/srv/legacy/redis",
            "--legacy-nginx-log-path",
            "/var/log/nginx",
            "--legacy-sub2api-container",
            "legacy-app",
            "--legacy-postgres-container",
            "legacy-postgres",
            "--legacy-redis-container",
            "legacy-redis",
        ]
        mode, stage, _paths, _names, confirmed, record_path = self.tool.parse_arguments(
            arguments
        )
        self.assertEqual(mode, "verify-record")
        self.assertIsNone(stage)
        self.assertFalse(confirmed)
        self.assertEqual(record_path, self.tool.RECORD_PATH)
        with self.assertRaisesRegex(self.tool.UsageError, "does not accept an apply stage"):
            self.tool.parse_arguments(arguments + ["--stage", "record"])
        with self.assertRaisesRegex(self.tool.UsageError, "fixed record path"):
            self.tool.parse_arguments(
                arguments + ["--record-file", "/tmp/untrusted-retirement.json"]
            )

    def test_wrong_forward_only_phrase_never_deletes(self):
        self.create_record()
        with self.assertRaisesRegex(self.tool.RetirementError, "did not match"):
            self.retire(stdin=TtyBuffer("not approved\n"))
        self.assertTrue(all(path.is_dir() for _, path in self.paths.data_items()))

    def test_source_uses_fixed_local_boundaries_and_documents_discard_limit(self):
        source = TOOL_PATH.read_text(encoding="utf-8")
        self.assertIn('TARGET_ROOT = pathlib.Path("/mnt/data/sub2api-gate")', source)
        self.assertIn('DOCKER = "/usr/bin/docker"', source)
        self.assertIn('FSTRIM = "/usr/sbin/fstrim"', source)
        self.assertIn("require-clean-worktree.sh", source)
        self.assertIn("not a guarantee of forensic-grade erasure", source)
        self.assertNotIn("SUB2API_RETIRE_TEST_ROOT", source)


if __name__ == "__main__":
    unittest.main()
