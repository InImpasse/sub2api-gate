import importlib.util
import os
import pathlib
import stat
import tempfile
import sys
import unittest

from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "deploy" / "harden-legacy-sync-service.py"
SPEC = importlib.util.spec_from_file_location("legacy_sync_hardening", SCRIPT)
HARDENING = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARDENING
SPEC.loader.exec_module(HARDENING)


class FakeRunner:
    def __init__(
        self,
        paths,
        *,
        fail_first_restart=False,
        hardened=True,
        exec_start=None,
        environment_files=None,
        working_directory=None,
        effective_overrides=None,
    ):
        self.paths = paths
        self.unit_path = str(paths.unit_path)
        self.fail_first_restart = fail_first_restart
        self.hardened = hardened
        self.exec_start = exec_start or (
            "{ path=/usr/bin/python3 ; "
            f"argv[]=/usr/bin/python3 {paths.entry_script} ; "
            "ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; "
            "pid=0 ; code=(null) ; status=0/0 }"
        )
        self.environment_files = environment_files or (
            f"{paths.environment_file} (ignore_errors=no)"
        )
        self.working_directory = working_directory or str(paths.working_directory)
        self.effective_overrides = effective_overrides or {}
        self.calls = []
        self.restart_count = 0

    def __call__(self, command, **_kwargs):
        self.calls.append(tuple(command))
        if command[1:3] == ["show", HARDENING.UNIT_NAME]:
            properties = [item.split("=", 1)[1] for item in command if item.startswith("--property=")]
            if "Id" in properties:
                values = {
                    "Id": HARDENING.UNIT_NAME,
                    "LoadState": "loaded",
                    "FragmentPath": self.unit_path,
                    "ActiveState": "active",
                    "SubState": "running",
                    "MainPID": "4242",
                    "User": "root",
                    "WorkingDirectory": self.working_directory,
                    "ExecStart": self.exec_start,
                    "EnvironmentFiles": self.environment_files,
                }
            else:
                values = dict(HARDENING.EXPECTED_EFFECTIVE_PROPERTIES) if self.hardened else {
                    **HARDENING.EXPECTED_EFFECTIVE_PROPERTIES,
                    "PrivateTmp": "no",
                }
                values.update(self.effective_overrides)
            output = "".join(f"{name}={values[name]}\n" for name in properties).encode()
            return HARDENING.CommandResult(0, output)
        if command[1:] == ["daemon-reload"]:
            return HARDENING.CommandResult(0)
        if command[1:3] == ["restart", HARDENING.UNIT_NAME]:
            self.restart_count += 1
            if self.fail_first_restart and self.restart_count == 1:
                return HARDENING.CommandResult(1)
            return HARDENING.CommandResult(0)
        raise AssertionError(f"unexpected command: {command}")


class FakeTTY:
    def __init__(self, value=True):
        self.value = value

    def isatty(self):
        return self.value


class LegacySyncHardeningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary.name)
        self.unit_directory = self.root / "system"
        self.unit_directory.mkdir(mode=0o755)
        self.unit = self.unit_directory / HARDENING.UNIT_NAME
        self.unit.write_text("[Service]\nExecStart=/usr/bin/python3 app.py\n", encoding="ascii")
        self.unit.chmod(0o644)
        self.runtime_root = self.root / "runtime-root"
        self.working_directory = self.runtime_root / "opt" / "sub2api-sync"
        self.working_directory.mkdir(parents=True, mode=0o755)
        for directory in (self.runtime_root, self.runtime_root / "opt", self.working_directory):
            directory.chmod(0o755)
        self.entry_script = self.working_directory / "sub2api_sync.py"
        self.entry_script.write_text("pass\n", encoding="ascii")
        self.entry_script.chmod(0o644)
        environment_directory = self.runtime_root / "etc"
        environment_directory.mkdir(mode=0o755)
        self.environment_file = environment_directory / "sub2api-sync.env"
        self.environment_file.write_text("SYNC_TEST=placeholder\n", encoding="ascii")
        self.environment_file.chmod(0o600)
        self.dropin_directory = self.unit_directory / (HARDENING.UNIT_NAME + ".d")
        self.dropin = self.dropin_directory / "99-sub2api-gate-hardening.conf"
        self.paths = HARDENING.HardeningPaths(
            repo_dir=self.root,
            trusted_release_root=self.root,
            clean_worktree=self.root / "clean-worktree",
            unit_path=self.unit,
            working_directory=self.working_directory,
            entry_script=self.entry_script,
            environment_file=self.environment_file,
            runtime_trust_root=self.runtime_root,
            dropin_directory=self.dropin_directory,
            dropin_path=self.dropin,
            trusted_unit_directories=(self.root, self.unit_directory),
            proc_root=self.root / "proc",
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def healthy(*_args, **_kwargs):
        return None

    @staticmethod
    def listener(*_args, **_kwargs):
        return None

    def test_dropin_is_conservative_and_preserves_user_and_network_contracts(self):
        self.assertEqual(
            SCRIPT.read_bytes().splitlines()[0], b"#!/usr/bin/python3 -I"
        )
        HARDENING.validate_dropin_contract()
        text = HARDENING.HARDENING_DROPIN.decode("ascii")
        self.assertIn("ReadOnlyPaths=/opt/sub2api-sync", text)
        self.assertIn("InaccessiblePaths=/var/run/docker.sock", text)
        self.assertIn("/mnt/data/sub2api-gate/private", text)
        self.assertIn("CapabilityBoundingSet=", text)
        self.assertIn("PrivateTmp=yes", text)
        for forbidden in (
            "User=",
            "Group=",
            "Environment=",
            "ExecStart=",
            "PrivateNetwork=",
            "IPAddressAllow=",
            "IPAddressDeny=",
            "RestrictAddressFamilies=",
        ):
            self.assertNotIn(forbidden, text)

    def test_apply_installs_root_style_dropin_restarts_and_verifies_loopback_runtime(self):
        runner = FakeRunner(self.paths)
        changed = HARDENING.apply_hardening(
            self.paths,
            runner=runner,
            health_probe=self.healthy,
            listener_verifier=self.listener,
        )
        self.assertTrue(changed)
        self.assertEqual(self.dropin.read_bytes(), HARDENING.HARDENING_DROPIN)
        self.assertEqual(stat.S_IMODE(self.dropin.stat().st_mode), 0o644)
        self.assertIn((HARDENING.SYSTEMCTL, "daemon-reload"), runner.calls)
        self.assertIn((HARDENING.SYSTEMCTL, "restart", HARDENING.UNIT_NAME), runner.calls)

    def test_apply_rolls_back_dropin_and_restarts_original_service_on_failure(self):
        runner = FakeRunner(self.paths, fail_first_restart=True)
        with self.assertRaisesRegex(
            HARDENING.LegacySyncHardeningError,
            "original service configuration was restored",
        ):
            HARDENING.apply_hardening(
                self.paths,
                runner=runner,
                health_probe=self.healthy,
                listener_verifier=self.listener,
            )
        self.assertFalse(self.dropin.exists())
        self.assertEqual(runner.restart_count, 2)

    def test_existing_matching_dropin_is_idempotent_and_never_restarts(self):
        self.dropin_directory.mkdir(mode=0o755)
        self.dropin.write_bytes(HARDENING.HARDENING_DROPIN)
        self.dropin.chmod(0o644)
        runner = FakeRunner(self.paths)
        changed = HARDENING.apply_hardening(
            self.paths,
            runner=runner,
            health_probe=self.healthy,
            listener_verifier=self.listener,
        )
        self.assertFalse(changed)
        self.assertNotIn((HARDENING.SYSTEMCTL, "daemon-reload"), runner.calls)
        self.assertNotIn((HARDENING.SYSTEMCTL, "restart", HARDENING.UNIT_NAME), runner.calls)

    def test_dropin_finalization_failure_is_rolled_back_before_returning(self):
        self.dropin_directory.mkdir(mode=0o755)
        runner = FakeRunner(self.paths)
        original_fsync = HARDENING.fsync_directory
        failed = False

        def fail_once(directory):
            nonlocal failed
            if pathlib.Path(directory) == self.dropin_directory and not failed:
                failed = True
                raise OSError("simulated filesystem failure")
            return original_fsync(directory)

        with mock.patch.object(HARDENING, "fsync_directory", side_effect=fail_once):
            with self.assertRaisesRegex(
                HARDENING.LegacySyncHardeningError,
                "original service configuration was restored",
            ):
                HARDENING.apply_hardening(
                    self.paths,
                    runner=runner,
                    health_probe=self.healthy,
                    listener_verifier=self.listener,
                )
        self.assertTrue(failed)
        self.assertFalse(self.dropin.exists())
        self.assertEqual(runner.restart_count, 1)

    def test_rejects_tampered_exec_start_before_any_restart(self):
        _payload, snapshot = HARDENING.read_unit_fragment(self.paths)
        runner = FakeRunner(
            self.paths,
            exec_start=(
                "{ path=/usr/bin/python3 ; "
                "argv[]=/usr/bin/python3 /opt/sub2api-sync/tampered.py ; "
                "ignore_errors=no }"
            ),
        )
        with self.assertRaisesRegex(
            HARDENING.LegacySyncHardeningError, "effective command is invalid"
        ):
            HARDENING.systemctl_restart(self.paths, snapshot, runner=runner)
        self.assertEqual(runner.restart_count, 0)

    def test_rejects_mismatched_environment_file_before_any_restart(self):
        _payload, snapshot = HARDENING.read_unit_fragment(self.paths)
        runner = FakeRunner(
            self.paths,
            environment_files="/etc/different.env (ignore_errors=no)",
        )
        with self.assertRaisesRegex(
            HARDENING.LegacySyncHardeningError,
            "effective environment file is invalid",
        ):
            HARDENING.systemctl_restart(self.paths, snapshot, runner=runner)
        self.assertEqual(runner.restart_count, 0)

    def test_rejects_mismatched_working_directory_before_any_restart(self):
        _payload, snapshot = HARDENING.read_unit_fragment(self.paths)
        runner = FakeRunner(self.paths, working_directory="/opt/different")
        with self.assertRaisesRegex(
            HARDENING.LegacySyncHardeningError,
            "unit identity or state is invalid",
        ):
            HARDENING.systemctl_restart(self.paths, snapshot, runner=runner)
        self.assertEqual(runner.restart_count, 0)

    def test_rejects_unsafe_app_environment_and_ancestor_paths(self):
        cases = (
            (self.entry_script, 0o664, 0o644),
            (self.environment_file, 0o660, 0o600),
            (self.working_directory.parent, 0o775, 0o755),
        )
        for path, unsafe_mode, safe_mode in cases:
            with self.subTest(path=path):
                path.chmod(unsafe_mode)
                try:
                    with self.assertRaisesRegex(
                        HARDENING.LegacySyncHardeningError,
                        "(?:runtime file|unit directory) is unsafe",
                    ):
                        HARDENING.inspect_active_unit(
                            self.paths, runner=FakeRunner(self.paths)
                        )
                finally:
                    path.chmod(safe_mode)

    def test_rejects_linked_entry_script(self):
        target = self.working_directory / "real_sync.py"
        target.write_text("pass\n", encoding="ascii")
        target.chmod(0o644)
        self.entry_script.unlink()
        self.entry_script.symlink_to(target.name)
        with self.assertRaisesRegex(
            HARDENING.LegacySyncHardeningError, "runtime file is unsafe"
        ):
            HARDENING.inspect_active_unit(self.paths, runner=FakeRunner(self.paths))

    def test_effective_hardening_requires_both_inaccessible_paths(self):
        runner = FakeRunner(
            self.paths,
            effective_overrides={
                "InaccessiblePaths": str(HARDENING.DOCKER_SOCKET),
            },
        )
        with self.assertRaisesRegex(
            HARDENING.LegacySyncHardeningError,
            "sandbox settings are not effective",
        ):
            HARDENING.verify_effective_hardening(runner=runner)

    def test_rejects_unit_that_is_not_a_root_style_single_link_0644_regular_file(self):
        self.unit.chmod(0o600)
        runner = FakeRunner(self.paths)
        with self.assertRaisesRegex(HARDENING.LegacySyncHardeningError, "service file is unsafe"):
            HARDENING.inspect_active_unit(self.paths, runner=runner)

    def test_apply_context_requires_root_trusted_tree_and_private_tty(self):
        outside = dataclasses_replace(self.paths, repo_dir=self.root / "outside")
        with self.assertRaisesRegex(HARDENING.LegacySyncHardeningError, "trusted production release tree"):
            HARDENING.require_production_apply_context(
                outside,
                streams=(FakeTTY(), FakeTTY(), FakeTTY()),
            )
        with self.assertRaisesRegex(HARDENING.LegacySyncHardeningError, "private interactive TTY"):
            with mock.patch.object(HARDENING.os, "geteuid", return_value=0), \
                 mock.patch.object(HARDENING, "require_safe_system_binary"):
                production_like = dataclasses_replace(
                    self.paths,
                    repo_dir=self.paths.trusted_release_root,
                )
                HARDENING.require_production_apply_context(
                    production_like,
                    streams=(FakeTTY(), FakeTTY(False), FakeTTY()),
                )

    def test_apply_context_validates_every_fixed_system_binary(self):
        with mock.patch.object(HARDENING.os, "geteuid", return_value=0), \
             mock.patch.object(HARDENING, "require_trusted_release_tree") as trusted_tree, \
             mock.patch.object(HARDENING, "require_safe_system_binary") as safe_binary:
            HARDENING.require_production_apply_context(
                self.paths,
                streams=(FakeTTY(), FakeTTY(), FakeTTY()),
            )
        trusted_tree.assert_called_once_with(self.paths)
        safe_binary.assert_has_calls(
            [
                mock.call(HARDENING.SYSTEMCTL),
                mock.call(HARDENING.BASH),
                mock.call(HARDENING.EXPECTED_PYTHON),
            ]
        )

    def test_trusted_release_tree_requires_fixed_source_guard_and_metadata(self):
        release_root = self.root / "opt" / "sub2api-gate-release"
        deploy_directory = release_root / "deploy"
        deploy_directory.mkdir(parents=True)
        source = deploy_directory / "harden-legacy-sync-service.py"
        guard = deploy_directory / "require-clean-worktree.sh"
        source.write_text("#!/usr/bin/env python3\n", encoding="ascii")
        guard.write_text("#!/bin/bash\n", encoding="ascii")
        for path in (self.root / "opt", release_root, deploy_directory, source, guard):
            path.chmod(0o755)
        paths = dataclasses_replace(
            self.paths,
            repo_dir=release_root,
            trusted_release_root=release_root,
            clean_worktree=guard,
        )

        with mock.patch.object(HARDENING, "TRUSTED_FILESYSTEM_ROOT", self.root), \
             mock.patch.object(HARDENING, "TRUSTED_RELEASE_PARENT", release_root.parent), \
             mock.patch.object(HARDENING, "TRUSTED_RELEASE_ROOT", release_root):
            HARDENING.require_trusted_release_tree(
                paths,
                source_path=source,
                expected_uid=os.geteuid(),
                expected_gid=os.getegid(),
            )
            wrong_guard = deploy_directory / "different-guard.sh"
            wrong_guard.write_text("#!/bin/bash\n", encoding="ascii")
            wrong_guard.chmod(0o755)
            with self.assertRaisesRegex(
                HARDENING.LegacySyncHardeningError, "clean worktree guard"
            ):
                HARDENING.require_trusted_release_tree(
                    dataclasses_replace(paths, clean_worktree=wrong_guard),
                    source_path=source,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )
            wrong_source = deploy_directory / "different-controller.py"
            wrong_source.write_text("#!/usr/bin/env python3\n", encoding="ascii")
            wrong_source.chmod(0o755)
            with self.assertRaisesRegex(
                HARDENING.LegacySyncHardeningError, "controller is outside"
            ):
                HARDENING.require_trusted_release_tree(
                    paths,
                    source_path=wrong_source,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )
            release_root.chmod(0o775)
            with self.assertRaisesRegex(
                HARDENING.LegacySyncHardeningError, "release path is unsafe"
            ):
                HARDENING.require_trusted_release_tree(
                    paths,
                    source_path=source,
                    expected_uid=os.geteuid(),
                    expected_gid=os.getegid(),
                )

    def test_loopback_listener_requires_the_unit_process_socket_and_rejects_wildcard(self):
        proc = self.paths.proc_root
        (proc / "net").mkdir(parents=True)
        (proc / "4242" / "fd").mkdir(parents=True)
        (proc / "4242" / "fd" / "3").symlink_to("socket:[12345]")
        header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        (proc / "net" / "tcp").write_text(
            header + "   0: 0100007F:0BCD 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 1\n",
            encoding="ascii",
        )
        (proc / "net" / "tcp6").write_text(header, encoding="ascii")
        HARDENING.verify_loopback_listener(4242, proc_root=proc)
        (proc / "net" / "tcp").write_text(
            header + "   0: 00000000:0BCD 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 12345 1\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(HARDENING.LegacySyncHardeningError, "not loopback-only"):
            HARDENING.verify_loopback_listener(4242, proc_root=proc)


def dataclasses_replace(value, **changes):
    return HARDENING.dataclasses.replace(value, **changes)


if __name__ == "__main__":
    unittest.main()
